/*******************************************************************************
    Copyright (c) 2015 NVIDIA Corporation

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to
    deal in the Software without restriction, including without limitation the
    rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
    sell copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

        The above copyright notice and this permission notice shall be
        included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.

*******************************************************************************/

#include "linux/sort.h"
#include "nv_uvm_interface.h"
#include "uvm_linux.h"
#include "uvm8_global.h"
#include "uvm8_gpu_replayable_faults.h"
#include "uvm8_hal.h"
#include "uvm8_kvmalloc.h"
#include "uvm8_tools.h"
#include "uvm8_va_block.h"
#include "uvm8_va_range.h"
#include "uvm8_va_space.h"
#include "uvm8_procfs.h"
#include "uvm8_perf_thrashing.h"

#include "uvm8_gpu_non_replayable_faults.h"


// TODO: Bug 1881601: [uvm] Add fault handling overview for replayable and
// non-replayable faults

#define UVM_PERF_REENABLE_PREFETCH_FAULTS_LAPSE_MSEC_DEFAULT 1000

// Lapse of time in milliseconds after which prefetch faults can be re-enabled. 0 means it is never disabled
static unsigned uvm_perf_reenable_prefetch_faults_lapse_msec = UVM_PERF_REENABLE_PREFETCH_FAULTS_LAPSE_MSEC_DEFAULT;
module_param(uvm_perf_reenable_prefetch_faults_lapse_msec, uint, S_IRUGO);

#define UVM_PERF_FAULT_BATCH_COUNT_MIN 1
#define UVM_PERF_FAULT_BATCH_COUNT_DEFAULT 256

// Number of entries that are fetched from the GPU fault buffer and serviced in batch
static unsigned uvm_perf_fault_batch_count = UVM_PERF_FAULT_BATCH_COUNT_DEFAULT;
module_param(uvm_perf_fault_batch_count, uint, S_IRUGO);

#define UVM_PERF_FAULT_REPLAY_POLICY_DEFAULT UVM_PERF_FAULT_REPLAY_POLICY_BATCH_FLUSH

// Policy that determines when to issue fault replays
static uvm_perf_fault_replay_policy_t uvm_perf_fault_replay_policy = UVM_PERF_FAULT_REPLAY_POLICY_DEFAULT;
module_param(uvm_perf_fault_replay_policy, uint, S_IRUGO);

#define UVM_PERF_FAULT_REPLAY_UPDATE_PUT_RATIO_DEFAULT 50

// Reading fault buffer GET/PUT pointers from the CPU is expensive. However,
// updating PUT before flushing the buffer helps minimizing the number of
// duplicates in the buffer as it discards faults that were not processed
// because of the batch size limit or because they arrived during servicing.
// If PUT is not updated, the replay operation will make them show up again
// in the buffer as duplicates.
//
// We keep track of the number of duplicates in each batch and we use
// UVM_GPU_BUFFER_FLUSH_MODE_UPDATE_PUT for the fault buffer flush after if the
// percentage of duplicate faults in a batch is greater than the ratio defined
// in the following module parameter. UVM_GPU_BUFFER_FLUSH_MODE_CACHED_PUT is
// used, otherwise.
static unsigned uvm_perf_fault_replay_update_put_ratio = UVM_PERF_FAULT_REPLAY_UPDATE_PUT_RATIO_DEFAULT;
module_param(uvm_perf_fault_replay_update_put_ratio, uint, S_IRUGO);

#define UVM_PERF_FAULT_MAX_BATCHES_PER_SERVICE_DEFAULT 20

#define UVM_PERF_FAULT_MAX_THROTTLE_PER_SERVICE_DEFAULT 5

// Maximum number of batches to be processed per execution of the bottom-half
static unsigned uvm_perf_fault_max_batches_per_service = UVM_PERF_FAULT_MAX_BATCHES_PER_SERVICE_DEFAULT;
module_param(uvm_perf_fault_max_batches_per_service, uint, S_IRUGO);

// Maximum number of batches with thrashing pages per execution of the bottom-half
static unsigned uvm_perf_fault_max_throttle_per_service = UVM_PERF_FAULT_MAX_THROTTLE_PER_SERVICE_DEFAULT;
module_param(uvm_perf_fault_max_throttle_per_service, uint, S_IRUGO);

// There is no error handling in this function. The caller is in charge of
// calling fault_buffer_deinit_replayable_faults on failure.
static NV_STATUS fault_buffer_init_replayable_faults(uvm_gpu_t *gpu)
{
    NV_STATUS status = NV_OK;
    uvm_replayable_fault_buffer_info_t *replayable_faults = &gpu->fault_buffer_info.replayable;
    uvm_fault_service_batch_context_t *batch_context = &replayable_faults->batch_service_context;

    UVM_ASSERT(gpu->fault_buffer_info.rm_info.replayable.bufferSize %
               gpu->fault_buffer_hal->entry_size(gpu) == 0);

    replayable_faults->max_faults = gpu->fault_buffer_info.rm_info.replayable.bufferSize /
                                    gpu->fault_buffer_hal->entry_size(gpu);

    // Check provided module parameter value
    gpu->fault_buffer_info.max_batch_size = max(uvm_perf_fault_batch_count,
                                                (NvU32)UVM_PERF_FAULT_BATCH_COUNT_MIN);
    gpu->fault_buffer_info.max_batch_size = min(gpu->fault_buffer_info.max_batch_size,
                                                replayable_faults->max_faults);

    if (gpu->fault_buffer_info.max_batch_size != uvm_perf_fault_batch_count) {
        pr_info("Invalid uvm_perf_fault_batch_count value on GPU %s: %u. Valid range [%u:%u] Using %u instead\n",
                gpu->name,
                uvm_perf_fault_batch_count,
                UVM_PERF_FAULT_BATCH_COUNT_MIN,
                replayable_faults->max_faults,
                gpu->fault_buffer_info.max_batch_size);
    }

    batch_context->fault_cache = uvm_kvmalloc_zero(replayable_faults->max_faults * sizeof(*batch_context->fault_cache));
    if (!batch_context->fault_cache)
        return NV_ERR_NO_MEMORY;

    // fault_cache is used to signal that the tracker was initialized.
    uvm_tracker_init(&replayable_faults->replay_tracker);

    batch_context->ordered_fault_cache = uvm_kvmalloc_zero(replayable_faults->max_faults *
                                                           sizeof(*batch_context->ordered_fault_cache));
    if (!batch_context->ordered_fault_cache)
        return NV_ERR_NO_MEMORY;

    // This value must be initialized by HAL
    UVM_ASSERT(replayable_faults->utlb_count > 0);

    batch_context->utlbs = uvm_kvmalloc_zero(replayable_faults->utlb_count * sizeof(*batch_context->utlbs));
    if (!batch_context->utlbs)
        return NV_ERR_NO_MEMORY;

    batch_context->max_utlb_id = 0;

    status = uvm_rm_locked_call(nvUvmInterfaceOwnPageFaultIntr(&gpu->uuid, NV_TRUE));
    if (status != NV_OK) {
        UVM_ERR_PRINT("Failed to take page fault ownership from RM: %s, GPU %s\n",
                      nvstatusToString(status), gpu->name);
        return status;
    }

    // Read current get/put pointers as this might not be the first time we have taken control of the fault buffer
    // since the GPU was initialized
    replayable_faults->cached_get = gpu->fault_buffer_hal->read_get(gpu);
    replayable_faults->cached_put = gpu->fault_buffer_hal->read_put(gpu);

    replayable_faults->replay_policy = uvm_perf_fault_replay_policy < UVM_PERF_FAULT_REPLAY_POLICY_MAX?
                                           uvm_perf_fault_replay_policy:
                                           UVM_PERF_FAULT_REPLAY_POLICY_DEFAULT;

    if (replayable_faults->replay_policy != uvm_perf_fault_replay_policy) {
        pr_info("Invalid uvm_perf_fault_replay_policy value on GPU %s: %d. Using %d instead\n",
                gpu->name, uvm_perf_fault_replay_policy, replayable_faults->replay_policy);
    }

    replayable_faults->replay_update_put_ratio = min(uvm_perf_fault_replay_update_put_ratio, 100u);
    if (replayable_faults->replay_update_put_ratio != uvm_perf_fault_replay_update_put_ratio) {
        pr_info("Invalid uvm_perf_fault_replay_update_put_ratio value on GPU %s: %u. Using %u instead\n",
                gpu->name, uvm_perf_fault_replay_update_put_ratio, replayable_faults->replay_update_put_ratio);
    }

    // Re-enable fault prefetching just in case it was disabled in a previous run
    if (gpu->prefetch_fault_supported) {
        gpu->arch_hal->enable_prefetch_faults(gpu);
        gpu->fault_buffer_info.prefetch_faults_enabled = true;
    }
    else {
        gpu->arch_hal->disable_prefetch_faults(gpu);
        gpu->fault_buffer_info.prefetch_faults_enabled = false;
    }

    return NV_OK;
}

static void fault_buffer_deinit_replayable_faults(uvm_gpu_t *gpu)
{
    NV_STATUS status = NV_OK;
    uvm_replayable_fault_buffer_info_t *replayable_faults = &gpu->fault_buffer_info.replayable;
    uvm_fault_service_batch_context_t *batch_context = &replayable_faults->batch_service_context;

    if (batch_context->fault_cache) {
        status = uvm_tracker_wait_deinit(&replayable_faults->replay_tracker);
        if (status != NV_OK)
            UVM_ASSERT(status == uvm_global_get_status());
    }

    if (gpu->fault_buffer_info.rm_info.faultBufferHandle) {
        // Re-enable prefetch faults in case we disabled them
        if (gpu->prefetch_fault_supported && !gpu->fault_buffer_info.prefetch_faults_enabled)
            gpu->arch_hal->enable_prefetch_faults(gpu);
    }

    uvm_kvfree(batch_context->fault_cache);
    uvm_kvfree(batch_context->ordered_fault_cache);
    uvm_kvfree(batch_context->utlbs);
    batch_context->fault_cache         = NULL;
    batch_context->ordered_fault_cache = NULL;
    batch_context->utlbs               = NULL;
}

NV_STATUS uvm_gpu_fault_buffer_init(uvm_gpu_t *gpu)
{
    NV_STATUS status = NV_OK;

    uvm_assert_mutex_locked(&g_uvm_global.global_lock);
    UVM_ASSERT(gpu->fault_buffer_hal != NULL);

    status = uvm_rm_locked_call(nvUvmInterfaceInitFaultInfo(gpu->rm_address_space,
                                                            &gpu->fault_buffer_info.rm_info));
    if (status != NV_OK) {
        UVM_ERR_PRINT("Failed to init fault buffer info from RM: %s, GPU %s\n",
                      nvstatusToString(status), gpu->name);

        // nvUvmInterfaceInitFaultInfo may leave fields in rm_info populated
        // when it returns an error. Set the buffer handle to zero as it is
        // used by the deinitialization logic to determine if it was correctly
        // initialized.
        gpu->fault_buffer_info.rm_info.faultBufferHandle = 0;
        goto fail;
    }

    status = fault_buffer_init_replayable_faults(gpu);
    if (status != NV_OK)
        goto fail;


    if (uvm_gpu_supports_non_replayable_faults(gpu)) {
        status = uvm_gpu_fault_buffer_init_non_replayable_faults(gpu);
        if (status != NV_OK)
            goto fail;
    }


    return NV_OK;

fail:
    uvm_gpu_fault_buffer_deinit(gpu);

    return status;
}

void uvm_gpu_fault_buffer_deinit(uvm_gpu_t *gpu)
{
    NV_STATUS status = NV_OK;

    uvm_assert_mutex_locked(&g_uvm_global.global_lock);


    if (uvm_gpu_supports_non_replayable_faults(gpu))
        uvm_gpu_fault_buffer_deinit_non_replayable_faults(gpu);


    fault_buffer_deinit_replayable_faults(gpu);

    if (gpu->fault_buffer_info.rm_info.faultBufferHandle) {
        status = uvm_rm_locked_call(nvUvmInterfaceOwnPageFaultIntr(&gpu->uuid, NV_FALSE));
        UVM_ASSERT(status == NV_OK);

        uvm_rm_locked_call_void(nvUvmInterfaceDestroyFaultInfo(gpu->rm_address_space,
                                                               &gpu->fault_buffer_info.rm_info));

        gpu->fault_buffer_info.rm_info.faultBufferHandle = 0;
    }
}


bool uvm_gpu_replayable_faults_pending(uvm_gpu_t *gpu)
{
    uvm_replayable_fault_buffer_info_t *replayable_faults = &gpu->fault_buffer_info.replayable;

    UVM_ASSERT(uvm_gpu_supports_replayable_faults(gpu));

    // Fast path 1: we left some faults unserviced in the buffer in the last pass
    if (replayable_faults->cached_get != replayable_faults->cached_put)
        return true;

    // Fast path 2: read the valid bit of the fault buffer entry pointed by the cached get pointer
    if (!gpu->fault_buffer_hal->entry_is_valid(gpu, replayable_faults->cached_get)) {
        // Slow path: read the put pointer from the GPU register via BAR0 over PCIe
        replayable_faults->cached_put = gpu->fault_buffer_hal->read_put(gpu);

        // No interrupt pending
        if (replayable_faults->cached_get == replayable_faults->cached_put)
            return false;
    }

    return true;
}

// Push a fault cancel method on the given client. Any failure during this operation may lead to
// application hang (requiring manual Ctrl+C from the user) or system crash (requiring reboot).
// In that case we log an error message.
//
// This function acquires both the given tracker and the replay tracker
static NV_STATUS push_cancel_on_gpu(uvm_gpu_t *gpu, uvm_gpu_phys_address_t instance_ptr, NvU32 gpc_id, NvU32 client_id,
                                    uvm_tracker_t *tracker)
{
    NV_STATUS status;
    uvm_push_t push;
    uvm_replayable_fault_buffer_info_t *replayable_faults = &gpu->fault_buffer_info.replayable;

    status = uvm_push_begin_acquire(gpu->channel_manager,
                                    UVM_CHANNEL_TYPE_MEMOPS,
                                    &replayable_faults->replay_tracker,
                                    &push,
                                    "Cancel targeting instance_ptr {%s, %p} gpc %u client %u\n",
                                    uvm_aperture_string(instance_ptr.aperture),
                                    (void *)instance_ptr.address,
                                    gpc_id,
                                    client_id);

    UVM_ASSERT(status == NV_OK);
    if (status != NV_OK) {
        UVM_ERR_PRINT("Failed to create push and acquire replay tracker before pushing cancel: %s, GPU %s\n",
                      nvstatusToString(status), gpu->name);
        return status;
    }

    uvm_push_acquire_tracker(&push, tracker);

    gpu->host_hal->cancel_faults_targeted(&push, instance_ptr, gpc_id, client_id);

    // We don't need to put the cancel in the GPU replay tracker since we wait on it immediately.
    status = uvm_push_end_and_wait(&push);

    UVM_ASSERT(status == NV_OK);
    if (status != NV_OK) {
        UVM_ERR_PRINT("Failed to wait for pushed cancel: %s, GPU %s\n",
                      nvstatusToString(status), gpu->name);
    }

    uvm_tracker_clear(&replayable_faults->replay_tracker);

    return status;
}


// Volta implements a targeted VA fault cancel that simplifies the fault cancel
// process. You only need to specify the address, type, and mmu_engine_id for
// the access to be cancelled. Caller must hold the VA space lock for the access
// to be cancelled.
static NV_STATUS cancel_fault_precise_va(uvm_gpu_t *gpu, uvm_fault_buffer_entry_t *fault_entry)
{
    NV_STATUS status;
    uvm_gpu_va_space_t *gpu_va_space;
    uvm_gpu_phys_address_t pdb;
    uvm_push_t push;
    uvm_replayable_fault_buffer_info_t *replayable_faults = &gpu->fault_buffer_info.replayable;

    UVM_ASSERT(uvm_gpu_supports_replayable_faults(gpu));
    UVM_ASSERT(fault_entry->fatal_reason != UvmEventFatalReasonInvalid);

    gpu_va_space = uvm_gpu_va_space_get(fault_entry->va_space, gpu);
    UVM_ASSERT(gpu_va_space);
    pdb = uvm_page_tree_pdb(&gpu_va_space->page_tables)->addr;

    // Record fatal fault event
    uvm_tools_record_gpu_fatal_fault(gpu->id, fault_entry->va_space, fault_entry, fault_entry->fatal_reason);

    status = uvm_push_begin_acquire(gpu->channel_manager,
                                    UVM_CHANNEL_TYPE_MEMOPS,
                                    &replayable_faults->replay_tracker,
                                    &push,
                                    "Precise cancel targeting PDB {%s,%p} VA %p VEID %u with access type %s",
                                    uvm_aperture_string(pdb.aperture),
                                    (void *)pdb.address,
                                    (void *)fault_entry->fault_address,
                                    fault_entry->fault_source.ve_id,
                                    uvm_fault_access_type_string(fault_entry->fault_access_type));

    gpu->host_hal->cancel_faults_va(&push, pdb, fault_entry);

    // We don't need to put the cancel in the GPU replay tracker since we wait on it immediately.
    status = uvm_push_end_and_wait(&push);
    if (status != NV_OK) {
        UVM_ERR_PRINT("Failed to wait for pushed VA global fault cancel: %s, GPU %s\n",
                      nvstatusToString(status), gpu->name);
    }

    uvm_tracker_clear(&replayable_faults->replay_tracker);

    return status;
}


static NV_STATUS push_replay_on_gpu(uvm_gpu_t *gpu, uvm_fault_replay_type_t type, uvm_fault_service_batch_context_t *batch_context)
{
    NV_STATUS status;
    uvm_push_t push;
    uvm_replayable_fault_buffer_info_t *replayable_faults = &gpu->fault_buffer_info.replayable;
    uvm_tracker_t *tracker = NULL;

    if (batch_context)
        tracker = &batch_context->tracker;

    status = uvm_push_begin_acquire(gpu->channel_manager, UVM_CHANNEL_TYPE_MEMOPS, tracker, &push,
                                    "Replaying faults");
    if (status != NV_OK)
        return status;

    gpu->host_hal->replay_faults(&push, type);

    // Do not count REPLAY_TYPE_START_ACK_ALL's toward the replay count.
    // REPLAY_TYPE_START_ACK_ALL's are issued for cancels, and the cancel algorithm checks to make sure that
    // no REPLAY_TYPE_START's have been issued using batch_context->replays.
    if (batch_context && type != UVM_FAULT_REPLAY_TYPE_START_ACK_ALL) {
        uvm_tools_broadcast_replay(gpu, &push, batch_context->batch_id);
        ++batch_context->num_replays;
    }

    uvm_push_end(&push);

    // Add this push to the GPU's replay_tracker so cancel can wait on it.
    status = uvm_tracker_add_push_safe(&replayable_faults->replay_tracker, &push);

    if (uvm_procfs_is_debug_enabled()) {
        if (type == UVM_FAULT_REPLAY_TYPE_START)
            ++replayable_faults->stats.num_replays;
        else
            ++replayable_faults->stats.num_replays_ack_all;
    }

    return status;
}

static NV_STATUS fault_buffer_flush_locked(uvm_gpu_t *gpu,
                                           uvm_gpu_buffer_flush_mode_t flush_mode,
                                           uvm_fault_replay_type_t fault_replay,
                                           uvm_fault_service_batch_context_t *batch_context)
{
    NvU32 get;
    NvU32 put;
    uvm_spin_loop_t spin;
    NvU32 utlb_id;
    uvm_replayable_fault_buffer_info_t *replayable_faults = &gpu->fault_buffer_info.replayable;

    // TODO: Bug 1766600: right now uvm locks do not support the synchronization
    //       method used by top and bottom ISR. Add uvm lock assert when it's
    //       supported. Use plain mutex kernel utilities for now.
    UVM_ASSERT(uvm_gpu_supports_replayable_faults(gpu));
    UVM_ASSERT(mutex_is_locked(&gpu->isr.replayable_faults.service_lock.m));

    // Read PUT pointer from the GPU if requested
    if (flush_mode == UVM_GPU_BUFFER_FLUSH_MODE_UPDATE_PUT)
        replayable_faults->cached_put = gpu->fault_buffer_hal->read_put(gpu);

    get = replayable_faults->cached_get;
    put = replayable_faults->cached_put;

    while (get != put) {
        // Wait until valid bit is set
        UVM_SPIN_WHILE(!gpu->fault_buffer_hal->entry_is_valid(gpu, get), &spin);

        gpu->fault_buffer_hal->entry_clear_valid(gpu, get);
        ++get;
        if (get == replayable_faults->max_faults)
            get = 0;
    }

    // Write get on the GPU only if it's changed.
    if (replayable_faults->cached_get != get) {
        replayable_faults->cached_get = get;

        gpu->fault_buffer_hal->write_get(gpu, get);
    }

    // Reset uTLB stats
    if (batch_context) {
        for (utlb_id = 0; utlb_id <= batch_context->max_utlb_id; ++utlb_id) {
            batch_context->utlbs[utlb_id].num_pending_faults = 0;
            batch_context->utlbs[utlb_id].num_fatal_faults   = 0;
        }
    }

    // Issue fault replay
    return push_replay_on_gpu(gpu, fault_replay, batch_context);
}

NV_STATUS uvm_gpu_fault_buffer_flush(uvm_gpu_t *gpu)
{
    NV_STATUS status = NV_OK;

    UVM_ASSERT(uvm_gpu_supports_replayable_faults(gpu));

    // Disables replayable fault interrupts and fault servicing
    uvm_gpu_replayable_faults_isr_lock(gpu);

    status = fault_buffer_flush_locked(gpu,
                                       UVM_GPU_BUFFER_FLUSH_MODE_UPDATE_PUT,
                                       UVM_FAULT_REPLAY_TYPE_START,
                                       NULL);

    // This will trigger the top half to start servicing faults again, if the
    // replay brought any back in
    uvm_gpu_replayable_faults_isr_unlock(gpu);
    return status;
}

static inline int cmp_fault_instance_ptr(const uvm_fault_buffer_entry_t *a,
                                         const uvm_fault_buffer_entry_t *b)
{
    int result = uvm_gpu_phys_addr_cmp(a->instance_ptr, b->instance_ptr);

    // On Volta+ we need to sort by {instance_ptr + subctx_id} pair since it can
    // map to a different VA space
    if (result != 0)
        return result;
    return UVM_CMP_DEFAULT(a->fault_source.ve_id, b->fault_source.ve_id);



}

// Compare two VA spaces
static inline int cmp_va_space(const uvm_va_space_t *a, const uvm_va_space_t *b)
{
    return UVM_CMP_DEFAULT(a, b);
}

// Compare two virtual addresses
static inline int cmp_addr(NvU64 a, NvU64 b)
{
    return UVM_CMP_DEFAULT(a, b);
}

// Compare two fault access types
static inline int cmp_access_type(uvm_fault_access_type_t a, uvm_fault_access_type_t b)
{
    UVM_ASSERT(a >= 0 && a < UVM_FAULT_ACCESS_TYPE_MAX);
    UVM_ASSERT(b >= 0 && b < UVM_FAULT_ACCESS_TYPE_MAX);

    // Check that fault access type enum values are ordered by "intrusiveness"

    BUILD_BUG_ON(UVM_FAULT_ACCESS_TYPE_ATOMIC_STRONG >= UVM_FAULT_ACCESS_TYPE_ATOMIC_WEAK);
    BUILD_BUG_ON(UVM_FAULT_ACCESS_TYPE_ATOMIC_WEAK >= UVM_FAULT_ACCESS_TYPE_WRITE);



    BUILD_BUG_ON(UVM_FAULT_ACCESS_TYPE_WRITE >= UVM_FAULT_ACCESS_TYPE_READ);
    BUILD_BUG_ON(UVM_FAULT_ACCESS_TYPE_READ >= UVM_FAULT_ACCESS_TYPE_PREFETCH);

    return a - b;
}

typedef enum
{
    // Fetch a batch of faults from the buffer.
    FAULT_FETCH_MODE_BATCH_ALL,

    // Fetch a batch of faults from the buffer. Stop at the first entry that is not ready yet
    FAULT_FETCH_MODE_BATCH_READY,

    // Fetch all faults in the buffer before PUT. Wait for all faults to become ready
    FAULT_FETCH_MODE_ALL,
} fault_fetch_mode_t;

static NvU32 fetch_fault_buffer_entries(uvm_gpu_t *gpu,
                                        uvm_fault_service_batch_context_t *batch_context,
                                        fault_fetch_mode_t fetch_mode)
{
    NvU32 get;
    NvU32 put;
    NvU32 i;
    NvU32 utlb_id;
    uvm_fault_buffer_entry_t *fault_cache;
    uvm_spin_loop_t spin;
    uvm_replayable_fault_buffer_info_t *replayable_faults = &gpu->fault_buffer_info.replayable;

    // TODO: Bug 1766600: right now uvm locks do not support the synchronization
    //       method used by top and bottom ISR. Add uvm lock assert when it's
    //       supported. Use plain mutex kernel utilities for now.
    UVM_ASSERT(mutex_is_locked(&gpu->isr.replayable_faults.service_lock.m));
    UVM_ASSERT(uvm_gpu_supports_replayable_faults(gpu));

    // Check that all prior faults have been serviced
    for (utlb_id = 0; utlb_id <= batch_context->max_utlb_id; ++utlb_id)
        UVM_ASSERT(batch_context->utlbs[utlb_id].num_pending_faults == 0);

    batch_context->max_utlb_id = 0;

    fault_cache = batch_context->fault_cache;

    get = replayable_faults->cached_get;

    // Read put pointer from GPU and cache it
    if (get == replayable_faults->cached_put)
        replayable_faults->cached_put = gpu->fault_buffer_hal->read_put(gpu);

    put = replayable_faults->cached_put;

    if (get == put)
        return 0;

    batch_context->is_single_instance_ptr = true;

    // Parse until get != put and have enough space to cache.
    for (i = 0;
        (get != put) && (fetch_mode == FAULT_FETCH_MODE_ALL || i < gpu->fault_buffer_info.max_batch_size);
        ++i) {
        // We cannot just wait for the last entry (the one pointed by put) to become valid, we have to do it
        // individually since entries can be written out of order
        UVM_SPIN_WHILE(!gpu->fault_buffer_hal->entry_is_valid(gpu, get), &spin) {
            // We have some entry to work on. Let's do the rest later.
            if (fetch_mode != FAULT_FETCH_MODE_ALL &&
                fetch_mode != FAULT_FETCH_MODE_BATCH_ALL &&
                i > 0)
                goto done;
        }

        // Prevent later accesses being moved above the read of the valid bit
        smp_mb__after_atomic();

        // Got valid bit set. Let's cache.
        gpu->fault_buffer_hal->parse_entry(gpu, get, &fault_cache[i]);

        // The GPU aligns the fault addresses to 4k, but all of our tracking is
        // done in PAGE_SIZE chunks which might be larger.
        fault_cache[i].fault_address = UVM_PAGE_ALIGN_DOWN(fault_cache[i].fault_address);

        // Make sure that all fields in the entry are properly initialized
        fault_cache[i].va_space = NULL;
        fault_cache[i].is_fatal = (fault_cache[i].fault_type >= UVM_FAULT_TYPE_FATAL);

        if (fault_cache[i].is_fatal) {
            // Record the fatal fault event later as we need the va_space locked
            fault_cache[i].fatal_reason = UvmEventFatalReasonInvalidFaultType;
        }
        else {
            fault_cache[i].fatal_reason = UvmEventFatalReasonInvalid;
        }

        if (fault_cache[i].fault_source.utlb_id > batch_context->max_utlb_id) {
            UVM_ASSERT(fault_cache[i].fault_source.utlb_id < replayable_faults->utlb_count);
            batch_context->max_utlb_id = fault_cache[i].fault_source.utlb_id;
        }

        if (batch_context->is_single_instance_ptr &&
            i > 0 &&
            cmp_fault_instance_ptr(&fault_cache[i], &fault_cache[i - 1]) != 0) {
            batch_context->is_single_instance_ptr = false;
        }

        ++batch_context->utlbs[fault_cache[i].fault_source.utlb_id].num_pending_faults;

        ++get;
        if (get == replayable_faults->max_faults)
            get = 0;
    }

done:

    // Write get on the GPU only if it's changed.
    if (replayable_faults->cached_get != get) {
        replayable_faults->cached_get = get;

        gpu->fault_buffer_hal->write_get(gpu, get);
    }

    return i;
}

// Sort comparator for pointers to fault buffer entries that sorts by instance pointer
static int cmp_sort_fault_entry_by_instance_ptr(const void *_a, const void *_b)
{
    const uvm_fault_buffer_entry_t **a = (const uvm_fault_buffer_entry_t **)_a;
    const uvm_fault_buffer_entry_t **b = (const uvm_fault_buffer_entry_t **)_b;

    return cmp_fault_instance_ptr(*a, *b);
}

// Sort comparator for pointers to fault buffer entries that sorts by va_space, fault address and fault access type
static int cmp_sort_fault_entry_by_va_space_address_access_type(const void *_a, const void *_b)
{
    const uvm_fault_buffer_entry_t **a = (const uvm_fault_buffer_entry_t **)_a;
    const uvm_fault_buffer_entry_t **b = (const uvm_fault_buffer_entry_t **)_b;

    int result;

    result = cmp_va_space((*a)->va_space, (*b)->va_space);
    if (result != 0)
        return result;

    result = cmp_addr((*a)->fault_address, (*b)->fault_address);
    if (result != 0)
        return result;

    return cmp_access_type((*a)->fault_access_type, (*b)->fault_access_type);
}

// Translate all instance pointers to VA spaces. Since the buffer is ordered by instance_ptr, we minimize the number of
// translations
//
// This function returns NV_WARN_MORE_PROCESSING_REQUIRED if a fault buffer flush occurred and
// executed successfully, or the error code if it failed. NV_OK otherwise.
static NV_STATUS translate_instance_ptrs(uvm_gpu_t *gpu,
                                         uvm_fault_service_batch_context_t *batch_context)
{
    NvU32 i;
    NV_STATUS status;

    for (i = 0; i < batch_context->num_cached_faults; ++i) {
        uvm_fault_buffer_entry_t *current_entry;

        current_entry = batch_context->ordered_fault_cache[i];

        // If this instance pointer matches the previous instance pointer, just
        // copy over the already-translated va_space and move on.
        if (i != 0 && cmp_fault_instance_ptr(current_entry, batch_context->ordered_fault_cache[i - 1]) == 0) {
            current_entry->va_space = batch_context->ordered_fault_cache[i - 1]->va_space;
            continue;
        }

        status = uvm_gpu_fault_entry_to_va_space(gpu, current_entry, &current_entry->va_space);
        if (status != NV_OK) {

            if (status == NV_ERR_PAGE_TABLE_NOT_AVAIL) {
                // The channel is valid but the subcontext is not. This can only
                // happen if the subcontext is torn down before its work is
                // complete while other subcontexts in the same TSG are still
                // executing. This is a violation of the programming model. We
                // have limited options since the VA space is gone, meaning we
                // can't target the PDB for cancel even if we wanted to. So
                // we'll just throw away precise attribution and cancel this
                // fault using the SW method, which validates that the intended
                // context (TSG) is still running so we don't cancel an innocent
                // context.
                UVM_ASSERT(!current_entry->va_space);
                UVM_ASSERT(gpu->max_subcontexts > 0);

                status = push_cancel_on_gpu(gpu,
                                            current_entry->instance_ptr,
                                            current_entry->fault_source.gpc_id,
                                            current_entry->fault_source.client_id,
                                            &batch_context->tracker);
                if (status != NV_OK)
                    return status;

                // Fall through and let the flush restart fault processing
            }
            else {
                UVM_ASSERT(status == NV_ERR_INVALID_CHANNEL);
            }




            // If the channel is gone then we're looking at a stale fault entry.
            // The fault must have been resolved already (serviced or
            // cancelled), so we can just flush the fault buffer.
            status = fault_buffer_flush_locked(gpu,
                                               UVM_GPU_BUFFER_FLUSH_MODE_UPDATE_PUT,
                                               UVM_FAULT_REPLAY_TYPE_START,
                                               batch_context);
            if (status != NV_OK)
                 return status;

            return NV_WARN_MORE_PROCESSING_REQUIRED;
        }
        else {
            UVM_ASSERT(current_entry->va_space);
        }
    }

    return NV_OK;
}

// Fault cache preprocessing for fault coalescing
//
// This function generates an ordered view of the given fault_cache in which faults are sorted by VA space, fault
// address (aligned to 4K) and access type "intrusiveness" (atomic - write - read - prefetch). In order to minimize
// the number of instance_ptr to VA space translations we perform a first sort by instance_ptr.
//
// This function returns NV_WARN_MORE_PROCESSING_REQUIRED if a fault buffer flush occurred during instance_ptr
// translation and executed successfully, or the error code if it failed. NV_OK otherwise.
//
// Current scheme:
// 1) sort by instance_ptr
// 2) translate all instance_ptrs to VA spaces
// 3) sort by va_space, fault address (GPU already reports 4K-aligned address) and access type
static NV_STATUS preprocess_fault_batch(uvm_gpu_t *gpu, uvm_fault_service_batch_context_t *batch_context)
{
    NV_STATUS status;
    NvU32 i;
    uvm_fault_buffer_entry_t **ordered_fault_cache = batch_context->ordered_fault_cache;

    UVM_ASSERT(batch_context->num_cached_faults > 0);

    // Generate an ordered view of the fault cache in ordered_fault_cache. We sort the pointers, not the entries
    // in fault_cache

    // Initialize pointers before they are sorted
    for (i = 0; i < batch_context->num_cached_faults; ++i)
        ordered_fault_cache[i] = &batch_context->fault_cache[i];

    // 1) if the fault batch contains more than one, sort by instance_ptr
    if (!batch_context->is_single_instance_ptr) {
        sort(ordered_fault_cache,
             batch_context->num_cached_faults,
             sizeof(*ordered_fault_cache),
             cmp_sort_fault_entry_by_instance_ptr,
             NULL);
    }

    // 2) translate all instance_ptrs to VA spaces
    status = translate_instance_ptrs(gpu, batch_context);
    if (status != NV_OK)
        return status;

    // 3) sort by va_space, fault address (GPU already reports 4K-aligned address) and access type
    sort(ordered_fault_cache,
         batch_context->num_cached_faults,
         sizeof(*ordered_fault_cache),
         cmp_sort_fault_entry_by_va_space_address_access_type,
         NULL);
#if 0
UCM_DBG("\n\n GOT %d cached faults:\n", batch_context->num_cached_faults);
if (batch_context->num_cached_faults == UVM_PERF_FAULT_BATCH_COUNT_DEFAULT) {
	NvU64 addr_prev = 0;
	for (i = 0; i < batch_context->num_cached_faults; ++i) {
		NvU64 addr = ordered_fault_cache[i]->fault_address;
		if (addr != addr_prev) {pr_err("(%d) 0x%llx,  ",i, addr); addr_prev = addr;}
	}
	UCM_DBG("\n\n");
}
#endif
    return NV_OK;
}

// We notify the fault event for all faults within the block so that the
// performance heuristics are updated. Then, all required actions for the block
// data are performed by the performance heuristics code.
//
// Fatal faults are flagged as fatal for later cancellation. Servicing is not
// interrupted on fatal faults due to insufficient permissions or invalid
// addresses.
//
// Return codes:
// - NV_OK if all faults were handled (both fatal and non-fatal)
// - NV_ERR_MORE_PROCESSING_REQUIRED if servicing needs allocation retry
// - NV_ERR_NO_MEMORY if the faults could not be serviced due to OOM
// - Any other value is a UVM-global error
static NV_STATUS service_fault_batch_block_locked(uvm_gpu_t *gpu,
                                                  uvm_va_block_t *va_block,
                                                  uvm_va_block_retry_t *va_block_retry,
                                                  NvU32 first_fault_index,
                                                  uvm_fault_service_batch_context_t *batch_context,
                                                  NvU32 *block_faults)
{
    NV_STATUS status = NV_OK;
    NvU32 i;
    NvU32 block_fatal_faults = 0;
    NvU32 block_throttled_faults = 0;
    NvU32 block_invalid_prefetch_faults = 0;
    NvU32 first_page_index;
    NvU32 last_page_index;
    NvU32 page_fault_count = 0;
    uvm_range_group_range_iter_t iter;
    uvm_replayable_fault_buffer_info_t *replayable_faults = &gpu->fault_buffer_info.replayable;
    uvm_fault_buffer_entry_t **ordered_fault_cache = batch_context->ordered_fault_cache;
    uvm_fault_service_block_context_t *block_context = &replayable_faults->block_service_context;
    uvm_va_space_t *va_space;

    // Check that all uvm_fault_access_type_t values can fit into an NvU8
    BUILD_BUG_ON(UVM_FAULT_ACCESS_TYPE_MAX > (int)(NvU8)-1);

    uvm_assert_mutex_locked(&va_block->lock);

    // Check that the va_block is still valid
    UVM_ASSERT(va_block->va_range);
    va_space = va_block->va_range->va_space;

    *block_faults = 0;

    // Initialize fault service block context
    uvm_processor_mask_zero(&block_context->resident_processors);

    first_page_index = PAGES_PER_UVM_VA_BLOCK;
    last_page_index = 0;

    block_context->thrashing_pin_count = 0;
    block_context->read_duplicate_count = 0;

    block_context->are_replayable_faults = true;


    uvm_range_group_range_migratability_iter_first(va_space, va_block->start, va_block->end, &iter);

    // The first entry is guaranteed to fall within this block
    UVM_ASSERT(ordered_fault_cache[first_fault_index]->va_space == va_space);
    UVM_ASSERT(ordered_fault_cache[first_fault_index]->fault_address >= va_block->start);
    UVM_ASSERT(ordered_fault_cache[first_fault_index]->fault_address <= va_block->end);

    // Scan the sorted array and notify the fault event for all fault entries in the block
    for (i = first_fault_index;
         i < batch_context->num_cached_faults &&
         ordered_fault_cache[i]->va_space == va_space &&
         ordered_fault_cache[i]->fault_address <= va_block->end;
         ++i) {
        uvm_fault_buffer_entry_t *current_entry = ordered_fault_cache[i];
        uvm_fault_buffer_entry_t *previous_entry = NULL;
        NV_STATUS perm_status;
        bool read_duplicate;
        uvm_processor_id_t new_residency;
        uvm_perf_thrashing_hint_t thrashing_hint;
        uvm_va_block_region_t region = uvm_va_block_region_from_start_size(va_block,
                                                                           current_entry->fault_address,
                                                                           PAGE_SIZE);
        bool is_duplicate;

        current_entry->is_fatal            = false;
        current_entry->is_throttled        = false;
        current_entry->is_invalid_prefetch = false;

        thrashing_hint.type = UVM_PERF_THRASHING_HINT_TYPE_NONE;

        if (i > first_fault_index)
            previous_entry = ordered_fault_cache[i - 1];

        is_duplicate = (i > first_fault_index && current_entry->fault_address == previous_entry->fault_address);

        if (block_context->num_retries == 0) {
            uvm_perf_event_notify_gpu_fault(&va_space->perf_events,
                                            va_block,
                                            gpu->id,
                                            current_entry,
                                            batch_context->batch_id,
                                            is_duplicate);

            if (is_duplicate)
                ++batch_context->num_duplicate_faults;
        }

        // Service the most intrusive fault per page, only. Waive the rest
        if (is_duplicate) {
            // Propagate the is_invalid_prefetch flag across all prefetch faults on the page
            if (previous_entry->is_invalid_prefetch)
                current_entry->is_invalid_prefetch = true;

            // If a page is throttled, all faults on the page must be skipped
            if (previous_entry->is_throttled)
                current_entry->is_throttled = true;

            // The previous fault was non-fatal so the page has been already serviced
            if (!previous_entry->is_fatal)
                goto next;
        }

        // ensure that the migratability iterator covers the current fault address
        while (iter.end < current_entry->fault_address)
            uvm_range_group_range_migratability_iter_next(va_space, &iter, va_block->end);

        UVM_ASSERT(iter.start <= current_entry->fault_address && iter.end >= current_entry->fault_address);

        // Check logical permissions
        perm_status = uvm_va_range_check_logical_permissions(va_block->va_range, gpu->id,
                                                             current_entry->fault_access_type,
                                                             iter.migratable);
        if (perm_status != NV_OK) {
            if (current_entry->fault_access_type != UVM_FAULT_ACCESS_TYPE_PREFETCH) {
                // Do not exit early due to logical errors. Flag the fault as fatal for later
                // cancellation and keep going
                current_entry->is_fatal = true;
                current_entry->fatal_reason = uvm_tools_status_to_fatal_fault_reason(perm_status);
            }
            else {
                current_entry->is_invalid_prefetch = true;
            }

            goto next;
        }

        // If the GPU already has the necessary access permission, the fault does not need to be serviced
        if (uvm_va_block_is_gpu_authorized_on_whole_region(va_block,
                                                           region,
                                                           gpu->id,
                                                           uvm_fault_access_type_to_prot(current_entry->fault_access_type)))
            goto next;

        thrashing_hint = uvm_perf_thrashing_get_hint(va_block, current_entry->fault_address, gpu->id);
        if (thrashing_hint.type == UVM_PERF_THRASHING_HINT_TYPE_THROTTLE) {
            // Throttling is implemented by sleeping in the fault handler on the CPU and by continuing to
            // process faults on other pages on the GPU
            current_entry->is_throttled = true;
            goto next;
        }
        else if (thrashing_hint.type == UVM_PERF_THRASHING_HINT_TYPE_PIN) {
            if (block_context->thrashing_pin_count++ == 0)
                uvm_page_mask_zero(block_context->thrashing_pin_mask);

            __set_bit(region.first, block_context->thrashing_pin_mask);
        }

        // Compute new residency and update the masks
        new_residency = uvm_va_block_select_residency_after_fault(va_block,
                                                                  region,
                                                                  gpu->id,
                                                                  current_entry->fault_access_type,
                                                                  &thrashing_hint,
                                                                  &read_duplicate);

        if (!uvm_processor_mask_test(&block_context->resident_processors, new_residency)) {
            uvm_processor_mask_set(&block_context->resident_processors, new_residency);
            uvm_page_mask_zero(block_context->per_processor_masks[new_residency].new_residency);
        }

        __set_bit(region.first, block_context->per_processor_masks[new_residency].new_residency);

        if (read_duplicate) {
            if (block_context->read_duplicate_count++ == 0)
                uvm_page_mask_zero(block_context->read_duplicate_mask);

            __set_bit(region.first, block_context->read_duplicate_mask);
        }

        ++page_fault_count;

        block_context->fault_access_type[region.first] = current_entry->fault_access_type;

        if (region.first < first_page_index)
            first_page_index = region.first;
        if (region.first > last_page_index)
            last_page_index = region.first;

    next:
        // Only update counters the first time since logical permissions cannot change while we hold the
        // VA space lock
        // TODO: Bug 1750144: That might not be true with HMM.
        if (block_context->num_retries == 0) {
            uvm_fault_utlb_info_t *utlb = &batch_context->utlbs[current_entry->fault_source.utlb_id];

            if (current_entry->is_fatal) {
                ++block_fatal_faults;
                ++utlb->num_fatal_faults;
            }

            if (current_entry->is_invalid_prefetch)
                ++block_invalid_prefetch_faults;

            if (current_entry->is_throttled)
                ++block_throttled_faults;

            UVM_ASSERT(utlb->num_pending_faults > 0);
            --utlb->num_pending_faults;
        }
    }

    // Apply the changes computed in the fault service block context, if there are pages to be serviced
    if (page_fault_count > 0) {
        block_context->fault_region = uvm_va_block_region(first_page_index, last_page_index + 1);
        status = uvm_va_block_service_faults_locked(gpu->id, va_block, va_block_retry, block_context);
    }

    *block_faults = i - first_fault_index;

    ++block_context->num_retries;

    if (status == NV_OK && block_fatal_faults > 0)
        status = uvm_va_block_set_cancel(va_block, gpu);

    // Report context counters when we are sure we won't retry
    if (status == NV_OK) {
        batch_context->num_fatal_faults            += block_fatal_faults;
        batch_context->num_throttled_faults        += block_throttled_faults;
        batch_context->num_invalid_prefetch_faults += block_invalid_prefetch_faults;
        batch_context->num_serviced_faults         += *block_faults - (block_fatal_faults +
                                                                       block_invalid_prefetch_faults +
                                                                       block_throttled_faults);
    }

    return status;
}

// We notify the fault event for all faults within the block so that the performance heuristics are updated.
// The VA block lock is taken for the whole fault servicing although it might be temporarily dropped and
// re-taken if memory eviction is required.
//
// See the comments for function service_fault_batch_block_locked for implementation details and error codes.
static NV_STATUS service_fault_batch_block(uvm_gpu_t *gpu, uvm_va_block_t *va_block,
                                           NvU32 first_fault_index,
                                           uvm_fault_service_batch_context_t *batch_context,
                                           NvU32 *block_faults)
{
    NV_STATUS status;
    uvm_va_block_retry_t va_block_retry;
    NV_STATUS tracker_status;
    uvm_fault_service_block_context_t *block_context = &gpu->fault_buffer_info.replayable.block_service_context;

    block_context->num_retries = 0;

    uvm_mutex_lock(&va_block->lock);

    status = UVM_VA_BLOCK_RETRY_LOCKED(va_block, &va_block_retry,
                                       service_fault_batch_block_locked(gpu,
                                                                        va_block,
                                                                        &va_block_retry,
                                                                        first_fault_index,
                                                                        batch_context,
                                                                        block_faults));

    tracker_status = uvm_tracker_add_tracker_safe(&batch_context->tracker, &va_block->tracker);

    uvm_mutex_unlock(&va_block->lock);

    return status == NV_OK? tracker_status: status;
}

typedef enum
{
    // Use this mode when calling from the normal fault servicing path
    FAULT_SERVICE_MODE_REGULAR,

    // Use this mode when servicing faults from the fault cancelling algorithm. In this mode no replays are issued
    FAULT_SERVICE_MODE_CANCEL,
} fault_service_mode_t;


#if defined(NV_PNV_NPU2_INIT_CONTEXT_PRESENT)
NV_STATUS uvm_ats_service_fault_entry(uvm_gpu_t *gpu,
                                      NvU32 entry_index,
                                      uvm_fault_service_batch_context_t *batch_context)
{
    uvm_gpu_va_space_t *gpu_va_space;
    uvm_fault_buffer_entry_t *previous_entry = NULL;
    uvm_fault_buffer_entry_t *current_entry = batch_context->ordered_fault_cache[entry_index];
    uvm_fault_utlb_info_t *utlb = &batch_context->utlbs[current_entry->fault_source.utlb_id];
    unsigned long flags;
    uintptr_t addr;
    unsigned long fault_status = 0;
    NV_STATUS status = NV_OK;
    bool is_duplicate = false;

    if (entry_index > 0)
        previous_entry = batch_context->ordered_fault_cache[entry_index - 1];

    // This is a bringup driver, so do some verbose printing:
    uvm_hal_print_fault_entry(current_entry);

    // Service the most intrusive fault per page, only. Waive the rest.
    if ((entry_index > 0) && (current_entry->va_space == previous_entry->va_space) &&
        (current_entry->fault_address == previous_entry->fault_address)) {
        // Propagate the is_invalid_prefetch flag across all prefetch faults on the page
        if (previous_entry->is_invalid_prefetch)
            current_entry->is_invalid_prefetch = true;

        // If a page is throttled, all faults on the page must be skipped
        if (previous_entry->is_throttled)
            current_entry->is_throttled = true;

        is_duplicate = true;
    }

    // Generate fault events for all fault packets
    uvm_perf_event_notify_gpu_fault(&current_entry->va_space->perf_events,
                                    NULL,
                                    gpu->id,
                                    current_entry,
                                    0,
                                    is_duplicate);

    // The previous fault was non-fatal so the page has been already serviced
    if (is_duplicate && !previous_entry->is_fatal)
        goto skip_fault;

    // TODO: Bug 1896767: Service more than a single fault at a time
    flags = (unsigned long)((current_entry->fault_access_type <= UVM_FAULT_ACCESS_TYPE_WRITE) ? NPU2_WRITE : 0);
    addr = (uintptr_t)current_entry->fault_address;

    // TODO: Bug 1896767: Combine ATS and non-ATS fault servicing so we can
    //       handle both types of faults in the same GPU VA space.
    gpu_va_space = uvm_gpu_va_space_get(current_entry->va_space, gpu);
    if (gpu_va_space->ats_enabled) {
        status = errno_to_nv_status(pnv_npu2_handle_fault(gpu_va_space->npu_context, &addr, &flags, &fault_status, 1));
    }
    else {
        pr_info_ratelimited("Support is not yet implemented for faults in non-ATS GPU VA spaces "
                            "when loading with uvm8_ats_mode=1, cancelling.\n");
        status = NV_ERR_INVALID_ADDRESS;
    }

    // Do not flag prefetch faults as fatal unless something fatal happened
    if (status == NV_ERR_INVALID_ADDRESS) {
        if (current_entry->fault_access_type != UVM_FAULT_ACCESS_TYPE_PREFETCH) {
            current_entry->is_fatal = true;
            current_entry->fatal_reason = uvm_tools_status_to_fatal_fault_reason(status);
        }

        // Do not fail overall fault servicing due to logical errors
        status = NV_OK;
    }

skip_fault:
    if (current_entry->is_fatal) {
        ++batch_context->num_fatal_faults;
        ++utlb->num_fatal_faults;
    }

    if (current_entry->is_invalid_prefetch)
        ++batch_context->num_invalid_prefetch_faults;

    if (current_entry->is_throttled)
        ++batch_context->num_throttled_faults;

    UVM_ASSERT(utlb->num_pending_faults > 0);
    --utlb->num_pending_faults;

    return status;
}
#endif


static void uvm_down_read_mmap_sem_unsafe(uvm_va_space_t *va_space)
{

    #if defined(NV_PNV_NPU2_INIT_CONTEXT_PRESENT)
        // TODO: Bug 1896767: See the comments on unsafe_mm in uvm8_va_space.h.
        //       We can only get here when loaded in ATS mode (uvm8_ats_mode=1).
        if (va_space->unsafe_mm)
            uvm_down_read_mmap_sem(&va_space->unsafe_mm->mmap_sem);
    #endif

}

static void uvm_up_read_mmap_sem_unsafe(uvm_va_space_t *va_space)
{

    #if defined(NV_PNV_NPU2_INIT_CONTEXT_PRESENT)
        // TODO: Bug 1896767: See the comments on unsafe_mm in uvm8_va_space.h.
        //       We can only get here when loaded in ATS mode (uvm8_ats_mode=1).
        if (va_space->unsafe_mm)
            uvm_up_read_mmap_sem(&va_space->unsafe_mm->mmap_sem);
    #endif

}


static NV_STATUS service_ats_fault_entry(uvm_gpu_t *gpu,
                                         NvU32 entry_index,
                                         uvm_fault_service_batch_context_t *batch_context)
{
    #if defined(NV_PNV_NPU2_INIT_CONTEXT_PRESENT)
        if (uvm8_ats_mode)
            return uvm_ats_service_fault_entry(gpu, entry_index, batch_context);
    #else
        UVM_ASSERT(!uvm8_ats_mode);
    #endif

    return NV_ERR_NOT_SUPPORTED;
}


// Scan the ordered view of faults and group them by different va_blocks. Service faults for each va_block, in batch.
//
// This function returns NV_WARN_MORE_PROCESSING_REQUIRED if the fault buffer was flushed because the
// needs_fault_buffer_flush flag was set on some GPU VA space
static NV_STATUS service_fault_batch(uvm_gpu_t *gpu,
                                     fault_service_mode_t service_mode,
                                     uvm_fault_service_batch_context_t *batch_context)
{
    NV_STATUS status = NV_OK;
    NvU32 i;
    uvm_va_space_t *va_space = NULL;
    bool va_block_supported = false;

    UVM_ASSERT(uvm_gpu_supports_replayable_faults(gpu));

    for (i = 0; i < batch_context->num_cached_faults;) {
        uvm_va_block_t *va_block;
        NvU32 block_faults;
        uvm_fault_buffer_entry_t *current_entry = batch_context->ordered_fault_cache[i];
        uvm_fault_utlb_info_t *utlb = &batch_context->utlbs[current_entry->fault_source.utlb_id];

        UVM_ASSERT(current_entry->va_space);

        if (current_entry->va_space != va_space) {
            uvm_gpu_va_space_t *gpu_va_space;
            // Fault on a different va_space, drop the lock of the old one...
            if (va_space != NULL) {
                uvm_va_space_up_read(va_space);
                uvm_up_read_mmap_sem_unsafe(va_space);
            }

            va_space = current_entry->va_space;

            // ... and take the lock of the new one
            //
            // TODO: Bug 1867098: Taking mmap_sem here may deadlock between RM
            //       and UVM.
            uvm_down_read_mmap_sem_unsafe(va_space);
            uvm_va_space_down_read(va_space);

            gpu_va_space = uvm_gpu_va_space_get(va_space, gpu);
            if (gpu_va_space && gpu_va_space->needs_fault_buffer_flush) {
                // flush if required and clear the flush flag
                status = fault_buffer_flush_locked(gpu,
                                                   UVM_GPU_BUFFER_FLUSH_MODE_UPDATE_PUT,
                                                   UVM_FAULT_REPLAY_TYPE_START,
                                                   batch_context);
                gpu_va_space->needs_fault_buffer_flush = false;

                if (status == NV_OK)
                    status = NV_WARN_MORE_PROCESSING_REQUIRED;

                break;
            }
            // The case where there is no valid GPU VA space for the GPU in this VA space is handled next
        }

        // Some faults could be already fatal if they cannot be handled by the UVM driver
        if (current_entry->is_fatal) {
            ++i;
            ++batch_context->num_fatal_faults;
            ++utlb->num_fatal_faults;
            UVM_ASSERT(utlb->num_pending_faults > 0);
            --utlb->num_pending_faults;
            continue;
        }

        if (!uvm_processor_mask_test(&va_space->registered_gpu_va_spaces, gpu->id)) {
            // If there is no GPU VA space for the GPU, ignore the fault. This can happen if a GPU VA space is
            // destroyed without explicitly freeing all memory ranges (destroying the VA range triggers a flush
            // of the fault buffer) and there are stale entries in the buffer that got fixed by the servicing
            // in a previous batch
            ++i;
            continue;
        }


        // ATS fault servicing routine. It will return NV_ERR_NOT_SUPPORTED if
        // called on unsupported platforms.
        status = service_ats_fault_entry(gpu, i, batch_context);




        if (status == NV_OK) {
            va_block_supported = false;
        }
        else if (status == NV_ERR_NOT_SUPPORTED) {
            status = uvm_va_block_find_create(current_entry->va_space, current_entry->fault_address, &va_block);
            if (status == NV_OK) {
                va_block_supported = true;
                status = service_fault_batch_block(gpu, va_block, i, batch_context, &block_faults);

                // When service_fault_batch_block returns != NV_OK something really bad happened
                if (status != NV_OK)
                    goto fail;
            }
            else  {
                // Avoid dropping fault events when the VA block is not found or cannot be created
                uvm_perf_event_notify_gpu_fault(&va_space->perf_events,
                                                NULL,
                                                gpu->id,
                                                current_entry,
                                                batch_context->batch_id,
                                                false);

                UVM_ASSERT(utlb->num_pending_faults > 0);
                --utlb->num_pending_faults;

                if (status == NV_ERR_INVALID_ADDRESS) {
                    // If the VA block cannot be found, set the fatal fault flag, unless it is a prefetch fault
                    if (current_entry->fault_access_type == UVM_FAULT_ACCESS_TYPE_PREFETCH) {
                        ++batch_context->num_invalid_prefetch_faults;
                    }
                    else {
                        current_entry->is_fatal = true;
                        current_entry->fatal_reason = uvm_tools_status_to_fatal_fault_reason(status);
                        ++batch_context->num_fatal_faults;
                        ++utlb->num_fatal_faults;
                    }

                    // Do not exit early due to logical errors
                    status = NV_OK;
                }
                else if (status != NV_OK) {
                    goto fail;
                }

                ++i;
                continue;
            }
        }
        else {

            // ATS fault servicing failure

            goto fail;
        }

        // Don't issue replays in cancel mode
        if (service_mode != FAULT_SERVICE_MODE_CANCEL &&
            gpu->fault_buffer_info.replayable.replay_policy == UVM_PERF_FAULT_REPLAY_POLICY_BLOCK) {
            status = push_replay_on_gpu(gpu, UVM_FAULT_REPLAY_TYPE_START, batch_context);
            if (status != NV_OK)
                goto fail;

            // Increment the batch id if UVM_PERF_FAULT_REPLAY_POLICY_BLOCK
            // is used, as we issue a replay after servicing each VA block
            // and we can service a number of VA blocks before returning.
            ++batch_context->batch_id;
        }

        if (va_block_supported)
            i += block_faults;
        else
            ++i;
    }

fail:
    if (va_space != NULL) {
        uvm_va_space_up_read(va_space);
        uvm_up_read_mmap_sem_unsafe(va_space);
    }

    return status;
}

// Tells if the given fault entry is the first one in its uTLB
static bool is_first_fault_in_utlb(uvm_fault_service_batch_context_t *batch_context, NvU32 fault_index)
{
    NvU32 i;
    NvU32 utlb_id = batch_context->fault_cache[fault_index].fault_source.utlb_id;

    for (i = 0; i < fault_index; ++i) {
        uvm_fault_buffer_entry_t *current_entry = &batch_context->fault_cache[i];

        // We have found a prior fault in the same uTLB
        if (current_entry->fault_source.utlb_id == utlb_id)
            return false;
    }

    return true;
}

// Compute the number of fatal and non-fatal faults for a page in the given uTLB
static void faults_for_page_in_utlb(uvm_fault_service_batch_context_t *batch_context,
                                    uvm_va_space_t *va_space,
                                    NvU64 addr,
                                    NvU32 utlb_id,
                                    NvU32 *fatal_faults,
                                    NvU32 *non_fatal_faults)
{
    NvU32 i;

    *fatal_faults = 0;
    *non_fatal_faults = 0;

    for (i = 0; i < batch_context->num_cached_faults; ++i) {
        uvm_fault_buffer_entry_t *current_entry = &batch_context->fault_cache[i];

        if (current_entry->fault_source.utlb_id == utlb_id &&
            current_entry->va_space == va_space && current_entry->fault_address == addr) {
            // We have found the page
            if (current_entry->is_fatal)
                ++(*fatal_faults);
            else
                ++(*non_fatal_faults);
        }
    }
}

// Function that tells if there are addresses (reminder: they are aligned to 4K) with non-fatal faults only
static bool no_fatal_pages_in_utlb(uvm_fault_service_batch_context_t *batch_context,
                                   NvU32 start_index,
                                   NvU32 utlb_id)
{
    NvU32 i;

    for (i = start_index; i < batch_context->num_cached_faults; ++i) {
        uvm_fault_buffer_entry_t *current_entry = &batch_context->fault_cache[i];

        if (current_entry->fault_source.utlb_id == utlb_id) {
            // We have found a fault for the uTLB
            NvU32 fatal_faults;
            NvU32 non_fatal_faults;

            faults_for_page_in_utlb(batch_context,
                                    current_entry->va_space,
                                    current_entry->fault_address,
                                    utlb_id,
                                    &fatal_faults,
                                    &non_fatal_faults);

            if (non_fatal_faults > 0 && fatal_faults == 0)
                return true;
        }
    }

    return false;
}

static void record_fatal_fault_helper(uvm_gpu_t *gpu, uvm_fault_buffer_entry_t *entry, UvmEventFatalReason reason)
{
    uvm_va_space_t *va_space;

    va_space = entry->va_space;
    UVM_ASSERT(va_space);
    uvm_va_space_down_read(va_space);
    // Record fatal fault event
    uvm_tools_record_gpu_fatal_fault(gpu->id, va_space, entry, reason);
    uvm_va_space_up_read(va_space);
}

// This function tries to find and issue a cancel for each uTLB that meets the requirements to guarantee precise
// fault attribution:
// - No new faults can arrive on the uTLB (uTLB is in lockdown)
// - The first fault in the buffer for a specific uTLB is fatal
// - There are no other addresses in the uTLB with non-fatal faults only
//
// This function and the related helpers iterate over faults as read from HW, not through the ordered fault view
//
// TODO: Bug 1766754
// This is very costly, although not critical for performance since we are cancelling.
// - Build a list with all the faults within a uTLB
// - Sort by uTLB id
static NV_STATUS try_to_cancel_utlbs(uvm_gpu_t *gpu, uvm_fault_service_batch_context_t *batch_context)
{
    NvU32 i;

    for (i = 0; i < batch_context->num_cached_faults; ++i) {
        uvm_fault_buffer_entry_t *current_entry = &batch_context->fault_cache[i];
        uvm_fault_utlb_info_t *utlb = &batch_context->utlbs[current_entry->fault_source.utlb_id];
        NvU32 gpc_id = current_entry->fault_source.gpc_id;
        NvU32 utlb_id = current_entry->fault_source.utlb_id;
        NvU32 client_id = current_entry->fault_source.client_id;

        // Only fatal faults are considered
        if (!current_entry->is_fatal)
            continue;

        // Only consider uTLBs in lock-down
        if (!utlb->in_lockdown)
            continue;

        // Issue a single cancel per uTLB
        if (utlb->cancelled)
            continue;

        if (is_first_fault_in_utlb(batch_context, i) &&
            !no_fatal_pages_in_utlb(batch_context, i + 1, utlb_id)) {
            NV_STATUS status;

            record_fatal_fault_helper(gpu, current_entry, current_entry->fatal_reason);

            status = push_cancel_on_gpu(gpu, current_entry->instance_ptr, gpc_id, client_id, &batch_context->tracker);
            if (status != NV_OK)
                return status;

            utlb->cancelled = true;
        }
    }

    return NV_OK;
}

static NvU32 find_fatal_fault_in_utlb(uvm_fault_service_batch_context_t *batch_context,
                                      NvU32 utlb_id)
{
    NvU32 i;

    for (i = 0; i < batch_context->num_cached_faults; ++i) {
        if (batch_context->fault_cache[i].is_fatal &&
            batch_context->fault_cache[i].fault_source.utlb_id == utlb_id)
            return i;
    }

    return i;
}

static NvU32 is_fatal_fault_in_buffer(uvm_fault_service_batch_context_t *batch_context,
                                      uvm_fault_buffer_entry_t *fault)
{
    NvU32 i;

    for (i = 0; i < batch_context->num_cached_faults; ++i) {
        uvm_fault_buffer_entry_t *current_entry = &batch_context->fault_cache[i];
        if (cmp_fault_instance_ptr(current_entry, fault) == 0 &&
            current_entry->fault_address == fault->fault_address &&
            current_entry->fault_access_type == fault->fault_access_type &&
            current_entry->fault_source.utlb_id == fault->fault_source.utlb_id) {
            return true;
        }
    }

    return false;
}



typedef enum
{
    // Only cancel faults flagged as fatal
    FAULT_CANCEL_MODE_FATAL,

    // Cancel all faults in the batch unconditionally
    FAULT_CANCEL_MODE_ALL,
} fault_cancel_mode_t;

// Cancel faults in the given fault service batch context. The function provides
// two different modes depending on the value of cancel_mode:
// - If cancel_mode == FAULT_CANCEL_MODE_FATAL, only faults flagged as fatal
// will be cancelled. In this case, the reason reported to tools is the one
// contained in the fault entry itself.
// - If cancel_mode == FAULT_CANCEL_MODE_ALL, all faults will be cancelled
// unconditionally. In this case, the reason reported to tools for non-fatal
// faults is the one passed to this function.
static NV_STATUS cancel_faults_precise_va(uvm_gpu_t *gpu,
                                          uvm_fault_service_batch_context_t *batch_context,
                                          fault_cancel_mode_t cancel_mode,
                                          UvmEventFatalReason reason)
{
    NV_STATUS status = NV_OK;
    uvm_va_space_t *va_space = NULL;
    NvU32 i;

    UVM_ASSERT(uvm_gpu_supports_fault_cancel_va(gpu));
    if (cancel_mode == FAULT_CANCEL_MODE_ALL)
        UVM_ASSERT(reason != UvmEventFatalReasonInvalid);

    for (i = 0; i < batch_context->num_cached_faults; ++i) {
        uvm_fault_buffer_entry_t *current_entry = batch_context->ordered_fault_cache[i];

        UVM_ASSERT(current_entry->va_space);

        if (current_entry->va_space != va_space) {
            // Fault on a different va_space, drop the lock of the old one...
            if (va_space != NULL)
                uvm_va_space_up_read(va_space);

            va_space = current_entry->va_space;

            // ... and take the lock of the new one
            uvm_va_space_down_read(va_space);

            // We don't need to check whether a buffer flush is required (due to VA range destruction).
            // - For cancel_mode == FAULT_CANCEL_MODE_FATAL, once a fault is flagged as fatal we need to cancel it,
            // even if its VA range no longer exists.
            // - For cancel_mode == FAULT_CANCEL_MODE_ALL we don't care about any of this, we just want to trigger
            // RC in RM.
        }

        if (!uvm_processor_mask_test(&va_space->registered_gpu_va_spaces, gpu->id)) {
            // If there is no GPU VA space for the GPU, ignore the fault. This can happen if the GPU VA did not exist
            // in service_fault_batch, or it was destroyed since then. This is to avoid targetting a PDB that might
            // have been reused by another process.
            continue;
        }

        // Cancel the fault
        if (cancel_mode == FAULT_CANCEL_MODE_ALL || current_entry->is_fatal) {
            // If cancelling unconditionally and the fault was not fatal, set the cancel reason passed to this
            // function
            if (!current_entry->is_fatal)
                current_entry->fatal_reason = reason;

            status = cancel_fault_precise_va(gpu, current_entry);
            if (status != NV_OK)
                break;
        }
    }

    if (va_space != NULL)
        uvm_va_space_up_read(va_space);

    return status;
}




// Function called when the system has fould a global error and needs to trigger RC in RM
// We cancel one entry per uTLB
static void cancel_fault_batch_tlb(uvm_gpu_t *gpu,
                                   uvm_fault_service_batch_context_t *batch_context,
                                   UvmEventFatalReason reason)
{
    NvU32 i;

    for (i = 0; i < batch_context->num_cached_faults; ++i) {
        NV_STATUS status;
        uvm_fault_buffer_entry_t *current_entry;
        uvm_fault_utlb_info_t *utlb;

        current_entry = &batch_context->fault_cache[i];
        utlb = &batch_context->utlbs[current_entry->fault_source.utlb_id];

        // If this uTLB has been already cancelled, skip it
        if (utlb->cancelled)
            continue;

        record_fatal_fault_helper(gpu, current_entry, reason);

        status = push_cancel_on_gpu(gpu,
                                    current_entry->instance_ptr,
                                    current_entry->fault_source.gpc_id,
                                    current_entry->fault_source.client_id,
                                    &batch_context->tracker);
        if (status != NV_OK)
            break;

        utlb->cancelled = true;
    }
}

static void cancel_fault_batch(uvm_gpu_t *gpu,
                               uvm_fault_service_batch_context_t *batch_context,
                               UvmEventFatalReason reason)
{

    if (uvm_gpu_supports_fault_cancel_va(gpu)) {
        cancel_faults_precise_va(gpu, batch_context, FAULT_CANCEL_MODE_ALL, reason);
        return;
    }


    cancel_fault_batch_tlb(gpu, batch_context, reason);
}


// Current fault cancel algorithm
//
// 1- Disable prefetching to avoid new requests keep coming and flooding the buffer
// LOOP
//   2- Record one fatal fault per uTLB to check if it shows up after the replay
//   3- Flush fault buffer (REPLAY_TYPE_START_ACK_ALL to prevent new faults from coming to TLBs with pending faults)
//   4- Wait for replay to finish
//   5- Fetch all faults from buffer
//   6- Check what uTLBs are in lockdown mode and can be cancelled
//   7- Preprocess faults (order per va_space, fault address, access type)
//   8- Service all non-fatal faults and mark all non-serviceable faults as fatal
//      6.1- If fatal faults are not found, we are done
//   9- Search for a uTLB which can be targeted for cancel, as described in try_to_cancel_utlbs. If found, cancel it.
// END LOOP
// 10- Re-enable prefetching
//
// NOTE: prefetch faults MUST NOT trigger fault cancel. We make sure that no prefetch faults are left in the buffer
// by disabling prefetching and flushing the fault buffer afterwards (prefetch faults are not replayed and, therefore,
// will not show up again)
static NV_STATUS cancel_faults_precise_tlb(uvm_gpu_t *gpu, uvm_fault_service_batch_context_t *batch_context)
{
    NV_STATUS status;
    NV_STATUS tracker_status;
    uvm_replayable_fault_buffer_info_t *replayable_faults = &gpu->fault_buffer_info.replayable;

    UVM_ASSERT(uvm_gpu_supports_replayable_faults(gpu));

    // 1) Disable prefetching to avoid new requests keep coming and flooding the buffer
    if (gpu->fault_buffer_info.prefetch_faults_enabled)
        gpu->arch_hal->disable_prefetch_faults(gpu);

    while (1) {
        NvU32 utlb_id;

        batch_context->num_fatal_faults            = 0;
        batch_context->num_serviced_faults         = 0;
        batch_context->num_throttled_faults        = 0;
        batch_context->num_invalid_prefetch_faults = 0;
        batch_context->num_replays                 = 0;

        // 2) Record one fatal fault per uTLB to check if it shows up after the replay. This is used to handle the
        // case in which the uTLB is being cancelled from behind our backs by RM. See the comment in step 6.
        for (utlb_id = 0; utlb_id <= batch_context->max_utlb_id; ++utlb_id) {
            uvm_fault_utlb_info_t *utlb = &batch_context->utlbs[utlb_id];

            if (utlb->num_fatal_faults > 0) {
                NvU32 idx = find_fatal_fault_in_utlb(batch_context, utlb_id);
                UVM_ASSERT(idx < batch_context->num_cached_faults);

                utlb->prev_fatal_fault = batch_context->fault_cache[idx];
            }
            else {
                utlb->prev_fatal_fault.fault_address = (NvU64)-1;
            }
        }

        // 3) Flush fault buffer. After this call, all faults from any of the faulting uTLBs are before PUT. New
        // faults from other uTLBs can keep arriving. Therefore, in each iteration we just try to cancel faults
        // from uTLBs that contained fatal faults in the previous iterations and will cause the TLB to stop
        // generating new page faults after the following replay with type UVM_FAULT_REPLAY_TYPE_START_ACK_ALL
        status = fault_buffer_flush_locked(gpu,
                                           UVM_GPU_BUFFER_FLUSH_MODE_UPDATE_PUT,
                                           UVM_FAULT_REPLAY_TYPE_START_ACK_ALL,
                                           batch_context);
        if (status != NV_OK)
            break;

        // 4) Wait for replay to finish
        status = uvm_tracker_wait(&replayable_faults->replay_tracker);
        if (status != NV_OK)
            break;

        // 5) Fetch all faults from buffer
        batch_context->num_cached_faults = fetch_fault_buffer_entries(gpu, batch_context, FAULT_FETCH_MODE_ALL);
        ++batch_context->batch_id;

        // No more faults left, we are done
        if (batch_context->num_cached_faults == 0)
            break;

        // 6) Check what uTLBs are in lockdown mode and can be cancelled
        for (utlb_id = 0; utlb_id <= batch_context->max_utlb_id; ++utlb_id) {
            uvm_fault_utlb_info_t *utlb = &batch_context->utlbs[utlb_id];

            utlb->in_lockdown = false;
            utlb->cancelled   = false;

            if (utlb->prev_fatal_fault.fault_address != (NvU64)-1) {
                // If a previously-reported fault shows up again we can "safely" assume that the uTLB that contains it
                // is in lockdown mode and no new translations will show up before cancel. A fatal fault could only
                // be removed behind our backs by RM issuing a cancel, which only happens when RM is resetting the
                // engine. That means the instance pointer can't generate any new faults, so we won't have an ABA
                // problem where a new fault arrives with the same state.
                if (is_fatal_fault_in_buffer(batch_context, &utlb->prev_fatal_fault))
                    utlb->in_lockdown = true;
            }
        }

        // 7) Preprocess faults
        status = preprocess_fault_batch(gpu, batch_context);
        if (status == NV_WARN_MORE_PROCESSING_REQUIRED)
            continue;
        else if (status != NV_OK)
            break;

        // 8) Service all non-fatal faults and mark all non-serviceable faults as fatal
        status = service_fault_batch(gpu, FAULT_SERVICE_MODE_CANCEL, batch_context);
        if (status == NV_WARN_MORE_PROCESSING_REQUIRED)
            continue;

        UVM_ASSERT(batch_context->num_replays == 0);
        if (status == NV_ERR_NO_MEMORY)
            continue;
        else if (status != NV_OK)
            break;

        // No more fatal faults left, we are done
        if (batch_context->num_fatal_faults == 0)
            break;

        // 9) Search for uTLBs that contain fatal faults and meet the requirements to be cancelled
        try_to_cancel_utlbs(gpu, batch_context);
    }

    // 10) Re-enable prefetching
    if (gpu->fault_buffer_info.prefetch_faults_enabled)
        gpu->arch_hal->enable_prefetch_faults(gpu);

    if (status == NV_OK)
        status = push_replay_on_gpu(gpu, UVM_FAULT_REPLAY_TYPE_START, batch_context);

    tracker_status = uvm_tracker_wait(&batch_context->tracker);

    return status == NV_OK? tracker_status: status;
}

static NV_STATUS cancel_faults_precise(uvm_gpu_t *gpu, uvm_fault_service_batch_context_t *batch_context)
{
    UVM_ASSERT(batch_context->num_fatal_faults > 0);

    if (uvm_gpu_supports_fault_cancel_va(gpu)) {
        return cancel_faults_precise_va(gpu,
                                        batch_context,
                                        FAULT_CANCEL_MODE_FATAL,
                                        UvmEventFatalReasonInvalid);
    }


    return cancel_faults_precise_tlb(gpu, batch_context);
}

static void enable_disable_prefetch_faults(uvm_gpu_t *gpu, uvm_fault_service_batch_context_t *batch_context)
{
    if (!gpu->prefetch_fault_supported)
        return;

    // If more than 66% of faults are invalid prefetch accesses, disable prefetch faults for a while
    if (gpu->fault_buffer_info.prefetch_faults_enabled &&
        ((batch_context->num_invalid_prefetch_faults * 3 > gpu->fault_buffer_info.max_batch_size * 2 &&
          uvm_perf_reenable_prefetch_faults_lapse_msec > 0) ||
         (uvm_enable_builtin_tests && batch_context->num_invalid_prefetch_faults > 5))) {
        uvm_gpu_disable_prefetch_faults(gpu);
    }
    else if (!gpu->fault_buffer_info.prefetch_faults_enabled) {
        NvU64 lapse = NV_GETTIME() - gpu->fault_buffer_info.disable_prefetch_faults_timestamp;
        // Reenable prefetch faults after some time
        if (lapse > ((NvU64)uvm_perf_reenable_prefetch_faults_lapse_msec * (1000 * 1000)))
            uvm_gpu_enable_prefetch_faults(gpu);
    }
}

void uvm_gpu_service_replayable_faults(uvm_gpu_t *gpu)
{
    NvU32 num_replays = 0;
    NvU32 num_batches = 0;
    NvU32 num_throttled = 0;
    NV_STATUS status = NV_OK;
    uvm_replayable_fault_buffer_info_t *replayable_faults = &gpu->fault_buffer_info.replayable;
    uvm_fault_service_batch_context_t *batch_context = &replayable_faults->batch_service_context;

    UVM_ASSERT(uvm_gpu_supports_replayable_faults(gpu));

    uvm_tracker_init(&batch_context->tracker);

    // Process all faults in the buffer
    while (1) {
        if (num_throttled >= uvm_perf_fault_max_throttle_per_service ||
            num_batches >= uvm_perf_fault_max_batches_per_service) {
            break;
        }

        batch_context->num_fatal_faults            = 0;
        batch_context->num_serviced_faults         = 0;
        batch_context->num_throttled_faults        = 0;
        batch_context->num_invalid_prefetch_faults = 0;
        batch_context->num_duplicate_faults        = 0;
        batch_context->num_replays                 = 0;

        batch_context->num_cached_faults = fetch_fault_buffer_entries(gpu, batch_context, FAULT_FETCH_MODE_BATCH_READY);
        if (batch_context->num_cached_faults == 0)
            break;

        ++batch_context->batch_id;

        status = preprocess_fault_batch(gpu, batch_context);

        num_replays += batch_context->num_replays;

        if (status == NV_WARN_MORE_PROCESSING_REQUIRED)
            continue;
        else if (status != NV_OK)
            break;

        status = service_fault_batch(gpu, FAULT_SERVICE_MODE_REGULAR, batch_context);

        // We may have issued replays even if status != NV_OK if
        // UVM_PERF_FAULT_REPLAY_POLICY_BLOCK is being used or the fault buffer
        // was flushed
        num_replays += batch_context->num_replays;

        if (status == NV_WARN_MORE_PROCESSING_REQUIRED)
            continue;

        enable_disable_prefetch_faults(gpu, batch_context);

        if (status != NV_OK) {
            // Unconditionally cancel all faults to trigger RC. This will not provide precise
            // attribution, but this case handles global errors such as OOM or ECC where it's
            // not reasonable to guarantee precise attribution. We ignore the return value
            // of the cancel operation since this path is already returning an error code.
            cancel_fault_batch(gpu, batch_context, uvm_tools_status_to_fatal_fault_reason(status));
            break;
        }

        if (batch_context->num_fatal_faults > 0) {
            status = uvm_tracker_wait(&batch_context->tracker);
            if (status == NV_OK)
                status = cancel_faults_precise(gpu, batch_context);

            break;
        }

        if (replayable_faults->replay_policy == UVM_PERF_FAULT_REPLAY_POLICY_BATCH) {
            status = push_replay_on_gpu(gpu, UVM_FAULT_REPLAY_TYPE_START, batch_context);
            if (status != NV_OK)
                break;
            ++num_replays;
        }
        else if (replayable_faults->replay_policy == UVM_PERF_FAULT_REPLAY_POLICY_BATCH_FLUSH) {
            uvm_gpu_buffer_flush_mode_t flush_mode = UVM_GPU_BUFFER_FLUSH_MODE_CACHED_PUT;

            if (batch_context->num_duplicate_faults * 100 >
                batch_context->num_cached_faults * replayable_faults->replay_update_put_ratio) {
                flush_mode = UVM_GPU_BUFFER_FLUSH_MODE_UPDATE_PUT;
            }

            status = fault_buffer_flush_locked(gpu,
                                               flush_mode,
                                               UVM_FAULT_REPLAY_TYPE_START,
                                               batch_context);
            if (status != NV_OK)
                break;
            ++num_replays;
            status = uvm_tracker_wait(&replayable_faults->replay_tracker);
            if (status != NV_OK)
                break;
        }

        if (batch_context->num_throttled_faults > 0)
            ++num_throttled;

        ++num_batches;
    }

    if (status == NV_WARN_MORE_PROCESSING_REQUIRED)
        status = NV_OK;

    // Make sure that we issue at least one replay if no replay has been issued yet to avoid dropping faults that do
    // not show up in the buffer
    if ((status == NV_OK && replayable_faults->replay_policy == UVM_PERF_FAULT_REPLAY_POLICY_ONCE) ||
        num_replays == 0)
        status = push_replay_on_gpu(gpu, UVM_FAULT_REPLAY_TYPE_START, batch_context);

    uvm_tracker_deinit(&batch_context->tracker);

    if (status != NV_OK)
        UVM_DBG_PRINT("Error servicing replayable faults on GPU: %s\n", gpu->name);
}

void uvm_gpu_enable_prefetch_faults(uvm_gpu_t *gpu)
{
    UVM_ASSERT(gpu->isr.replayable_faults.handling);
    UVM_ASSERT(gpu->prefetch_fault_supported);

    if (!gpu->fault_buffer_info.prefetch_faults_enabled) {
        gpu->arch_hal->enable_prefetch_faults(gpu);
        gpu->fault_buffer_info.prefetch_faults_enabled = true;
    }
}

void uvm_gpu_disable_prefetch_faults(uvm_gpu_t *gpu)
{
    UVM_ASSERT(gpu->isr.replayable_faults.handling);
    UVM_ASSERT(gpu->prefetch_fault_supported);

    if (gpu->fault_buffer_info.prefetch_faults_enabled) {
        gpu->arch_hal->disable_prefetch_faults(gpu);
        gpu->fault_buffer_info.prefetch_faults_enabled = false;
        gpu->fault_buffer_info.disable_prefetch_faults_timestamp = NV_GETTIME();
    }
}

const char *uvm_perf_fault_replay_policy_string(uvm_perf_fault_replay_policy_t replay_policy)
{
    BUILD_BUG_ON(UVM_PERF_FAULT_REPLAY_POLICY_MAX != 4);

    switch (replay_policy) {
        UVM_ENUM_STRING_CASE(UVM_PERF_FAULT_REPLAY_POLICY_BLOCK);
        UVM_ENUM_STRING_CASE(UVM_PERF_FAULT_REPLAY_POLICY_BATCH);
        UVM_ENUM_STRING_CASE(UVM_PERF_FAULT_REPLAY_POLICY_BATCH_FLUSH);
        UVM_ENUM_STRING_CASE(UVM_PERF_FAULT_REPLAY_POLICY_ONCE);
        UVM_ENUM_STRING_DEFAULT();
    }
}

NV_STATUS uvm8_test_get_prefetch_faults_reenable_lapse(UVM_TEST_GET_PREFETCH_FAULTS_REENABLE_LAPSE_PARAMS *params,
                                                       struct file *filp)
{
    params->reenable_lapse = uvm_perf_reenable_prefetch_faults_lapse_msec;

    return NV_OK;
}

NV_STATUS uvm8_test_set_prefetch_faults_reenable_lapse(UVM_TEST_SET_PREFETCH_FAULTS_REENABLE_LAPSE_PARAMS *params,
                                                       struct file *filp)
{
    uvm_perf_reenable_prefetch_faults_lapse_msec = params->reenable_lapse;

    return NV_OK;
}
