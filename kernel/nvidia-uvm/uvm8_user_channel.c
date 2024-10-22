/*******************************************************************************
    Copyright (c) 2016 NVIDIA Corporation

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

#include "uvm_common.h"
#include "uvm_linux.h"
#include "uvm8_va_space.h"
#include "uvm8_va_range.h"
#include "uvm8_lock.h"
#include "uvm8_hal_types.h"
#include "uvm8_mmu.h"
#include "uvm8_user_channel.h"
#include "uvm8_kvmalloc.h"
#include "uvm8_api.h"
#include "uvm8_gpu.h"
#include "uvm8_tracker.h"
#include "uvm8_map_external.h"
#include "uvm8_init.h"
#include "nv_uvm_interface.h"

#include <linux/sort.h>

// Sort channel resources from highest to lowest alignments
static int resource_align_high_cmp(const void *a, const void *b)
{
    const UvmGpuChannelResourceInfo *resource_a = a;
    const UvmGpuChannelResourceInfo *resource_b = b;

    if (resource_a->alignment > resource_b->alignment)
        return -1;
    if (resource_a->alignment < resource_b->alignment)
        return 1;
    return 0;
}

static NV_STATUS get_rm_channel_resources(uvm_user_channel_t *user_channel)
{
    UvmGpuChannelResourceInfo *resources = NULL;
    uvm_gpu_va_space_t *gpu_va_space = user_channel->gpu_va_space;
    NV_STATUS status;
    NvU32 i, num_resources = user_channel->num_resources;

    // Note that num_resources may be 0, in which case resources will be
    // ZERO_SIZE_PTR. This is preferred to setting resources to NULL, since we
    // use NULL to indicate error conditions in various cleanup paths.

    resources = uvm_kvmalloc_zero(num_resources * sizeof(resources[0]));
    if (!resources)
        return NV_ERR_NO_MEMORY;

    status = uvm_rm_locked_call(nvUvmInterfaceRetainChannelResources(user_channel->rm_retained_channel, resources));
    if (status != NV_OK) {
        UVM_DBG_PRINT("Failed to get %u channel resources for {0x%x, 0x%x}: %s, GPU: %s\n",
                      num_resources,
                      user_channel->user_rm_channel.user_client, user_channel->user_rm_channel.user_object,
                      nvstatusToString(status), gpu_va_space->gpu->name);
        goto error;
    }

    // Info fix-up
    for (i = 0; i < num_resources; i++) {
        UvmGpuMemoryInfo *mem_info = &resources[i].resourceInfo;

        // RM can return alignments of 0, so make sure it's at least page size
        // before we start using it.
        resources[i].alignment = max(resources[i].alignment, (NvU64)mem_info->pageSize);

        // RM tracks logical size, so the size might not be a multiple of page
        // size. This would cause problems in our tracking.
        mem_info->size = UVM_ALIGN_UP(mem_info->size, mem_info->pageSize);
    }

    // Sort the resources from highest to lowest alignment. This should
    // guarantee that they fit in the provided VA space, regardless of the order
    // used to calculate the total size.
    sort(resources, num_resources, sizeof(resources[0]), resource_align_high_cmp, NULL);

    user_channel->resources = resources;
    return NV_OK;

error:
    uvm_kvfree(resources);
    return status;
}

static NV_STATUS uvm_user_channel_create(uvm_va_space_t *va_space,
                                         NvProcessorUuid *uuid,
                                         uvm_rm_user_object_t *user_rm_channel,
                                         uvm_user_channel_t **out_channel,
                                         NvU64 base,
                                         NvU64 length)
{
    UvmGpuChannelInstanceInfo channel_info;
    uvm_user_channel_t *user_channel = NULL;
    NV_STATUS status = NV_OK;
    NvU32 rm_client = user_rm_channel->user_client;
    NvU32 rm_channel = user_rm_channel->user_object;
    uvm_gpu_t *gpu;
    void *rm_retained_channel = NULL;

    *out_channel = NULL;

    gpu = uvm_va_space_get_gpu_by_uuid_with_gpu_va_space(va_space, uuid);
    if (!gpu)
        return NV_ERR_INVALID_DEVICE;

    user_channel = uvm_kvmalloc_zero(sizeof(*user_channel));
    if (!user_channel)
        return NV_ERR_NO_MEMORY;

    user_channel->gpu = gpu;
    memcpy(&user_channel->user_rm_channel, user_rm_channel, sizeof(*user_rm_channel));
    INIT_LIST_HEAD(&user_channel->list_node);
    nv_kref_init(&user_channel->kref);

    user_channel->gpu_va_space = uvm_gpu_va_space_get(va_space, gpu);
    UVM_ASSERT(user_channel->gpu_va_space);

    // Convert the user channel handles into a handle safe for kernel use. This
    // also takes a ref-count on the instance pointer, though not on other
    // channel state.
    //
    // TODO: Bug 1624521: This interface needs to use rm_control_fd to do
    //       validation.
    memset(&channel_info, 0, sizeof(channel_info));
    (void)user_channel->user_rm_channel.rm_control_fd;
    status = uvm_rm_locked_call(nvUvmInterfaceRetainChannel(user_channel->gpu_va_space->duped_gpu_va_space,
                                                            rm_client,
                                                            rm_channel,
                                                            &rm_retained_channel,
                                                            &channel_info));
    if (status != NV_OK) {
        UVM_DBG_PRINT("Failed to retain channel {0x%x, 0x%x}: %s, GPU: %s\n",
                      rm_client, rm_channel, nvstatusToString(status), gpu->name);
        goto error;
    }

    if (channel_info.sysmem)
        user_channel->instance_ptr.aperture = UVM_APERTURE_SYS;
    else
        user_channel->instance_ptr.aperture = UVM_APERTURE_VID;

    user_channel->instance_ptr.address = channel_info.base;
    user_channel->rm_retained_channel  = rm_retained_channel;
    user_channel->hw_channel_id        = channel_info.chId;
    user_channel->num_resources        = channel_info.resourceCount;
    user_channel->engine_type          = channel_info.channelEngineType;

    user_channel->in_subctx            = channel_info.bInSubctx == NV_TRUE;
    user_channel->subctx_id            = channel_info.subctxId;
    user_channel->in_tsg               = channel_info.bTsgChannel == NV_TRUE;
    user_channel->tsg_id               = channel_info.tsgId;

    // CE does not support subcontexts
    if (user_channel->in_subctx)
        UVM_ASSERT(user_channel->engine_type != UVM_GPU_CHANNEL_ENGINE_TYPE_CE);


    // If num_resources == 0, as can happen with CE channels, we ignore base and
    // length.
    if (user_channel->num_resources > 0 && uvm_api_range_invalid(base, length)) {
        status = NV_ERR_INVALID_ADDRESS;
        goto error;
    }

    status = get_rm_channel_resources(user_channel);
    if (status != NV_OK)
        goto error;

    *out_channel = user_channel;
    return NV_OK;

error:
    // uvm_user_channel_destroy_detached expects this
    user_channel->gpu_va_space = NULL;
    uvm_user_channel_destroy_detached(user_channel);
    return status;
}

static uvm_user_channel_t *find_user_channel(uvm_va_space_t *va_space, uvm_rm_user_object_t *user_rm_channel)
{
    uvm_user_channel_t *user_channel;
    uvm_gpu_va_space_t *gpu_va_space;

    // This is a pretty naive search but it's unlikely to show up in a perf-
    // critical path. We could optimize it in the future with a table lookup
    // instead, if it becomes a problem.
    for_each_gpu_va_space(gpu_va_space, va_space) {
        list_for_each_entry(user_channel, &gpu_va_space->registered_channels, list_node) {
            if (user_channel->user_rm_channel.user_client == user_rm_channel->user_client &&
                user_channel->user_rm_channel.user_object == user_rm_channel->user_object)
                return user_channel;
        }
    }

    return NULL;
}

static uvm_va_range_t *find_local_range(uvm_gpu_va_space_t *gpu_va_space, NvP64 rm_descriptor)
{
    uvm_va_range_t *range;
    list_for_each_entry(range, &gpu_va_space->local_channel_ranges, channel.local_node) {
        UVM_ASSERT(range->type == UVM_VA_RANGE_TYPE_CHANNEL);
        UVM_ASSERT(range->channel.ref_count > 0);
        UVM_ASSERT(range->channel.is_local);
        if (range->channel.rm_descriptor == rm_descriptor)
            return range;
    }
    return NULL;
}

// Allocate a VA range for the given channel resource, but don't map it. The VA
// used is the first VA in the range [base, end] which has alignment appropriate
// to the given resource. Note that base is an in/out parameter: this function
// updates base if it actually allocates a range, which it may not for local
// ranges.
static NV_STATUS create_va_range(uvm_user_channel_t *user_channel, NvU64 *base, NvU64 end, NvU32 resource_index)
{
    uvm_gpu_va_space_t *gpu_va_space = user_channel->gpu_va_space;
    UvmGpuChannelResourceInfo *resource = &user_channel->resources[resource_index];
    UvmGpuMemoryInfo *mem_info = &resource->resourceInfo;
    uvm_va_range_t *range = NULL;
    NvU64 curr_base, curr_end;
    uvm_aperture_t aperture;
    NV_STATUS status;

    uvm_assert_rwsem_locked_write(&gpu_va_space->va_space->lock);

    if (mem_info->sysmem)
        aperture = UVM_APERTURE_SYS;
    else
        aperture = UVM_APERTURE_VID;

    // If the resource is local, see if we've already mapped it
    if (!resource->globalResource) {
        range = find_local_range(gpu_va_space, resource->resourceDescriptor);
        if (range) {
            // We've already mapped this resource, so just bump the ref count
            UVM_ASSERT(IS_ALIGNED(range->node.start, resource->alignment));
            UVM_ASSERT(uvm_va_range_size(range) >= mem_info->size);
            UVM_ASSERT(range->channel.aperture == aperture);
            UVM_ASSERT(range->channel.is_local);

            ++range->channel.ref_count;
            user_channel->va_ranges[resource_index] = range;
            return NV_OK;
        }
    }

    // Dumb allocator which just keeps advancing the region
    curr_base = UVM_ALIGN_UP(*base, resource->alignment);
    curr_end = curr_base + mem_info->size - 1;

    // Check for exceeding end and for arithmetic overflow
    if (curr_base < *base || curr_base > end ||
        curr_end  < *base || curr_end  > end ||
        curr_base > curr_end) {
        UVM_DBG_PRINT("Range exceeded: allowed [0x%llx, 0x%llx], align: 0x%llx size: 0x%llx\n",
                      *base, end, resource->alignment, mem_info->size, curr_base, curr_end);
        return NV_ERR_INVALID_ADDRESS;
    }

    // TODO: Bug 1734586: RM computes alignments incorrectly

    status = uvm_va_range_create_channel(gpu_va_space->va_space, curr_base, curr_end, &range);
    if (status != NV_OK)
        goto error;

    range->channel.gpu_va_space = gpu_va_space;
    range->channel.aperture = aperture;
    range->channel.rm_descriptor = resource->resourceDescriptor;
    range->channel.is_local = !resource->globalResource;
    if (range->channel.is_local)
        list_add(&range->channel.local_node, &gpu_va_space->local_channel_ranges);
    range->channel.ref_count = 1;

    *base = curr_end + 1;
    user_channel->va_ranges[resource_index] = range;
    return NV_OK;

error:
    if (range) {
        range->channel.ref_count = 0; // Destroy assumes this
        uvm_va_range_destroy(range, NULL);
    }
    return status;
}

static void destroy_va_ranges(uvm_user_channel_t *user_channel)
{
    uvm_va_range_t *resource_range;
    size_t i;

    if (!user_channel || !user_channel->va_ranges)
        return;

    for (i = 0; i < user_channel->num_resources; i++) {
        resource_range = user_channel->va_ranges[i];
        if (!resource_range)
            continue;

        UVM_ASSERT(resource_range->type == UVM_VA_RANGE_TYPE_CHANNEL);
        UVM_ASSERT(resource_range->channel.rm_descriptor == user_channel->resources[i].resourceDescriptor);

        // Drop the ref count on each each range
        if (resource_range->channel.is_local)
            UVM_ASSERT(resource_range->channel.ref_count > 0);
        else
            UVM_ASSERT(resource_range->channel.ref_count == 1);

        --resource_range->channel.ref_count;
        if (resource_range->channel.ref_count == 0)
            uvm_va_range_destroy(resource_range, NULL);
    }

    uvm_kvfree(user_channel->va_ranges);
    user_channel->va_ranges = NULL;
}

// Channels need virtual allocations to operate, but we don't know about them.
// This function carves out a chunk within [base, end] for each allocation for
// later mapping.
static NV_STATUS create_va_ranges(uvm_user_channel_t *user_channel, NvU64 base, NvU64 end)
{
    NvU64 running_base;
    NvU32 i;
    NV_STATUS status;

    user_channel->va_ranges = uvm_kvmalloc_zero(user_channel->num_resources * sizeof(user_channel->va_ranges[0]));
    if (!user_channel->va_ranges)
        return NV_ERR_NO_MEMORY;

    running_base = base;
    for (i = 0; i < user_channel->num_resources; i++) {
        // Check if we're out of space
        if (running_base > end) {
            status = NV_ERR_INVALID_ADDRESS;
            goto error;
        }

        status = create_va_range(user_channel, &running_base, end, i);
        if (status != NV_OK)
            goto error;
    }

    return NV_OK;

error:
    destroy_va_ranges(user_channel);
    return status;
}

// "Binding" the resouces tells RM the virtual address of each allocation so it
// can in turn tell the HW where they are.
static NV_STATUS bind_channel_resources(uvm_user_channel_t *user_channel)
{
    UvmGpuChannelResourceBindParams *resource_va_list = NULL;
    uvm_va_range_t *resource_range;
    NV_STATUS status = NV_OK;
    NvU32 i;

    resource_va_list = uvm_kvmalloc_zero(user_channel->num_resources * sizeof(resource_va_list[0]));
    if (!resource_va_list) {
        status = NV_ERR_NO_MEMORY;
        goto out;
    }

    for (i = 0; i < user_channel->num_resources; i++) {
        resource_range = user_channel->va_ranges[i];
        UVM_ASSERT(resource_range);
        UVM_ASSERT(resource_range->type == UVM_VA_RANGE_TYPE_CHANNEL);
        UVM_ASSERT(resource_range->channel.rm_descriptor == user_channel->resources[i].resourceDescriptor);

        resource_va_list[i].resourceDescriptor = resource_range->channel.rm_descriptor;
        resource_va_list[i].resourceVa         = resource_range->node.start;

        // TODO: Bug 1732494: RM should be able to figure this out on its own
        resource_va_list[i].globalResource     = !resource_range->channel.is_local;
    }

    status = uvm_rm_locked_call(nvUvmInterfaceBindChannelResources(user_channel->rm_retained_channel,
                                                                   resource_va_list));
    if (status != NV_OK) {
        UVM_DBG_PRINT("Failed to bind channel resources for {0x%x, 0x%x}: %s, GPU: %s\n",
                      user_channel->user_rm_channel.user_client,
                      user_channel->user_rm_channel.user_object,
                      nvstatusToString(status),
                      user_channel->gpu_va_space->gpu->name);
        goto out;
    }

    atomic_set(&user_channel->is_bound, 1);

out:
    uvm_kvfree(resource_va_list);
    return status;
}

// Map the already-created VA ranges by getting the PTEs for each allocation
// from RM. The caller is responsible for destroying the VA ranges if the
// mappings fail.
static NV_STATUS uvm_user_channel_map_resources(uvm_user_channel_t *user_channel)
{
    uvm_tracker_t tracker = UVM_TRACKER_INIT();
    NvU32 i;
    NV_STATUS status = NV_OK, tracker_status;
    uvm_map_rm_params_t map_rm_params;
    UvmGpuMemoryInfo *mem_info;
    uvm_va_range_t *range;

    for (i = 0; i < user_channel->num_resources; i++) {
        range = user_channel->va_ranges[i];

        // Skip already-mapped VA ranges. Note that the ref count might not be
        // 1 even if the range is unmapped, because a thread which fails to map
        // will drop and re-take the VA space lock in uvm_register_channel
        // leaving a local (shared) VA range in the list unmapped. We could
        // attach to it during that window, so we'll do the mapping instead.
        if (range->channel.pt_range_vec.ranges) {
            UVM_ASSERT(range->channel.is_local);
            UVM_ASSERT(range->channel.ref_count >= 1);
            continue;
        }

        mem_info = &user_channel->resources[i].resourceInfo;

        // Perform the mapping. Some of these need to be privileged and/or read-
        // only, so use default types to let RM set those fields.
        map_rm_params.map_offset = 0;
        map_rm_params.mapping_type = UvmGpuMappingTypeDefault;
        map_rm_params.caching_type = UvmGpuCachingTypeDefault;
        map_rm_params.tracker = &tracker;
        status = uvm_va_range_map_rm_allocation(range, user_channel->gpu, mem_info, &map_rm_params);
        if (status != NV_OK) {
            // We can't destroy the VA ranges here since we only have the VA
            // space lock in read mode, so let the caller handle it.
            break;
        }
    }

    // Always wait for the tracker even on error so we don't have any pending
    // map operations happening during the subsequent destroy.
    tracker_status = uvm_tracker_wait_deinit(&tracker);
    return status == NV_OK ? tracker_status : status;
}

static NV_STATUS uvm_register_channel_under_write(uvm_user_channel_t *user_channel, NvU64 base, NvU64 length)
{
    uvm_gpu_va_space_t *gpu_va_space = user_channel->gpu_va_space;
    uvm_va_space_t *va_space = gpu_va_space->va_space;
    NV_STATUS status;

    uvm_assert_rwsem_locked_write(&va_space->lock);

    // Currently all user channels are stopped when any process using the VA
    // space is torn down, unless it passed UVM_INIT_FLAGS_DISABLE_TEARDOWN_ON_PROCESS_EXIT,
    // but the VA space could be shared and some other process could still try
    // registering a channel. Just disallow it for now.
    if (atomic_read(&va_space->user_channels_stopped))
        return NV_ERR_INVALID_STATE;

    // The GPU VA space is on its way out, so act as if it's already been
    // unregistered. See gpu_va_space_stop_all_channels.
    if (atomic_read(&gpu_va_space->disallow_new_channels))
        return NV_ERR_INVALID_DEVICE;

    // Verify that this handle pair wasn't already registered. This is just to
    // keep our internal state consistent, since a match doesn't mean that the
    // handles still represent the same channel. See the comment in
    // uvm_user_channel.h.
    if (find_user_channel(va_space, &user_channel->user_rm_channel))
        return NV_ERR_INVALID_CHANNEL;

    // TODO: Bug 1757136: Check that this handle pair also wasn't already
    //       registered on other GPUs in the GPU's SLI group.

    if (user_channel->num_resources > 0) {
        NvU64 end = base + length - 1;

        if (end >= gpu_va_space->gpu->max_channel_va)
            return NV_ERR_OUT_OF_RANGE;

        if (!uvm_va_space_range_empty(va_space, base, end))
            return NV_ERR_UVM_ADDRESS_IN_USE;

        // Create and insert the VA ranges, but don't map them yet since we can't
        // call RM until we downgrade the lock to read mode.
        status = create_va_ranges(user_channel, base, end);
        if (status != NV_OK)
            return status;
    }

    list_add(&user_channel->list_node, &gpu_va_space->registered_channels);

    return NV_OK;
}

static NV_STATUS uvm_register_channel(uvm_va_space_t *va_space,
                                      NvProcessorUuid *uuid,
                                      uvm_rm_user_object_t *user_rm_channel,
                                      NvU64 base,
                                      NvU64 length)
{
    NV_STATUS status;
    uvm_gpu_t *gpu;
    uvm_gpu_va_space_t *gpu_va_space;
    uvm_user_channel_t *user_channel = NULL;
    LIST_HEAD(deferred_free_list);

    uvm_va_space_down_read_rm(va_space);

    status = uvm_user_channel_create(va_space, uuid, user_rm_channel, &user_channel, base, length);
    if (status != NV_OK) {
        uvm_va_space_up_read_rm(va_space);
        return status;
    }

    // Retain the GPU VA space so our channel's gpu_va_space pointer remains
    // valid after we drop the lock.
    uvm_gpu_va_space_retain(user_channel->gpu_va_space);

    // Retain the GPU since retaining the gpu_va_space doesn't prevent it from
    // going away after we drop the lock.
    gpu = user_channel->gpu;
    uvm_gpu_retain(gpu);

    uvm_va_space_up_read_rm(va_space);

    // We have the RM objects now so we know what the VA range layout should be.
    // Re-take the VA space lock in write mode to create and insert them.
    uvm_va_space_down_write(va_space);

    // We dropped the lock so we have to re-verify that this gpu_va_space is
    // still valid. If so, then the GPU is also still registered under the VA
    // space.
    gpu_va_space = user_channel->gpu_va_space;
    if (!gpu_va_space->va_space) {
        status = NV_ERR_INVALID_DEVICE;
        user_channel->gpu_va_space = NULL;

        // uvm_user_channel_detach expects a valid VA space, so we can't call it
        // here. Just add this channel to the list directly so it gets
        // destroyed in the error handler.
        uvm_deferred_free_object_add(&deferred_free_list,
                                     &user_channel->deferred_free,
                                     UVM_DEFERRED_FREE_OBJECT_TYPE_CHANNEL);
    }

    uvm_gpu_va_space_release(gpu_va_space);
    if (status != NV_OK)
        goto error_under_write;

    UVM_ASSERT(gpu == uvm_va_space_get_gpu_by_uuid_with_gpu_va_space(va_space, uuid));
    UVM_ASSERT(gpu_va_space == uvm_gpu_va_space_get(va_space, gpu));

    // Performs verification checks and inserts the channel's VA ranges into the
    // VA space, but doesn't map them.
    status = uvm_register_channel_under_write(user_channel, base, length);
    if (status != NV_OK)
        goto error_under_write;

    // The subsequent mappings will need to call into RM, which means we must
    // downgrade the VA space lock to read mode. Although we're in read mode no
    // other threads could modify this channel or its VA ranges: other threads
    // which call channel register will first take the VA space lock in write
    // mode above, and threads which call channel unregister or GPU VA space
    // unregister unmap operate entirely with the lock in write mode.
    uvm_va_space_downgrade_write_rm(va_space);

    status = uvm_user_channel_map_resources(user_channel);
    if (status != NV_OK)
        goto error_under_read;

    // Tell the GPU page fault handler about this instance_ptr -> user_channel
    // mapping
    status = uvm_gpu_add_user_channel(gpu, user_channel);
    if (status != NV_OK)
        goto error_under_read;

    // Notify that the instance_ptr has been already registered so that we need
    // to remove it in case of an error
    user_channel->is_instance_ptr_registered = true;

    status = bind_channel_resources(user_channel);
    if (status != NV_OK)
        goto error_under_read;

    uvm_va_space_up_read_rm(va_space);
    uvm_gpu_release(gpu);
    return NV_OK;

error_under_write:
    if (user_channel->gpu_va_space)
        uvm_user_channel_detach(user_channel, &deferred_free_list);
    uvm_va_space_up_write(va_space);
    uvm_deferred_free_object_list(&deferred_free_list);
    uvm_gpu_release(gpu);
    return status;

error_under_read:
    // We have to destroy the VA ranges, which means we need to re-take the VA
    // space lock in write mode. That in turn means we must retain the channel
    // so its memory doesn't get freed from under us (though it could get
    // unregistered). Note that we also still have the GPU retained.
    uvm_user_channel_retain(user_channel);
    uvm_va_space_up_read_rm(va_space);

    uvm_va_space_down_write(va_space);

    // If a new channel was registered which uses our unmapped local (shared) VA
    // ranges, that new channel is responsible for mapping them if we haven't
    // gotten there yet. See uvm_user_channel_map_resources. It will take a
    // reference on them anyway so they won't go away.

    // If the channel was unregistered by another thread (explicitly or via GPU
    // VA space unregister), the thread which did the unregister is responsible
    // for destroying the channel.
    if (user_channel->gpu_va_space) {
        uvm_user_channel_detach(user_channel, &deferred_free_list);
        uvm_va_space_up_write(va_space);
        uvm_deferred_free_object_list(&deferred_free_list);
    }
    else {
        uvm_va_space_up_write(va_space);
    }

    uvm_user_channel_release(user_channel);
    uvm_gpu_release(gpu);
    return status;
}

NV_STATUS uvm_api_register_channel(UVM_REGISTER_CHANNEL_PARAMS *params, struct file *filp)
{
    uvm_va_space_t *va_space = uvm_va_space_get(filp);
    uvm_rm_user_object_t user_rm_channel =
    {
        .rm_control_fd = params->rmCtrlFd,
        .user_client   = params->hClient,
        .user_object   = params->hChannel
    };
    return uvm_register_channel(va_space, &params->gpuUuid, &user_rm_channel, params->base, params->length);
}

static void free_user_channel(nv_kref_t *nv_kref)
{
    uvm_user_channel_t *user_channel = container_of(nv_kref, uvm_user_channel_t, kref);
    UVM_ASSERT(!user_channel->gpu_va_space);
    UVM_ASSERT(!user_channel->va_ranges);
    UVM_ASSERT(!atomic_read(&user_channel->is_bound));
    uvm_kvfree(user_channel);
}

void uvm_user_channel_release(uvm_user_channel_t *user_channel)
{
    if (user_channel)
        nv_kref_put(&user_channel->kref, free_user_channel);
}

void uvm_user_channel_stop(uvm_user_channel_t *user_channel)
{
    uvm_va_space_t *va_space = user_channel->gpu_va_space->va_space;

    if (!user_channel->rm_retained_channel)
        return;

    // Skip if this channel was never bound, or if it's already been stopped.
    // Note that since we only hold the VA space lock in read mode here, two
    // threads could race and both call nvUvmInterfaceStopChannel concurrently.
    // RM handles that with internal locking, so it's not a problem.
    if (!atomic_read(&user_channel->is_bound))
        return;

    // TODO: Bug 1799173: Normal lock tracking should handle this assert once
    //       all RM calls have been moved out from under the VA space lock in
    //       write mode.
    uvm_assert_rwsem_locked_read(&va_space->lock);

    // TODO: Bug 1737765. This doesn't stop the user from putting the
    //       channel back on the runlist, which could put stale instance
    //       pointers back in the fault buffer.
    uvm_rm_locked_call_void(nvUvmInterfaceStopChannel(user_channel->rm_retained_channel,
                                                      va_space->user_channel_stops_are_immediate));

    // Multiple threads could perform this set concurrently, but is_bound never
    // transitions back to 1 after being set to 0 so that's not a problem.
    atomic_set(&user_channel->is_bound, 0);
}

void uvm_user_channel_detach(uvm_user_channel_t *user_channel, struct list_head *deferred_free_list)
{
    uvm_va_space_t *va_space;

    if (!user_channel)
        return;

    UVM_ASSERT(user_channel->gpu_va_space);
    va_space = user_channel->gpu_va_space->va_space;
    UVM_ASSERT(va_space);
    uvm_assert_rwsem_locked_write(&va_space->lock);

    // The caller is required to have already stopped the channel. We can't do
    // it here since we're holding the VA space lock in write mode.
    UVM_ASSERT(!atomic_read(&user_channel->is_bound));

    if (user_channel->is_instance_ptr_registered) {
        // Prevent the bottom half from servicing faults on this channel. Note
        // that this only prevents new faults from being serviced. It doesn't
        // flush out faults currently being serviced, nor prior faults still
        // pending in the fault buffer. Those are handled separately.
        uvm_gpu_remove_user_channel(user_channel->gpu_va_space->gpu, user_channel);

        // We can't release the channel back to RM here because leftover state
        // for this channel (such as the instance pointer) could still be in the
        // GPU fault buffer, so we need to prevent that state from being
        // reallocated until we can flush the buffer. Flushing the buffer means
        // taking the GPU isr_lock, so the caller is required to do that.
    }

    list_del(&user_channel->list_node);

    uvm_deferred_free_object_add(deferred_free_list,
                                 &user_channel->deferred_free,
                                 UVM_DEFERRED_FREE_OBJECT_TYPE_CHANNEL);

    destroy_va_ranges(user_channel);

    user_channel->gpu_va_space = NULL;
}

void uvm_user_channel_destroy_detached(uvm_user_channel_t *user_channel)
{
    NvP64 desc;
    NvU32 i;

    // Check that this channel was already detached
    UVM_ASSERT(user_channel->gpu_va_space == NULL);

    if (user_channel->resources) {
        UVM_ASSERT(!user_channel->va_ranges);
        for (i = 0; i < user_channel->num_resources; i++) {
            desc = user_channel->resources[i].resourceDescriptor;
            uvm_rm_locked_call_void(nvUvmInterfaceReleaseChannelResources(&desc, 1));
        }
        uvm_kvfree(user_channel->resources);
    }

    if (user_channel->rm_retained_channel)
        uvm_rm_locked_call_void(nvUvmInterfaceReleaseChannel(user_channel->rm_retained_channel));

    uvm_user_channel_release(user_channel);
}

static NV_STATUS uvm_unregister_channel(uvm_va_space_t *va_space, uvm_rm_user_object_t *user_rm_channel)
{
    uvm_gpu_t *gpu = NULL;
    uvm_user_channel_t *user_channel = NULL;
    NV_STATUS status = NV_OK;
    LIST_HEAD(deferred_free_list);

    // Despite taking the VA space lock in read mode, since this also takes the
    // serialize_writers_lock it also flushes out threads which may be about to
    // bind this channel. Without that we might stop the channel first, then the
    // other thread could come in and re-bind the channel.
    uvm_va_space_down_read_rm(va_space);

    // Tell RM to kill the channel before we start unmapping its allocations.
    // This is to prevent spurious MMU faults during teardown.
    user_channel = find_user_channel(va_space, user_rm_channel);
    if (user_channel) {
        uvm_user_channel_retain(user_channel);
        uvm_user_channel_stop(user_channel);
    }

    uvm_va_space_up_read_rm(va_space);

    if (!user_channel)
        return NV_ERR_INVALID_CHANNEL;

    // Re-take the lock in write mode to detach the channel
    uvm_va_space_down_write(va_space);

    // We dropped the lock so we have to re-verify that someone else didn't come
    // in and detach us.
    if (user_channel->gpu_va_space) {
        gpu = user_channel->gpu_va_space->gpu;
        uvm_user_channel_detach(user_channel, &deferred_free_list);
        uvm_gpu_retain(gpu);
    }
    else {
        status = NV_ERR_INVALID_CHANNEL;
    }

    uvm_va_space_up_write(va_space);

    if (status == NV_OK) {
        uvm_deferred_free_object_list(&deferred_free_list);
        uvm_gpu_release(gpu);
    }

    uvm_user_channel_release(user_channel);

    return status;
}

NV_STATUS uvm_api_unregister_channel(UVM_UNREGISTER_CHANNEL_PARAMS *params, struct file *filp)
{
    uvm_va_space_t *va_space = uvm_va_space_get(filp);
    uvm_rm_user_object_t user_rm_channel =
    {
        .rm_control_fd = -1, // Not needed for a UVM-internal handle lookup
        .user_client   = params->hClient,
        .user_object   = params->hChannel
    };
    return uvm_unregister_channel(va_space, &user_rm_channel);
}

static NV_STATUS uvm8_test_check_channel_va_space_get_info(uvm_va_space_t *va_space,
                                                           UVM_TEST_CHECK_CHANNEL_VA_SPACE_PARAMS *params,
                                                           UvmGpuChannelInstanceInfo *channel_info)
{
    uvm_gpu_t *gpu;
    uvm_gpu_va_space_t *gpu_va_space;
    void *rm_retained_channel;
    NV_STATUS status;

    uvm_va_space_down_read_rm(va_space);

    gpu = uvm_va_space_get_gpu_by_uuid_with_gpu_va_space(va_space, &params->gpu_uuid);
    if (!gpu) {
        status = NV_ERR_INVALID_DEVICE;
        goto out;
    }

    gpu_va_space = uvm_gpu_va_space_get(va_space, gpu);
    UVM_ASSERT(gpu_va_space);

    // Look up the instance pointer
    //
    // TODO: Bug 1624521: This interface needs to use rmCtrlFd to do validation
    memset(channel_info, 0, sizeof(*channel_info));
    status = uvm_rm_locked_call(nvUvmInterfaceRetainChannel(gpu_va_space->duped_gpu_va_space,
                                                            params->client,
                                                            params->channel,
                                                            &rm_retained_channel,
                                                            channel_info));
    if (status != NV_OK)
        goto out;

    uvm_rm_locked_call_void(nvUvmInterfaceReleaseChannel(rm_retained_channel));

out:
    uvm_va_space_up_read_rm(va_space);
    return status;
}

NV_STATUS uvm8_test_check_channel_va_space(UVM_TEST_CHECK_CHANNEL_VA_SPACE_PARAMS *params, struct file *filp)
{
    struct file *va_space_filp;
    uvm_va_space_t *va_space = NULL;
    uvm_va_space_t *channel_va_space;
    uvm_gpu_t *gpu;
    uvm_fault_buffer_entry_t fault_entry;
    UvmGpuChannelInstanceInfo channel_info;
    NV_STATUS status;

    memset(&fault_entry, 0, sizeof(fault_entry));

    // The channel is owned by this file, so we have to query it using this
    // file's VA space.
    status = uvm8_test_check_channel_va_space_get_info(uvm_va_space_get(filp), params, &channel_info);
    if (status != NV_OK)
        return status;

    // We need to do the lookup using the input file's VA space
    va_space_filp = fget(params->va_space_fd);
    if (!uvm_file_is_nvidia_uvm(va_space_filp)) {
        status = NV_ERR_INVALID_ARGUMENT;
        goto out;
    }

    va_space = uvm_va_space_get(va_space_filp);
    uvm_va_space_down_read(va_space);

    gpu = uvm_va_space_get_gpu_by_uuid(va_space, &params->gpu_uuid);
    if (!gpu || !uvm_processor_mask_test(&va_space->faultable_processors, gpu->id)) {
        status = NV_ERR_INVALID_DEVICE;
        goto out;
    }

    // Craft enough of the fault entry to do a VA space translation
    fault_entry.fault_type = UVM_FAULT_TYPE_INVALID_PTE;

    if (channel_info.sysmem)
        fault_entry.instance_ptr.aperture = UVM_APERTURE_SYS;
    else
        fault_entry.instance_ptr.aperture = UVM_APERTURE_VID;
    fault_entry.instance_ptr.address = channel_info.base;

    if (channel_info.channelEngineType == UVM_GPU_CHANNEL_ENGINE_TYPE_GR) {
        fault_entry.fault_source.client_type     = UVM_FAULT_CLIENT_TYPE_GPC;

        fault_entry.fault_source.mmu_engine_type = UVM_MMU_ENGINE_TYPE_GRAPHICS;
        fault_entry.fault_source.ve_id           = params->ve_id;

    }

    else if (uvm_gpu_supports_non_replayable_faults(gpu)) {
        fault_entry.fault_source.client_type     = UVM_FAULT_CLIENT_TYPE_HUB;
        fault_entry.fault_source.mmu_engine_type = UVM_MMU_ENGINE_TYPE_CE;
        fault_entry.fault_source.ve_id           = 0;
    }

    else {
        status = NV_ERR_INVALID_CHANNEL;
        goto out;
    }

    // We can ignore the return code because this ioctl only cares about whether
    // the provided channel + VEID matches the provided VA space. In all of the
    // non-NV_OK cases the translation will fail and we should return
    // NV_ERR_INVALID_CHANNEL. channel_va_space == NULL for all such cases.
    (void)uvm_gpu_fault_entry_to_va_space(gpu, &fault_entry, &channel_va_space);

    if (channel_va_space == va_space)
        status = NV_OK;
    else
        status = NV_ERR_INVALID_CHANNEL;

out:
    if (va_space_filp) {
        if (va_space)
            uvm_va_space_up_read(va_space);
        fput(va_space_filp);
    }

    return status;
}
