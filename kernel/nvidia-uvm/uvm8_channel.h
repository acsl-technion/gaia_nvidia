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

#ifndef __UVM8_CHANNEL_H__
#define __UVM8_CHANNEL_H__

#include "nv_uvm_types.h"
#include "uvm8_forward_decl.h"
#include "uvm8_gpu_semaphore.h"
#include "uvm8_pushbuffer.h"
#include "uvm8_tracker.h"

//
// UVM channels
//
// A channel manager is created as part of the GPU addition. This involves
// creating channels for each of the supported types (uvm_channel_type_t) in
// separate channel pools possibly using different CE instances in the HW. Each
// channel has a uvm_gpu_tracking_semaphore_t and a set of uvm_gpfifo_entry_t
// (one per each HW GPFIFO entry) allowing to track completion of pushes on the
// channel.
//
// Beginning a push on a channel implies reserving a GPFIFO entry in that
// channel and hence there can only be as many on-going pushes per channel as
// there are free GPFIFO entries. This ensures that ending a push won't have to
// wait for a GPFIFO entry to free up.
//

// Channel types
//
// Remember to update uvm_channel_type_to_string() in uvm8_channel.c when adding new types.
typedef enum
{
    // CPU to GPU copies
    UVM_CHANNEL_TYPE_CPU_TO_GPU,

    // GPU to CPU copies
    UVM_CHANNEL_TYPE_GPU_TO_CPU,

    // Memsets and copies within the GPU
    UVM_CHANNEL_TYPE_GPU_INTERNAL,

    // Memops and small memsets/copies for writing PTEs
    UVM_CHANNEL_TYPE_MEMOPS,

    // GPU to GPU peer copies
    // This will need to be expanded as on Pascal+ different LCEs should be used
    // for different peers.
    UVM_CHANNEL_TYPE_GPU_TO_GPU,

    // Any channel type
    // Can be used as a the type with uvm_push_begin*() to pick any channel
    UVM_CHANNEL_TYPE_ANY,

    UVM_CHANNEL_TYPE_COUNT
} uvm_channel_type_t;

struct uvm_gpfifo_entry_struct
{
    // Offset of the pushbuffer in the pushbuffer allocation used by this entry
    NvU32 pushbuffer_offset;

    // Size of the pushbuffer used for this entry
    NvU32 pushbuffer_size;

    // List node used by the pushbuffer tracking
    struct list_head pending_list_node;

    // Channel tracking semaphore value that indicates completion of this entry
    NvU64 tracking_semaphore_value;

    // Push info for the pending push that used this GPFIFO entry
    uvm_push_info_t *push_info;
};

typedef struct
{
    // Owning channel manager
    uvm_channel_manager_t *manager;

    // Type of the channels in the pool
    uvm_channel_type_t channel_type;

    // List of the channels in the pool
    struct list_head channels_list;

    // Lock protecting the state of channels in the pool
    uvm_spinlock_t lock;
} uvm_channel_pool_t;

struct uvm_channel_struct
{
    // Owning pool
    uvm_channel_pool_t *pool;

    // The channel type and HW channel ID as string for easy debugging and logs
    char name[64];

    // Array of gpfifo entries, one per each HW GPFIFO
    uvm_gpfifo_entry_t *gpfifo_entries;

    // Latest GPFIFO entry submitted to the GPU
    // Updated when new pushes are submitted to the GPU in
    // uvm_channel_end_push().
    NvU32 cpu_put;

    // Latest GPFIFO entry completed by the GPU
    // Updated by uvm_channel_update_progress() after checking pending GPFIFOs
    // for completion.
    NvU32 gpu_get;

    // Number of currently on-going pushes on this channel
    // A new push is only allowed to begin on the channel if there is a free
    // GPFIFO entry for it.
    NvU32 current_pushes_count;

    // Array of uvm_push_info_t for all pending pushes on the channel
    uvm_push_info_t *push_infos;

    // Push info index (for the push_infos array) to use for the next push that
    // begins on the channel
    // Notably this is different from assigning the GPFIFO entry that happens
    // when the push ends.
    NvU32 next_push_info_index;

    // GPU tracking semaphore tracking the work in the channel
    // Each push on the channel increments the semaphore, see
    // uvm_channel_end_push().
    uvm_gpu_tracking_semaphore_t tracking_sem;

    // Node in the list of all channels that the channel manager owns
    struct list_head all_list_node;

    // Node in the list of all channels in the pool this channels comes from
    struct list_head pool_list_node;

    // UVM-RM interface handle
    uvmGpuChannelHandle handle;

    // Channel state that UVM-RM interface populates, includes the GPFIFO, error
    // notifier etc.
    UvmGpuChannelPointers channel_info;

    struct
    {
        struct proc_dir_entry *dir;
        struct proc_dir_entry *info;
        struct proc_dir_entry *pushes;
    } procfs;

    // Information managed by the tools event notification mechanism. Mainly
    // used to keep a list of channels with pending events, which is needed
    // to collect the timestamps of asynchronous operations.
    struct
    {
        struct list_head channel_list_node;
        NvU32 pending_event_count;
    } tools;
};

struct uvm_channel_manager_struct
{
    // The owning GPU
    uvm_gpu_t *gpu;

    // The pushbuffer used for all pushes done with this channel manager
    uvm_pushbuffer_t *pushbuffer;

    // Array of channel pools, indexed by uvm_channel_type_t
    uvm_channel_pool_t channel_pools[UVM_CHANNEL_TYPE_COUNT];

    // Array of CE indices to be used by each channel type.
    // Initialized in channel_manager_pick_copy_engines()
    NvU32 ce_to_use_by_type[UVM_CHANNEL_TYPE_COUNT];

    // List of all channels
    struct list_head all_channels_list;

    struct
    {
        struct proc_dir_entry *channels_dir;
        struct proc_dir_entry *pending_pushes;
    } procfs;
};

// Create a channel manager for the GPU
//
// If with_procfs is true, also create the procfs entries for the pushbuffer.
// This is needed because some tests create temporary channel manager, but only
// only a single one can have its procfs entries created currently.
NV_STATUS uvm_channel_manager_create_common(uvm_gpu_t *gpu, bool with_procfs, uvm_channel_manager_t **manager_out);

// Create a channel manager for the GPU with procfs
static NV_STATUS uvm_channel_manager_create(uvm_gpu_t *gpu, uvm_channel_manager_t **manager_out)
{
    return uvm_channel_manager_create_common(gpu, true, manager_out);
}

// Create a channel manager for the GPU without procfs
static NV_STATUS uvm_channel_manager_create_no_procfs(uvm_gpu_t *gpu, uvm_channel_manager_t **manager_out)
{
    return uvm_channel_manager_create_common(gpu, false, manager_out);
}

// Destroy the channel manager
void uvm_channel_manager_destroy(uvm_channel_manager_t *channel_manager);

// Get the current status of the channel
// Returns NV_OK if the channel is in a good state and NV_ERR_RC_ERROR
// otherwise. Notably this never sets the global fatal error.
NV_STATUS uvm_channel_get_status(uvm_channel_t *channel);

// Check for channel errors
// Checks for channel errors by calling uvm_channel_get_status(). If an error
// occurred, sets the global fatal error and prints errors.
NV_STATUS uvm_channel_check_errors(uvm_channel_t *channel);

// Check errors on all channels in the channel manager
// Also includes uvm_global_get_status
NV_STATUS uvm_channel_manager_check_errors(uvm_channel_manager_t *channel_manager);

// Retrieve the GPFIFO entry that caused a channel error
// The channel has to be in error state prior to calling this function.
uvm_gpfifo_entry_t *uvm_channel_get_fatal_entry(uvm_channel_t *channel);

// Update progress of a specific channel
// Returns the number of still pending GPFIFO entries for that channel.
// Notably some of the pending GPFIFO entries might be already completed, but
// the update early-outs after completing a fixed number of them to spread the
// cost of the updates across calls.
NvU32 uvm_channel_update_progress(uvm_channel_t *channel);

// Update progress of all channels
// Returns the number of still pending GPFIFO entries for all channels.
// Notably some of the pending GPFIFO entries might be already completed, but
// the update early-outs after completing a fixed number of them to spread the
// cost of the updates across calls.
NvU32 uvm_channel_manager_update_progress(uvm_channel_manager_t *channel_manager);

// Wait for all channels to idle
// It waits for anything that is running, but doesn't prevent new work from
// beginning.
NV_STATUS uvm_channel_manager_wait(uvm_channel_manager_t *manager);

// Get the GPU tracking semaphore
uvm_gpu_semaphore_t *uvm_channel_get_tracking_semaphore(uvm_channel_t *channel);

// Check whether the channel completed a value
bool uvm_channel_is_value_completed(uvm_channel_t *channel, NvU64 value);

// Update and get the latest completed value by the channel
NvU64 uvm_channel_update_completed_value(uvm_channel_t *channel);

// Reserve a channel with the specified type for a push
// Channel type can be UVM_CHANNEL_TYPE_ANY to reserve any channel.
NV_STATUS uvm_channel_reserve_type(uvm_channel_manager_t *manager, uvm_channel_type_t type, uvm_channel_t **channel_out);

// Reserve a specific channel for a push
NV_STATUS uvm_channel_reserve(uvm_channel_t *channel);

// Find a channel that's available at the moment.
// Only really useful in tests.
uvm_channel_t *uvm_channel_manager_find_available_channel(uvm_channel_manager_t *channel_manager);

// Begin a push on a previously reserved channel
// Should be used by uvm_push_*() only.
NV_STATUS uvm_channel_begin_push(uvm_channel_t *channel, uvm_push_t *push);

// End a push
// Should be used by uvm_push_end() only.
void uvm_channel_end_push(uvm_push_t *push);

const char *uvm_channel_type_to_string(uvm_channel_type_t channel_type);

void uvm_channel_print_pending_pushes(uvm_channel_t *channel);

static uvm_gpu_t *uvm_channel_get_gpu(uvm_channel_t *channel)
{
    return channel->pool->manager->gpu;
}

// Helper to get the first channel of the given type including UVM_CHANNEL_ANY_TYPE.
static uvm_channel_t *uvm_channel_get_first(uvm_channel_manager_t *manager, uvm_channel_type_t type)
{
    if (type == UVM_CHANNEL_TYPE_ANY)
        return list_first_entry(&manager->all_channels_list, uvm_channel_t, all_list_node);
    else
        return list_first_entry(&manager->channel_pools[type].channels_list, uvm_channel_t, pool_list_node);
}

// Helper to get the next channel of a given type including UVM_CHANNEL_ANY_TYPE.
static uvm_channel_t *uvm_channel_get_next(uvm_channel_t *channel, uvm_channel_type_t type)
{
    if (type == UVM_CHANNEL_TYPE_ANY) {
        if (list_is_last(&channel->all_list_node, &channel->pool->manager->all_channels_list))
            return NULL;
        return list_next_entry(channel, all_list_node);
    }
    else {
        UVM_ASSERT_MSG(channel->pool->channel_type == type, "Channel type %u != %u\n", channel->pool->channel_type, type);
        if (list_is_last(&channel->pool_list_node, &channel->pool->channels_list))
            return NULL;
        return list_next_entry(channel, pool_list_node);
    }
}

NvU32 uvm_channel_update_progress_all(uvm_channel_t *channel);

// Helper to iterate over all channels of a given type. Notably type can be
// UVM_CHANNEL_TYPE_ANY to iterate over all channels.
#define uvm_for_each_channel_of_type(channel, manager, type)            \
    for (channel = uvm_channel_get_first((manager), (type));            \
         channel != NULL;                                               \
         channel = uvm_channel_get_next(channel, (type)))

// Helper to iterate over all channels.
#define uvm_for_each_channel(channel, manager) uvm_for_each_channel_of_type(channel, (manager), UVM_CHANNEL_TYPE_ANY)

#endif // __UVM8_CHANNEL_H__
