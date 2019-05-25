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

#ifndef __UVM8_PMM_GPU_H__
#define __UVM8_PMM_GPU_H__

//
// The Physical Memory Manager (PMM) manages the life cycle of GPU physical
// memory.
//
// The memory is managed in GPU chunks of different sizes (uvm_chunk_size_t) and
// users of PMM need to explicitly register the chunk sizes they need to be
// supported (see chunk_size_init_func in uvm_pmm_gpu_init()).
//
// Two memory types (uvm_pmm_gpu_memory_type_t) are supported, one for user and
// one for kernel allocations. The user memory type is used only for backing
// user data managed by VA blocks and kernel memory type is used for everything
// else. The distinction exists to support oversubscription, which requires the
// ability to evict already allocated memory from its users on-demand to satisfy
// new memory allocations when no more unused memory is available. Eviction is
// limited to the user memory type as it's a very complex operation requiring
// integration between PMM and other UVM driver modules. The assumption is that
// the vast majority of memory should be used for user data as everything else
// can be considered overhead and should be minimized. Two flavors of
// oversubscription exist: internal oversubscription allowing PMM allocations to
// evict other PMM allocations and external oversubscription allowing other PMA
// clients to evict memory used by PMM.
//
// Both allocation and freeing of memory support asynchronous operations where
// the allocated/freed GPU memory chunks can have pending GPU operations
// returned when allocating memory and passed in when freeing it via trackers.
//

#include "uvm8_forward_decl.h"
#include "uvm8_lock.h"
#include "uvm8_tracker.h"
#include "uvm_linux.h"
#include "uvmtypes.h"
#include "nv_uvm_types.h"

typedef enum
{
    UVM_CHUNK_SIZE_1       =           1ULL,
    UVM_CHUNK_SIZE_2       =           2ULL,
    UVM_CHUNK_SIZE_4       =           4ULL,
    UVM_CHUNK_SIZE_8       =           8ULL,
    UVM_CHUNK_SIZE_16      =          16ULL,
    UVM_CHUNK_SIZE_32      =          32ULL,
    UVM_CHUNK_SIZE_64      =          64ULL,
    UVM_CHUNK_SIZE_128     =         128ULL,
    UVM_CHUNK_SIZE_256     =         256ULL,
    UVM_CHUNK_SIZE_512     =         512ULL,
    UVM_CHUNK_SIZE_1K      =        1024ULL,
    UVM_CHUNK_SIZE_2K      =      2*1024ULL,
    UVM_CHUNK_SIZE_4K      =      4*1024ULL,
    UVM_CHUNK_SIZE_8K      =      8*1024ULL,
    UVM_CHUNK_SIZE_16K     =     16*1024ULL,
    UVM_CHUNK_SIZE_32K     =     32*1024ULL,
    UVM_CHUNK_SIZE_64K     =     64*1024ULL,
    UVM_CHUNK_SIZE_128K    =    128*1024ULL,
    UVM_CHUNK_SIZE_256K    =    256*1024ULL,
    UVM_CHUNK_SIZE_512K    =    512*1024ULL,
    UVM_CHUNK_SIZE_1M      =   1024*1024ULL,
    UVM_CHUNK_SIZE_2M      = 2*1024*1024ULL,
    UVM_CHUNK_SIZE_MAX     = UVM_CHUNK_SIZE_2M,
    UVM_CHUNK_SIZE_INVALID = UVM_CHUNK_SIZE_MAX * 2ULL
} uvm_chunk_size_t;

typedef enum
{
    // Memory type for backing user pages. On Pascal+ it can be evicted.
    UVM_PMM_GPU_MEMORY_TYPE_USER,

    // Memory type for internal UVM allocations. It cannot be evicted.
    UVM_PMM_GPU_MEMORY_TYPE_KERNEL,

    // Number of types - MUST BE LAST.
    UVM_PMM_GPU_MEMORY_TYPE_COUNT
} uvm_pmm_gpu_memory_type_t;

const char *uvm_pmm_gpu_memory_type_string(uvm_pmm_gpu_memory_type_t type);

typedef enum
{
    // Chunk belongs to PMA. Code outside PMM should not have access to
    // it and it is likely a bug in UVM code (either in PMM or outside)
    // if that happens.
    UVM_PMM_GPU_CHUNK_STATE_PMA_OWNED,

    // Chunk is on free list. That is it can be reused or returned to PMA
    // as soon as its tracker is done. Code outside PMM should not have
    // access to this chunk and it is likely a bug in UVM code (either in
    // PMM or outside) if that happens.
    UVM_PMM_GPU_CHUNK_STATE_FREE,

    // Chunk is split into subchunks.
    UVM_PMM_GPU_CHUNK_STATE_IS_SPLIT,

    // Chunk is temporarily pinned.
    //
    // This state is used for user memory chunks that have been allocated, but haven't
    // been unpinned yet and also internally when a chunk is about to be split.
    UVM_PMM_GPU_CHUNK_STATE_TEMP_PINNED,

    // Chunk is allocated. That is it is backing some VA block
    UVM_PMM_GPU_CHUNK_STATE_ALLOCATED,

    // Number of states - MUST BE LAST
    UVM_PMM_GPU_CHUNK_STATE_COUNT
} uvm_pmm_gpu_chunk_state_t;

const char *uvm_pmm_gpu_chunk_state_string(uvm_pmm_gpu_chunk_state_t state);

typedef enum
{
    // No flags passed
    UVM_PMM_ALLOC_FLAGS_NONE,

    // If there is no free memory, allocation may evict chunks
    // instead of returning error immediately. Therefore it must not be called
    // under the VA block lock.
    UVM_PMM_ALLOC_FLAGS_EVICT = (1 << 0),

    UVM_PMM_ALLOC_FLAGS_MASK = (1 << 1) - 1
} uvm_pmm_alloc_flags_t;

// Maximum chunk sizes per type of allocation in single GPU.
// The worst case today is Maxwell with 4 allocations sizes for page tables and
// 2 page sizes used by uvm_mem_t. Notably one of the allocations for page
// tables is 2M which is our common root chunk size.
#define UVM_MAX_CHUNK_SIZES 6

// This specifies a maximum GAP between 2 allocation levels.
#define UVM_PMM_MAX_SUBCHUNKS UVM_CHUNK_SIZE_MAX

#define UVM_PMM_CHUNK_SPLIT_CACHE_SIZES (ilog2(UVM_PMM_MAX_SUBCHUNKS) + 1)
#define UVM_CHUNK_SIZE_MASK_SIZE (ilog2(UVM_CHUNK_SIZE_MAX) + 1)

typedef uvm_chunk_size_t uvm_chunk_sizes_mask_t;

typedef struct uvm_pmm_gpu_chunk_suballoc_struct uvm_pmm_gpu_chunk_suballoc_t;

#define UVM_GPU_CHUNK_FLAGS_TYPE_KERNEL         0
#define UVM_GPU_CHUNK_FLAGS_IN_EVICTION         1
#define UVM_GPU_CHUNK_FLAGS_INJECT_SPLIT_ERROR  2

#define UVM_GPU_CHUNK_FLAGS_STATE_START     (UVM_GPU_CHUNK_FLAGS_INJECT_SPLIT_ERROR + 1)
#define UVM_GPU_CHUNK_FLAGS_STATE_SIZE      order_base_2(UVM_PMM_GPU_CHUNK_STATE_COUNT)

#define UVM_GPU_CHUNK_FLAGS_SIZE_LOG2_START (UVM_GPU_CHUNK_FLAGS_STATE_START + UVM_GPU_CHUNK_FLAGS_STATE_SIZE)
#define UVM_GPU_CHUNK_FLAGS_SIZE_LOG2_SIZE  order_base_2(UVM_CHUNK_SIZE_MASK_SIZE)

typedef struct uvm_gpu_chunk_struct uvm_gpu_chunk_t;
struct uvm_gpu_chunk_struct
{
    // Physical address of GPU chunk. This may be removed to save memory
    // if we will be able to get it from reverse map and changed
    // into smaller index for subchunks.
    NvU64 address;

    // See UVM_GPU_CHUNK_FLAGS_*
    unsigned long flags;

    // List entry.
    //
    // Guaranteed to be a valid list node at all times for simplicity.
    //
    // Protected by PMM's list_lock when managed by PMM. Notably the list node
    // can be used by the allocator of the chunk after alloc and before the
    // chunk is unpinned or freed.
    struct list_head list;

    // The VA block using the chunk, if any.
    // User chunks that are not backed by a VA block are considered to be
    // temporarily pinned and cannot be evicted.
    uvm_va_block_t *va_block;

    // If this is subchunk it points to the parent - in other words
    // chunk of bigger size which contains this chunk.
    uvm_gpu_chunk_t *parent;

    // Array describing suballocations
    uvm_pmm_gpu_chunk_suballoc_t *suballoc;
};

typedef struct uvm_gpu_root_chunk_struct
{
    uvm_gpu_chunk_t chunk;

    // Pending operations for all GPU chunks under the root chunk.
    //
    // Protected by the corresponding root chunk bit lock.
    uvm_tracker_t tracker;
} uvm_gpu_root_chunk_t;

typedef struct
{
    uvm_gpu_t *gpu;

    // Sizes of the MMU
    uvm_chunk_sizes_mask_t chunk_sizes[UVM_PMM_GPU_MEMORY_TYPE_COUNT];

    // PMA (Physical Memory Allocator) opaque handle
    void *pma;

    // Array of all root chunks indexed by their physical address divided by
    // UVM_CHUNK_SIZE_MAX.
    //
    // This array is pre-allocated during uvm_pmm_gpu_init() for all possible
    // physical addresses (based on gpu::vidmem_max_physical_address).
    size_t root_chunks_count;
    uvm_gpu_root_chunk_t *root_chunks;

    // Bit locks for the root chunks with 1 bit per each root chunk
    uvm_bit_locks_t root_chunks_bitlocks;

    // Lock protecting PMA allocation, freeing and eviction
    uvm_rw_semaphore_t pma_lock;

    // Lock protecting splits, merges and walks of chunks.
    uvm_mutex_t lock;

    // Lock protecting lists and chunk's state transitions.
    uvm_spinlock_t list_lock;

    // Free chunk lists
    struct list_head free_list[UVM_PMM_GPU_MEMORY_TYPE_COUNT][UVM_MAX_CHUNK_SIZES];

    // List of root chunks unused by VA blocks, i.e. allocated, but not holding
    // any resident pages. These take priority when evicting as no data needs to
    // be migrated for them to be evicted.
    //
    // For simplicity, the list is approximate, tracking unused chunks only from
    // root chunk sized (2M) VA blocks.
    // Updated by the VA block code with uvm_pmm_gpu_mark_root_chunk_(un)used().
    struct list_head va_block_unused_root_chunks;

    // List of root chunks used by VA blocks
    struct list_head va_block_used_root_chunks;

    // Inject an error after evicting a number of chunks. 0 means no error left
    // to be injected.
    NvU32 inject_pma_evict_error_after_num_chunks;

    // The mask of the initialized chunk sizes
    DECLARE_BITMAP(chunk_split_cache_initialized, UVM_PMM_CHUNK_SPLIT_CACHE_SIZES);
} uvm_pmm_gpu_t;

// Initialize PMM on GPU
NV_STATUS uvm_pmm_gpu_init(uvm_gpu_t *gpu, uvm_pmm_gpu_t *pmm);

// Deinitialize the PMM on GPU
void uvm_pmm_gpu_deinit(uvm_pmm_gpu_t *pmm);

// Helpers for accessing the individual fields in flags
static unsigned long uvm_gpu_chunk_get_flags(uvm_gpu_chunk_t *chunk, unsigned long start, unsigned long size)
{
    unsigned long field = chunk->flags >> start;
    unsigned long mask = (1UL << size) - 1;
    return field & mask;
}

static void uvm_gpu_chunk_set_flags(uvm_gpu_chunk_t *chunk, unsigned long start, unsigned long size, unsigned long val)
{
    unsigned long mask = (1UL << size) - 1;
    UVM_ASSERT((val & ~mask) == 0);
    chunk->flags &= ~(mask << start);
    chunk->flags |= (val << start);
}

static uvm_pmm_gpu_memory_type_t uvm_gpu_chunk_get_type(uvm_gpu_chunk_t *chunk)
{
    if (test_bit(UVM_GPU_CHUNK_FLAGS_TYPE_KERNEL, &chunk->flags))
        return UVM_PMM_GPU_MEMORY_TYPE_KERNEL;
    return UVM_PMM_GPU_MEMORY_TYPE_USER;
}

static void uvm_gpu_chunk_set_type(uvm_gpu_chunk_t *chunk, uvm_pmm_gpu_memory_type_t type)
{
    if (type == UVM_PMM_GPU_MEMORY_TYPE_KERNEL)
        __set_bit(UVM_GPU_CHUNK_FLAGS_TYPE_KERNEL, &chunk->flags);
    else
        __clear_bit(UVM_GPU_CHUNK_FLAGS_TYPE_KERNEL, &chunk->flags);
}

static bool uvm_gpu_chunk_get_inject_split_error(uvm_gpu_chunk_t *chunk)
{
    return test_bit(UVM_GPU_CHUNK_FLAGS_INJECT_SPLIT_ERROR, &chunk->flags);
}

static void uvm_gpu_chunk_set_inject_split_error(uvm_gpu_chunk_t *chunk)
{
    __set_bit(UVM_GPU_CHUNK_FLAGS_INJECT_SPLIT_ERROR, &chunk->flags);
}

static void uvm_gpu_chunk_clear_inject_split_error(uvm_gpu_chunk_t *chunk)
{
    __clear_bit(UVM_GPU_CHUNK_FLAGS_INJECT_SPLIT_ERROR, &chunk->flags);
}

static uvm_pmm_gpu_chunk_state_t uvm_gpu_chunk_get_state(uvm_gpu_chunk_t *chunk)
{
    return uvm_gpu_chunk_get_flags(chunk, UVM_GPU_CHUNK_FLAGS_STATE_START, UVM_GPU_CHUNK_FLAGS_STATE_SIZE);
}

static void uvm_gpu_chunk_set_state(uvm_gpu_chunk_t *chunk, uvm_pmm_gpu_chunk_state_t state)
{
    uvm_gpu_chunk_set_flags(chunk, UVM_GPU_CHUNK_FLAGS_STATE_START, UVM_GPU_CHUNK_FLAGS_STATE_SIZE, state);
}

static uvm_chunk_size_t uvm_gpu_chunk_get_size(uvm_gpu_chunk_t *chunk)
{
    unsigned long size_log2 = uvm_gpu_chunk_get_flags(chunk,
                                                      UVM_GPU_CHUNK_FLAGS_SIZE_LOG2_START,
                                                      UVM_GPU_CHUNK_FLAGS_SIZE_LOG2_SIZE);
    return ((uvm_chunk_size_t)1) << size_log2;
}

static void uvm_gpu_chunk_set_size(uvm_gpu_chunk_t *chunk, uvm_chunk_size_t size)
{
    uvm_gpu_chunk_set_flags(chunk,
                            UVM_GPU_CHUNK_FLAGS_SIZE_LOG2_START,
                            UVM_GPU_CHUNK_FLAGS_SIZE_LOG2_SIZE,
                            ilog2(size));
}

// Allocates num_chunks chunks of size chunk_size in caller-supplied array (chunks).
//
// Returned chunks are in the TEMP_PINNED state, requiring a call to either
// uvm_pmm_gpu_unpin_temp or uvm_pmm_gpu_free. If a tracker is passed in, all
// the pending operations on the allocated chunks will be added to it
// guaranteeing that all the entries come from the same GPU as the PMM.
// Otherwise, when tracker is NULL, all the pending operations will be
// synchronized before returning to the caller.
//
// Each of the allocated chunks list nodes (uvm_gpu_chunk_t::list) can be used
// by the caller until the chunk is unpinned (uvm_pmm_gpu_unpin_temp) or freed
// (uvm_pmm_gpu_free). If used, the list node has to be returned to a valid
// state before calling either of the APIs.
//
// In case of an error, the chunks array is guaranteed to be cleared.
NV_STATUS uvm_pmm_gpu_alloc(uvm_pmm_gpu_t *pmm,
                            size_t num_chunks,
                            uvm_chunk_size_t chunk_size,
                            uvm_pmm_gpu_memory_type_t mem_type,
                            uvm_pmm_alloc_flags_t flags,
                            uvm_gpu_chunk_t **chunks,
                            uvm_tracker_t *out_tracker);

// Helper for allocating kernel memory
//
// Internally calls uvm_pmm_gpu_alloc() and sets the state of all chunks to
// allocated on success.
NV_STATUS uvm_pmm_gpu_alloc_kernel(uvm_pmm_gpu_t *pmm,
                                   size_t num_chunks,
                                   uvm_chunk_size_t chunk_size,
                                   uvm_pmm_alloc_flags_t flags,
                                   uvm_gpu_chunk_t **chunks,
                                   uvm_tracker_t *out_tracker);

// Helper for allocating user memory
//
// Simple wrapper that just uses UVM_PMM_GPU_MEMORY_TYPE_USER for the memory type.
static NV_STATUS uvm_pmm_gpu_alloc_user(uvm_pmm_gpu_t *pmm,
                                        size_t num_chunks,
                                        uvm_chunk_size_t chunk_size,
                                        uvm_pmm_alloc_flags_t flags,
                                        uvm_gpu_chunk_t **chunks,
                                        uvm_tracker_t *out_tracker)
{
    return uvm_pmm_gpu_alloc(pmm, num_chunks, chunk_size, UVM_PMM_GPU_MEMORY_TYPE_USER, flags, chunks, out_tracker);
}

// Unpin a temporarily pinned chunk and set its reverse map to a VA block
//
// Can only be used on user memory.
void uvm_pmm_gpu_unpin_temp(uvm_pmm_gpu_t *pmm, uvm_gpu_chunk_t *chunk, uvm_va_block_t *va_block);

// Frees the chunk. This also unpins the chunk if it is temporarily pinned.
//
// The tracker is optional and a NULL tracker indicates that no new operation
// has been pushed for the chunk, but the tracker returned as part of
// its allocation doesn't have to be completed as PMM will synchronize it
// internally if needed. A non-NULL tracker indicates any additional pending
// operations on the chunk pushed by the caller that need to be synchronized
// before freeing or re-using the chunk.
void uvm_pmm_gpu_free(uvm_pmm_gpu_t *pmm, uvm_gpu_chunk_t *chunk, uvm_tracker_t *tracker);

// Splits the input chunk in-place into smaller chunks of subchunk_size. No data
// is moved, and the smaller chunks remain allocated.
//
// If the subchunks array is non-NULL, it will be filled with
// (uvm_gpu_chunk_get_size(chunk) / subchunk_size) chunks in address order. The
// new chunks must all be freed individually.
//
// If the subchunks array is NULL, the split chunks can be retrieved later by
// passing the original parent chunk to uvm_pmm_gpu_get_subchunks.
//
// On error, the original chunk remains unmodified.
//
// The chunk must be in the ALLOCATED state with the owning VA block lock held,
// or the TEMP_PINNED state.
//
// subchunk_size must be a valid chunk size for the given type.
//
// The chunk can be re-merged if desired using uvm_pmm_gpu_merge_chunk.
NV_STATUS uvm_pmm_gpu_split_chunk(uvm_pmm_gpu_t *pmm,
                                  uvm_gpu_chunk_t *chunk,
                                  uvm_chunk_size_t subchunk_size,
                                  uvm_gpu_chunk_t **subchunks);

// Retrieve leaf subchunks under parent. Up to num_subchunks chunks are copied
// into the subchunks array in address order, starting with the subchunk at
// start_index. start_index can be thought of as the number of leaf subchunks to
// skip before beginning the copy.
//
// parent can be in the ALLOCATED state, in which case parent is the only chunk
// which may be copied into the subchunks array.
//
// num_subchunks may be 0.
//
// Returns the number of subchunks written to the array. This may be less than
// num_subchunks depending on the value of start_index and how many subchunks
// are present under parent.
size_t uvm_pmm_gpu_get_subchunks(uvm_pmm_gpu_t *pmm,
                                 uvm_gpu_chunk_t *parent,
                                 size_t start_index,
                                 size_t num_subchunks,
                                 uvm_gpu_chunk_t **subchunks);

// Merges a chunk previously split with uvm_pmm_gpu_split_chunk. All of chunk's
// leaf children must be allocated.
void uvm_pmm_gpu_merge_chunk(uvm_pmm_gpu_t *pmm, uvm_gpu_chunk_t *chunk);

// Waits for all free chunk trackers (removing their completed entries) to complete.
//
// This inherently races with any chunks being freed to this PMM. The assumption
// is that the caller doesn't care about preventing new chunks from being freed,
// just that any already-freed chunks will be synced.
void uvm_pmm_gpu_sync(uvm_pmm_gpu_t *pmm);

// Mark an allocated chunk as evicted
void uvm_pmm_gpu_mark_chunk_evicted(uvm_pmm_gpu_t *pmm, uvm_gpu_chunk_t *chunk);

// Mark a user chunk as used
//
// If the chunk is pinned or selected for eviction, this won't do anything. The
// chunk can be pinned when it's being initially populated by the VA block.
// Allow that state to make this API easy to use for the caller.
void uvm_pmm_gpu_mark_root_chunk_used(uvm_pmm_gpu_t *pmm, uvm_gpu_chunk_t *chunk);

// Mark an allocated user chunk as unused
void uvm_pmm_gpu_mark_root_chunk_unused(uvm_pmm_gpu_t *pmm, uvm_gpu_chunk_t *chunk);

static bool uvm_gpu_chunk_same_root(uvm_gpu_chunk_t *chunk_1, uvm_gpu_chunk_t *chunk_2)
{
    return UVM_ALIGN_DOWN(chunk_1->address, UVM_CHUNK_SIZE_MAX) == UVM_ALIGN_DOWN(chunk_2->address, UVM_CHUNK_SIZE_MAX);
}

// Finds the first (smallest) size in the chunk_sizes mask
static uvm_chunk_size_t uvm_chunk_find_first_size(uvm_chunk_sizes_mask_t chunk_sizes)
{
    UVM_ASSERT(chunk_sizes);
    return (uvm_chunk_size_t)1 << __ffs(chunk_sizes);
}

// Finds the last (biggest) size in the chunk_sizes mask
static uvm_chunk_size_t uvm_chunk_find_last_size(uvm_chunk_sizes_mask_t chunk_sizes)
{
    UVM_ASSERT(chunk_sizes);
    return (uvm_chunk_size_t)1 << __fls(chunk_sizes);
}

// Finds the smallest size in the chunk_sizes mask which is larger than
// chunk_size. If there is no such value returns UVM_CHUNK_SIZE_INVALID.
static uvm_chunk_size_t uvm_chunk_find_next_size(uvm_chunk_sizes_mask_t chunk_sizes, uvm_chunk_size_t chunk_size)
{
    UVM_ASSERT(is_power_of_2(chunk_size));
    UVM_ASSERT(chunk_sizes & chunk_size);
    BUILD_BUG_ON(sizeof(chunk_sizes) > sizeof(unsigned long));
    return (uvm_chunk_size_t)1 << __ffs((chunk_sizes & ~((chunk_size << 1) - 1)) | UVM_CHUNK_SIZE_INVALID);
}

// Finds the largest size in the chunk_sizes mask which is smaller than
// chunk_size. If there is no such value returns UVM_CHUNK_SIZE_INVALID.
static uvm_chunk_size_t uvm_chunk_find_prev_size(uvm_chunk_sizes_mask_t chunk_sizes, uvm_chunk_size_t chunk_size)
{
    UVM_ASSERT(is_power_of_2(chunk_size));
    UVM_ASSERT(chunk_sizes & chunk_size);
    chunk_sizes = chunk_sizes & (chunk_size - 1);
    if (!chunk_sizes)
        return UVM_CHUNK_SIZE_INVALID;
    return (uvm_chunk_size_t)1 << __fls(chunk_sizes);
}

// Iterates over every size in the input mask from smallest to largest
#define for_each_chunk_size(__size, __chunk_sizes)                                  \
    for ((__size) = (__chunk_sizes) ? uvm_chunk_find_first_size(__chunk_sizes) :    \
                                      UVM_CHUNK_SIZE_INVALID;                       \
         (__size) != UVM_CHUNK_SIZE_INVALID;                                        \
         (__size) = uvm_chunk_find_next_size((__chunk_sizes), (__size)))

// Iterates over every size in the input mask from largest to smallest
#define for_each_chunk_size_rev(__size, __chunk_sizes)                          \
    for ((__size) = (__chunk_sizes) ? uvm_chunk_find_last_size(__chunk_sizes) : \
                                      UVM_CHUNK_SIZE_INVALID;                   \
         (__size) != UVM_CHUNK_SIZE_INVALID;                                    \
         (__size) = uvm_chunk_find_prev_size((__chunk_sizes), (__size)))

// Iterates over every size in the input mask from smallest to largest, starting
// from and including __size. __size must be present in the mask.
#define for_each_chunk_size_from(__size, __chunk_sizes)                 \
    for (; (__size) != UVM_CHUNK_SIZE_INVALID;                          \
         (__size) = uvm_chunk_find_next_size((__chunk_sizes), (__size)))

// Iterates over every size in the input mask from largest to smallest, starting
// from and including __size. __size must be present in the mask.
#define for_each_chunk_size_rev_from(__size, __chunk_sizes)             \
    for (; (__size) != UVM_CHUNK_SIZE_INVALID;                          \
         (__size) = uvm_chunk_find_prev_size((__chunk_sizes), (__size)))

#endif
