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

#include "uvm_common.h"
#include "uvm8_pmm_gpu.h"
#include "uvm8_global.h"
#include "uvm8_gpu.h"
#include "uvm8_hal.h"
#include "uvm8_va_space.h"
#include "uvm8_tracker.h"
#include "uvm8_push.h"
#include "uvm8_mem.h"
#include "uvm8_kvmalloc.h"

#include "uvm8_test.h"
#include "uvm8_test_ioctl.h"
#include "uvm8_test_rng.h"

#define CHUNKS_PER_BUCKET 128

typedef struct
{
    struct list_head entry;
    uvm_gpu_chunk_t *chunks[CHUNKS_PER_BUCKET];
} pmm_leak_bucket_t;

typedef struct
{
    uvm_gpu_chunk_t *chunk;
    uvm_tracker_t tracker;
    NvU32 pattern;
    struct list_head node;
} test_chunk_t;

// When the basic_test free_pattern is BASIC_TEST_FREE_PATTERN_EVERY_N, this
// controls how many allocs to do before a free.
#define BASIC_TEST_FREE_EVERY_N 3

// Number of allocations to make in part of basic_test. This is 33 because
// that's a decent balance between the widest gap between chunk levels (causing
// us to fill up at least one root chunk), and 33*UVM_CHUNK_SIZE_MAX isn't too
// big.
#define BASIC_TEST_STATIC_ALLOCATIONS 33

typedef enum
{
    BASIC_TEST_FREE_PATTERN_IMMEDIATE,
    BASIC_TEST_FREE_PATTERN_ALL_FORWARD,
    BASIC_TEST_FREE_PATTERN_ALL_REVERSE,
    BASIC_TEST_FREE_PATTERN_EVERY_N,
    BASIC_TEST_FREE_PATTERN_COUNT
} basic_test_free_pattern_t;

typedef struct
{
    // List of all allocated test_chunk_t's
    struct list_head list;

    // Total number of chunks allocated in this test
    size_t num_chunks_total;

    uvm_va_space_t *va_space;
    uvm_pmm_gpu_t *pmm;
    uvm_mem_t *verif_mem;
    uvm_pmm_gpu_memory_type_t type;
    basic_test_free_pattern_t free_pattern;
} basic_test_state_t;

typedef enum
{
    SPLIT_TEST_MODE_NORMAL,
    SPLIT_TEST_MODE_MERGE,
    SPLIT_TEST_MODE_INJECT_ERROR,
    SPLIT_TEST_MODE_COUNT
} split_test_mode_t;

// Verify that the input chunks are in the correct state following alloc
static NV_STATUS check_chunks(uvm_pmm_gpu_t *pmm,
                              uvm_gpu_chunk_t **chunks,
                              size_t num_chunks,
                              uvm_chunk_size_t chunk_size,
                              uvm_pmm_gpu_memory_type_t mem_type)
{
    size_t i;
    for (i = 0; i < num_chunks; i++) {
        TEST_CHECK_RET(chunks[i]);
        TEST_CHECK_RET(chunks[i]->suballoc == NULL);
        TEST_CHECK_RET(uvm_gpu_chunk_get_type(chunks[i])  == mem_type);
        TEST_CHECK_RET(uvm_gpu_chunk_get_state(chunks[i]) == UVM_PMM_GPU_CHUNK_STATE_TEMP_PINNED);
        TEST_CHECK_RET(uvm_gpu_chunk_get_size(chunks[i])  == chunk_size);
        TEST_CHECK_RET(IS_ALIGNED(chunks[i]->address, chunk_size));
    }

    return NV_OK;
}

static NV_STATUS check_alloc_tracker(uvm_pmm_gpu_t *pmm, uvm_tracker_t *tracker)
{
    uvm_tracker_entry_t *tracker_entry;

    // The tracker entries returned from an alloc are not allowed to contain
    // entries for any GPU other than the owner. This is to prevent leaking
    // tracker entries from other GPUs into VA spaces which never registered
    // those GPUs.
    for_each_tracker_entry(tracker_entry, tracker)
        TEST_CHECK_RET(uvm_tracker_entry_gpu(tracker_entry) == pmm->gpu);

    return NV_OK;
}

static NV_STATUS chunk_alloc_check_common(uvm_pmm_gpu_t *pmm,
                                          size_t num_chunks,
                                          uvm_chunk_size_t chunk_size,
                                          uvm_pmm_gpu_memory_type_t mem_type,
                                          uvm_pmm_alloc_flags_t flags,
                                          uvm_gpu_chunk_t **chunks,
                                          uvm_tracker_t *local_tracker,
                                          uvm_tracker_t *tracker)
{
    NV_STATUS status;
    NV_STATUS check_status;

    check_status = check_alloc_tracker(pmm, local_tracker);

    if (tracker) {
        status = uvm_tracker_add_tracker_safe(tracker, local_tracker);
        uvm_tracker_clear(local_tracker);
    }
    else {
        status = uvm_tracker_wait(local_tracker);
    }
    uvm_tracker_deinit(local_tracker);

    if (check_status == NV_OK)
        check_status = status;

    if (check_status != NV_OK)
        return check_status;

    return check_chunks(pmm, chunks, num_chunks, chunk_size, mem_type);
}

static NV_STATUS chunk_alloc_check(uvm_pmm_gpu_t *pmm,
                                   size_t num_chunks,
                                   uvm_chunk_size_t chunk_size,
                                   uvm_pmm_gpu_memory_type_t mem_type,
                                   uvm_pmm_alloc_flags_t flags,
                                   uvm_gpu_chunk_t **chunks,
                                   uvm_tracker_t *tracker)
{
    NV_STATUS status;
    uvm_tracker_t local_tracker = UVM_TRACKER_INIT();

    status = uvm_pmm_gpu_alloc(pmm, num_chunks, chunk_size, mem_type, flags, chunks, &local_tracker);
    if (status != NV_OK)
        return status;

    return chunk_alloc_check_common(pmm, num_chunks, chunk_size, mem_type, flags, chunks, &local_tracker, tracker);
}

static NV_STATUS chunk_alloc_user_check(uvm_pmm_gpu_t *pmm,
                                        size_t num_chunks,
                                        uvm_chunk_size_t chunk_size,
                                        uvm_pmm_alloc_flags_t flags,
                                        uvm_gpu_chunk_t **chunks,
                                        uvm_tracker_t *tracker)
{
    NV_STATUS status;
    uvm_tracker_t local_tracker = UVM_TRACKER_INIT();

    status = uvm_pmm_gpu_alloc_user(pmm, num_chunks, chunk_size, flags, chunks, &local_tracker);
    if (status != NV_OK)
        return status;

    return chunk_alloc_check_common(pmm, num_chunks, chunk_size, UVM_PMM_GPU_MEMORY_TYPE_USER,
            flags, chunks, &local_tracker, tracker);
}

static NV_STATUS check_leak(uvm_gpu_t *gpu, uvm_chunk_size_t chunk_size, NvS64 limit, NvU64 *chunks)
{
    NV_STATUS status = NV_OK;
    pmm_leak_bucket_t *bucket, *next;
    LIST_HEAD(allocations);
    *chunks = 0;
    while (limit != *chunks) {
        int k;
        pmm_leak_bucket_t *allocated;
        allocated = kzalloc(sizeof(pmm_leak_bucket_t), GFP_KERNEL);
        if (allocated == NULL) {
            status = NV_ERR_NO_MEMORY;
            goto cleanup;
        }
        list_add(&allocated->entry, &allocations);
        for (k = 0; k < CHUNKS_PER_BUCKET && limit != *chunks; k++) {
            status = chunk_alloc_check(&gpu->pmm,
                                       1,
                                       chunk_size,
                                       UVM_PMM_GPU_MEMORY_TYPE_USER,
                                       UVM_PMM_ALLOC_FLAGS_NONE,
                                       &allocated->chunks[k],
                                       NULL);
            UVM_ASSERT(status == NV_OK || status == NV_ERR_NO_MEMORY);
            if (status != NV_OK) {
                if (limit == -1 && status == NV_ERR_NO_MEMORY)
                    status = NV_OK;
                goto cleanup;
            }
            (*chunks)++;
            if (fatal_signal_pending(current)) {
                status = NV_ERR_SIGNAL_PENDING;
                goto cleanup;
            }
        }
    }
cleanup:
    list_for_each_entry_safe(bucket, next, &allocations, entry) {
        int k;
        for (k = 0; k < CHUNKS_PER_BUCKET; k++) {
            if (!bucket->chunks[k])
                break;
            uvm_pmm_gpu_free(&gpu->pmm, bucket->chunks[k], NULL);
        }
        list_del(&bucket->entry);
        kfree(bucket);
    }
    return status;
}

static NV_STATUS init_test_chunk(uvm_va_space_t *va_space,
                                 uvm_pmm_gpu_t *pmm,
                                 test_chunk_t *test_chunk,
                                 uvm_pmm_gpu_memory_type_t type,
                                 uvm_chunk_size_t size,
                                 NvU32 pattern)
{
    NV_STATUS status;
    uvm_push_t push;
    uvm_gpu_address_t chunk_addr;
    uvm_gpu_t *other_gpu;

    INIT_LIST_HEAD(&test_chunk->node);
    uvm_tracker_init(&test_chunk->tracker);
    test_chunk->pattern = pattern;

    MEM_NV_CHECK_RET(chunk_alloc_check(pmm, 1, size, type, UVM_PMM_ALLOC_FLAGS_EVICT, &test_chunk->chunk, &test_chunk->tracker), NV_OK);

    // Fill the chunk
    status = uvm_push_begin_acquire(pmm->gpu->channel_manager,
                                    UVM_CHANNEL_TYPE_GPU_INTERNAL,
                                    &test_chunk->tracker,
                                    &push,
                                    "memset chunk {%s, %u} to 0x%08x",
                                    uvm_pmm_gpu_memory_type_string(type),
                                    size,
                                    pattern);
    TEST_NV_CHECK_GOTO(status, out);

    chunk_addr = uvm_gpu_address_physical(UVM_APERTURE_VID, test_chunk->chunk->address);
    pmm->gpu->ce_hal->memset_4(&push, chunk_addr, pattern, size);

    uvm_push_end(&push);
    TEST_NV_CHECK_GOTO(uvm_tracker_add_push_safe(&test_chunk->tracker, &push), out);

    // Launch dummy pushes on all other GPUs. This will increase the chances of
    // a subsequent re-alloc of this chunk needing to synchronize the tracker.
    // See the tracker comment in check_alloc_tracker.
    for_each_va_space_gpu(other_gpu, va_space) {
        if (other_gpu == pmm->gpu)
            continue;

        status = uvm_push_begin(other_gpu->channel_manager,
                                UVM_CHANNEL_TYPE_MEMOPS,
                                &push,
                                "dummy push for chunk {%s, %u} with 0x%08x",
                                uvm_pmm_gpu_memory_type_string(type),
                                size,
                                pattern);
        TEST_NV_CHECK_GOTO(status, out);

        other_gpu->host_hal->noop(&push, 4);

        uvm_push_end(&push);
        TEST_NV_CHECK_GOTO(uvm_tracker_add_push_safe(&test_chunk->tracker, &push), out);
    }

out:
    if (status != NV_OK) {
        uvm_pmm_gpu_free(pmm, test_chunk->chunk, &test_chunk->tracker);
        uvm_tracker_deinit(&test_chunk->tracker);
    }
    return status;
}

static NV_STATUS destroy_test_chunk(uvm_pmm_gpu_t *pmm, test_chunk_t *test_chunk, uvm_mem_t *verif_mem)
{
    uvm_push_t push;
    NV_STATUS status = NV_OK;
    uvm_gpu_address_t chunk_addr, verif_gpu_addr;
    NvU32 *verif_cpu_addr = uvm_mem_get_cpu_addr_kernel(verif_mem);
    uvm_gpu_chunk_t *chunk = test_chunk->chunk;
    uvm_chunk_size_t size = uvm_gpu_chunk_get_size(chunk);
    size_t i;

    UVM_ASSERT(verif_mem->size >= size);
    memset(verif_cpu_addr, 0, size);

    status = uvm_push_begin_acquire(pmm->gpu->channel_manager,
                                    UVM_CHANNEL_TYPE_GPU_TO_CPU,
                                    &test_chunk->tracker,
                                    &push,
                                    "GPU -> CPU chunk {%s, %u} expecting 0x%08x",
                                    uvm_pmm_gpu_memory_type_string(uvm_gpu_chunk_get_type(chunk)),
                                    uvm_gpu_chunk_get_size(chunk),
                                    test_chunk->pattern);
    TEST_NV_CHECK_GOTO(status, out);

    chunk_addr = uvm_gpu_address_physical(UVM_APERTURE_VID, chunk->address);
    verif_gpu_addr = uvm_mem_gpu_address_virtual_kernel(verif_mem, pmm->gpu);
    pmm->gpu->ce_hal->memcopy(&push, verif_gpu_addr, chunk_addr, size);

    TEST_NV_CHECK_GOTO(uvm_push_end_and_wait(&push), out);

    for (i = 0; i < size / sizeof(verif_cpu_addr[0]); i++) {
        if (verif_cpu_addr[i] != test_chunk->pattern) {
            UVM_TEST_PRINT("GPU chunk {%s, %u} expected pattern 0x%08x, but offset %zu is 0x%08x\n",
                           uvm_pmm_gpu_memory_type_string(uvm_gpu_chunk_get_type(chunk)),
                           uvm_gpu_chunk_get_size(chunk),
                           test_chunk->pattern,
                           i * sizeof(verif_cpu_addr[0]),
                           verif_cpu_addr[i]);
            status = NV_ERR_INVALID_STATE;
            goto out;
        }
    }

out:
    list_del(&test_chunk->node);
    uvm_pmm_gpu_free(pmm, chunk, &test_chunk->tracker);
    uvm_tracker_deinit(&test_chunk->tracker);
    return status;
}

static bool basic_test_should_free(basic_test_state_t *test_state)
{
    if (test_state->free_pattern == BASIC_TEST_FREE_PATTERN_IMMEDIATE)
        return true;

    return test_state->free_pattern == BASIC_TEST_FREE_PATTERN_EVERY_N &&
           (test_state->num_chunks_total % BASIC_TEST_FREE_EVERY_N) == 0;
}

static NV_STATUS basic_test_alloc(basic_test_state_t *test_state, uvm_chunk_size_t size)
{
    test_chunk_t *test_chunk;
    NvU32 pattern;
    NV_STATUS status = NV_OK;

    test_chunk = uvm_kvmalloc_zero(sizeof(*test_chunk));
    if (!test_chunk) {
        UVM_TEST_PRINT("Failed to allocate test_chunk\n");
        return NV_ERR_NO_MEMORY;
    }

    pattern = current->pid | (test_state->num_chunks_total << 16);

    status = init_test_chunk(test_state->va_space, test_state->pmm, test_chunk, test_state->type, size, pattern);
    if (status != NV_OK) {
        uvm_kvfree(test_chunk);
        return status;
    }

    list_add_tail(&test_chunk->node, &test_state->list);
    ++test_state->num_chunks_total;

    if (basic_test_should_free(test_state)) {
        test_chunk = list_first_entry(&test_state->list, test_chunk_t, node);
        status = destroy_test_chunk(test_state->pmm, test_chunk, test_state->verif_mem);
        uvm_kvfree(test_chunk);
    }

    return status;
}

static NV_STATUS basic_test_free_all(basic_test_state_t *test_state)
{
    test_chunk_t *test_chunk;
    NV_STATUS temp_status, status = NV_OK;

    while (!list_empty(&test_state->list)) {
        if (test_state->free_pattern == BASIC_TEST_FREE_PATTERN_ALL_REVERSE)
            test_chunk = list_last_entry(&test_state->list, test_chunk_t, node);
        else // Handles cleanup and BASIC_TEST_FREE_PATTERN_ALL_FORWARD
            test_chunk = list_first_entry(&test_state->list, test_chunk_t, node);

        temp_status = destroy_test_chunk(test_state->pmm, test_chunk, test_state->verif_mem);
        if (status == NV_OK)
            status = temp_status;

        uvm_kvfree(test_chunk);
    }

    return status;
}

// Try to allocate enough smaller chunks to fully fill the largest chunk, plus
// a little extra.
static size_t basic_test_num_allocations(uvm_chunk_size_t size)
{
    return (UVM_CHUNK_SIZE_MAX / size) + 1;
}

// - Allocate multiple chunks of all possible sizes and types using various
//   patterns
// - Write a unique value to each chunk
// - Free those chunks in various patterns, verifying the unique value
static NV_STATUS basic_test(uvm_va_space_t *va_space, uvm_gpu_t *gpu,
                            UvmTestPmmSanityMode mode)
{
    uvm_chunk_size_t size;
    uvm_chunk_sizes_mask_t chunk_sizes;
    basic_test_state_t test_state;
    NV_STATUS status = NV_OK; // Implicitly modified by TEST_NV_CHECK_GOTO
    size_t i;
    int first_memory_type, last_memory_type;
    int first_free_pattern, last_free_pattern;

    if (mode == UvmTestPmmSanityModeBasic) {
        first_memory_type = UVM_PMM_GPU_MEMORY_TYPE_USER;
        last_memory_type = UVM_PMM_GPU_MEMORY_TYPE_USER;

        first_free_pattern = BASIC_TEST_FREE_PATTERN_EVERY_N;
        last_free_pattern = BASIC_TEST_FREE_PATTERN_EVERY_N;
    }
    else {
        first_memory_type = 0;
        last_memory_type = UVM_PMM_GPU_MEMORY_TYPE_COUNT - 1;

        first_free_pattern = 0;
        last_free_pattern = BASIC_TEST_FREE_PATTERN_COUNT - 1;
    }

    // Note that we can't really test PMM in isolation, since even pushing work
    // to the GPU requires using PMM to create GPU page tables for the
    // pushbuffers. We could handle that in theory by forcing sysmem page
    // tables, but that would require re-allocating the entire GPU address
    // space.

    memset(&test_state, 0, sizeof(test_state));
    INIT_LIST_HEAD(&test_state.list);
    test_state.va_space = va_space;
    test_state.pmm = &gpu->pmm;
    MEM_NV_CHECK_RET(uvm_mem_alloc_sysmem_and_map_cpu_kernel(UVM_CHUNK_SIZE_MAX, &test_state.verif_mem, 0), NV_OK);
    TEST_NV_CHECK_GOTO(uvm_mem_map_gpu_kernel(test_state.verif_mem, gpu), out);

    for (test_state.type = first_memory_type; test_state.type <= last_memory_type; test_state.type++) {
        chunk_sizes = gpu->pmm.chunk_sizes[test_state.type];

        for (test_state.free_pattern = first_free_pattern;
             test_state.free_pattern <= last_free_pattern;
             test_state.free_pattern++) {

            // Outer loop over size, increasing
            size = uvm_chunk_find_first_size(chunk_sizes);
            for_each_chunk_size_from(size, chunk_sizes) {
                for (i = 0; i < basic_test_num_allocations(size); i++)
                    TEST_NV_CHECK_GOTO(basic_test_alloc(&test_state, size), out);
            }
            TEST_NV_CHECK_GOTO(basic_test_free_all(&test_state), out);

            // Outer loop over size, decreasing
            size = uvm_chunk_find_last_size(chunk_sizes);
            for_each_chunk_size_rev_from(size, chunk_sizes) {
                for (i = 0; i < basic_test_num_allocations(size); i++)
                    TEST_NV_CHECK_GOTO(basic_test_alloc(&test_state, size), out);
            }
            TEST_NV_CHECK_GOTO(basic_test_free_all(&test_state), out);

            // Inner loop over size, increasing
            for (i = 0; i < BASIC_TEST_STATIC_ALLOCATIONS; i++) {
                size = uvm_chunk_find_first_size(chunk_sizes);
                for_each_chunk_size_from(size, chunk_sizes)
                    TEST_NV_CHECK_GOTO(basic_test_alloc(&test_state, size), out);
            }
            TEST_NV_CHECK_GOTO(basic_test_free_all(&test_state), out);

            // Inner loop over size, decreasing
            for (i = 0; i < BASIC_TEST_STATIC_ALLOCATIONS; i++) {
                size = uvm_chunk_find_last_size(chunk_sizes);
                for_each_chunk_size_rev_from(size, chunk_sizes)
                    TEST_NV_CHECK_GOTO(basic_test_alloc(&test_state, size), out);
            }
            TEST_NV_CHECK_GOTO(basic_test_free_all(&test_state), out);
        }
    }

out:
    if (status != NV_OK)
        basic_test_free_all(&test_state);
    UVM_ASSERT(list_empty(&test_state.list));
    uvm_mem_free(test_state.verif_mem);
    return status;
}

static NV_STATUS get_subchunks_test(uvm_pmm_gpu_t *pmm,
                                    uvm_gpu_chunk_t *parent,
                                    uvm_gpu_chunk_t **expected_children,
                                    size_t num_children)
{
    uvm_gpu_chunk_t **subchunks = NULL;
    NV_STATUS status = NV_OK;
    size_t count, start_index, size = num_children * sizeof(subchunks[0]);

    subchunks = uvm_kvmalloc(size);
    if (!subchunks) {
        UVM_TEST_PRINT("Failed to allocate subchunks\n");
        return NV_ERR_NO_MEMORY;
    }

    // Verify all
    memset(subchunks, 0, size);
    TEST_CHECK_GOTO(uvm_pmm_gpu_get_subchunks(pmm, parent, 0, num_children, subchunks) == num_children, out);
    TEST_CHECK_GOTO(memcmp(expected_children, subchunks, num_children * sizeof(subchunks[0])) == 0, out);

    // Get first half
    count = num_children / 2;
    memset(subchunks, 0, size);
    TEST_CHECK_GOTO(uvm_pmm_gpu_get_subchunks(pmm, parent, 0, count, subchunks) == count, out);
    TEST_CHECK_GOTO(memcmp(expected_children, subchunks, count * sizeof(subchunks[0])) == 0, out);

    // Get second half, intentionally requesting more subchunks than available
    start_index = num_children / 2;
    count = num_children - start_index;
    memset(subchunks, 0, size);
    TEST_CHECK_GOTO(uvm_pmm_gpu_get_subchunks(pmm, parent, start_index, num_children, subchunks) == count, out);
    TEST_CHECK_GOTO(memcmp(&expected_children[start_index], subchunks, count * sizeof(subchunks[0])) == 0, out);

    // Larger-than-possible start_index
    TEST_CHECK_GOTO(uvm_pmm_gpu_get_subchunks(pmm, parent, num_children, 1, subchunks) == 0, out);

out:
    uvm_kvfree(subchunks);
    return status;
}

// Always frees parent chunk, even on error return
static NV_STATUS split_test_single(uvm_pmm_gpu_t *pmm,
                                   test_chunk_t *parent,
                                   uvm_chunk_size_t child_size,
                                   split_test_mode_t mode,
                                   uvm_mem_t *verif_mem)
{
    uvm_pmm_gpu_memory_type_t parent_type = uvm_gpu_chunk_get_type(parent->chunk);
    uvm_chunk_size_t parent_size = uvm_gpu_chunk_get_size(parent->chunk);
    NvU64 parent_addr = parent->chunk->address;
    size_t i, num_children = (size_t)(parent_size / child_size);
    uvm_gpu_chunk_t **split_chunks = NULL;
    uvm_gpu_chunk_t *temp_chunk;
    test_chunk_t child_wrapper;
    NV_STATUS temp_status, status = NV_OK;

    // Verify that we can get "subchunks" of a non-split chunk
    TEST_CHECK_RET(uvm_pmm_gpu_get_subchunks(pmm, parent->chunk, 0, 2, &temp_chunk) == 1);
    TEST_CHECK_RET(temp_chunk == parent->chunk);

    split_chunks = uvm_kvmalloc(num_children * sizeof(split_chunks[0]));
    if (!split_chunks) {
        UVM_TEST_PRINT("Failed to allocate split_chunks\n");
        status = NV_ERR_NO_MEMORY;
        goto error;
    }

    if (mode == SPLIT_TEST_MODE_INJECT_ERROR)
        uvm_gpu_chunk_set_inject_split_error(parent->chunk);

    status = uvm_pmm_gpu_split_chunk(pmm, parent->chunk, child_size, split_chunks);

    if (mode == SPLIT_TEST_MODE_INJECT_ERROR) {
        // This case verifies that a split failure will leave the chunk in its
        // original state.

        if (status != NV_ERR_NO_MEMORY) {
            UVM_TEST_PRINT("Injecting split error failed, returned %s\n", nvstatusToString(status));
            status = NV_ERR_INVALID_STATE;

            // Let the error label clean up the split children
            parent->chunk = NULL;
            goto error;
        }

        status = destroy_test_chunk(pmm, parent, verif_mem);
    }
    else {
        TEST_NV_CHECK_GOTO(status, error);

        temp_chunk = parent->chunk;
        parent->chunk = NULL;

        // Sanity check split
        for (i = 0; i < num_children; i++) {
            TEST_CHECK_GOTO(split_chunks[i], error);
            TEST_CHECK_GOTO(split_chunks[i]->address == parent_addr + i * child_size, error);
            TEST_CHECK_GOTO(split_chunks[i]->suballoc == NULL, error);
            TEST_CHECK_GOTO(uvm_gpu_chunk_get_type(split_chunks[i])  == parent_type, error);
            TEST_CHECK_GOTO(uvm_gpu_chunk_get_state(split_chunks[i]) == UVM_PMM_GPU_CHUNK_STATE_TEMP_PINNED, error);
            TEST_CHECK_GOTO(uvm_gpu_chunk_get_size(split_chunks[i])  == child_size, error);
        }

        status = get_subchunks_test(pmm, temp_chunk, split_chunks, num_children);
        if (status != NV_OK)
            goto error;

        if (mode == SPLIT_TEST_MODE_MERGE) {
            parent->chunk = temp_chunk;
            uvm_pmm_gpu_merge_chunk(pmm, parent->chunk);
            TEST_CHECK_GOTO(parent->chunk->address == parent_addr, error);
            TEST_CHECK_GOTO(parent->chunk->suballoc == NULL, error);
            TEST_CHECK_GOTO(uvm_gpu_chunk_get_state(parent->chunk) == UVM_PMM_GPU_CHUNK_STATE_TEMP_PINNED, error);
            status = destroy_test_chunk(pmm, parent, verif_mem);
        }
        else {
            // Destroy split chunks, verifying the original pattern
            for (i = 0; i < num_children; i++) {
                child_wrapper.chunk = split_chunks[i];
                child_wrapper.pattern = parent->pattern;
                temp_status = uvm_tracker_init_from(&child_wrapper.tracker, &parent->tracker);
                if (status == NV_OK)
                    status = temp_status;

                // destroy_test_chunk does list_del
                INIT_LIST_HEAD(&child_wrapper.node);

                temp_status = destroy_test_chunk(pmm, &child_wrapper, verif_mem);
                if (status == NV_OK)
                    status = temp_status;
            }

            uvm_tracker_deinit(&parent->tracker);
        }
    }

    uvm_kvfree(split_chunks);
    return status;

error:
    if (parent->chunk) {
        uvm_pmm_gpu_free(pmm, parent->chunk, &parent->tracker);
    }
    else {
        for (i = 0; i < num_children; i++)
            uvm_pmm_gpu_free(pmm, split_chunks[i], &parent->tracker);
    }

    uvm_kvfree(split_chunks);
    return status;
}

// Splits each possible non-leaf chunk size into all possible sizes below that
// size, and verifies that the data in the chunk remains intact.
static NV_STATUS split_test(uvm_va_space_t *va_space, uvm_gpu_t *gpu)
{
    uvm_pmm_gpu_memory_type_t type;
    uvm_chunk_size_t parent_size, child_size;
    NvU32 pattern;
    NvU32 count = 0;
    test_chunk_t parent_test_chunk;
    NV_STATUS status = NV_OK;
    uvm_mem_t *verif_mem = NULL;
    split_test_mode_t mode;

    // Check the num_subchunks == 0 case
    TEST_CHECK_RET(uvm_pmm_gpu_get_subchunks(&gpu->pmm, NULL, 0, 0, NULL) == 0);

    MEM_NV_CHECK_RET(uvm_mem_alloc_sysmem_and_map_cpu_kernel(UVM_CHUNK_SIZE_MAX, &verif_mem, 0), NV_OK);
    TEST_NV_CHECK_GOTO(uvm_mem_map_gpu_kernel(verif_mem, gpu), out);

    for (type = 0; type < UVM_PMM_GPU_MEMORY_TYPE_COUNT; type++) {
        // Test every available parent size except the smallest, which obviously
        // can't be split.
        parent_size = uvm_chunk_find_next_size(gpu->pmm.chunk_sizes[type],
                                               uvm_chunk_find_first_size(gpu->pmm.chunk_sizes[type]));

        for_each_chunk_size_from(parent_size, gpu->pmm.chunk_sizes[type]) {
            // Split from parent_size to every smaller supported size
            child_size = uvm_chunk_find_prev_size(gpu->pmm.chunk_sizes[type], parent_size);

            for_each_chunk_size_rev_from(child_size, gpu->pmm.chunk_sizes[type]) {

                for (mode = 0; mode < SPLIT_TEST_MODE_COUNT; mode++) {
                    pattern = current->pid | (count << 16);
                    ++count;

                    status = init_test_chunk(va_space, &gpu->pmm, &parent_test_chunk, type, parent_size, pattern);
                    if (status != NV_OK)
                        goto out;

                    status = split_test_single(&gpu->pmm, &parent_test_chunk, child_size, mode, verif_mem);
                    if (status != NV_OK)
                        goto out;
                }
            }
        }
    }

out:
    uvm_mem_free(verif_mem);
    return status;
}

NV_STATUS uvm8_test_pmm_query(UVM_TEST_PMM_QUERY_PARAMS *params, struct file *filp)
{
    NV_STATUS status = NV_OK;
    uvm_gpu_t *gpu;

    status = uvm_gpu_retain_by_uuid(&params->gpu_uuid, &gpu);
    if (status != NV_OK)
        return status;

    switch (params->key) {
        case UVM_TEST_CHUNK_SIZE_GET_USER_SIZE:
            params->value = gpu->pmm.chunk_sizes[UVM_PMM_GPU_MEMORY_TYPE_USER];
            status = NV_OK;
            break;
        default:
            status = NV_ERR_INVALID_ARGUMENT;
            break;
    }

    uvm_gpu_release(gpu);
    return status;
}

NV_STATUS uvm8_test_pmm_sanity(UVM_TEST_PMM_SANITY_PARAMS *params, struct file *filp)
{
    NV_STATUS status = NV_OK;
    uvm_va_space_t *va_space = uvm_va_space_get(filp);
    uvm_gpu_t *gpu;

    if (params->mode != UvmTestPmmSanityModeBasic &&
        params->mode != UvmTestPmmSanityModeFull) {
        return NV_ERR_INVALID_ARGUMENT;
    }

    uvm_va_space_down_read(va_space);

    for_each_va_space_gpu(gpu, va_space) {
        status = basic_test(va_space, gpu, params->mode);
        if (status != NV_OK)
            goto out;

        status = split_test(va_space, gpu);
        if (status != NV_OK)
            goto out;
    }

out:
    uvm_va_space_up_read(va_space);
    return status;
}

NV_STATUS uvm8_test_pmm_check_leak(UVM_TEST_PMM_CHECK_LEAK_PARAMS *params, struct file *filp)
{
    NV_STATUS status = NV_OK;
    uvm_gpu_t *gpu;

    if (params->alloc_limit < -1)
        return NV_ERR_INVALID_ARGUMENT;

    status = uvm_gpu_retain_by_uuid(&params->gpu_uuid, &gpu);
    if (status != NV_OK)
        return status;

    status = check_leak(gpu, params->chunk_size, params->alloc_limit, &params->allocated);

    uvm_gpu_release(gpu);
    return status;
}

NV_STATUS uvm8_test_pmm_async_alloc(UVM_TEST_PMM_ASYNC_ALLOC_PARAMS *params, struct file *filp)
{
    NV_STATUS status = NV_OK;
    NV_STATUS tracker_status = NV_OK;
    uvm_va_space_t *va_space = uvm_va_space_get(filp);
    uvm_gpu_chunk_t **chunks;
    uvm_chunk_size_t chunk_size = PAGE_SIZE;
    uvm_gpu_t *gpu, *work_gpu;
    uvm_mem_t *dummy_buffer = NULL;
    uvm_mem_alloc_params_t mem_params;
    uvm_tracker_t tracker = UVM_TRACKER_INIT();
    uvm_push_t push;
    NvU32 i;

    chunks = uvm_kvmalloc_zero(params->num_chunks * sizeof(chunks[0]));
    if (!chunks)
        return NV_ERR_NO_MEMORY;

    uvm_va_space_down_read(va_space);

    gpu = uvm_va_space_get_gpu_by_uuid(va_space, &params->gpu_uuid);
    if (!gpu) {
        status = NV_ERR_INVALID_DEVICE;
        goto out;
    }

    memset(&mem_params, 0, sizeof(mem_params));
    mem_params.backing_gpu = NULL;
    mem_params.size        = 1024*1024;
    status = uvm_mem_alloc(&mem_params, &dummy_buffer);
    if (status != NV_OK)
        goto out;
    status = uvm_mem_map_kernel(dummy_buffer, &va_space->registered_gpus);
    if (status != NV_OK)
        goto out;

    // Alloc lots of small chunks to trigger suballocation
    status = chunk_alloc_user_check(&gpu->pmm, params->num_chunks, chunk_size, UVM_PMM_ALLOC_FLAGS_NONE, chunks, &tracker);
    if (status != NV_OK)
        goto out;

    // Push long-running work on all GPUs and collect it all in the tracker
    for (i = 0; i < params->num_work_iterations; i++) {
        if (fatal_signal_pending(current)) {
            status = NV_ERR_SIGNAL_PENDING;
            goto out;
        }

        for_each_va_space_gpu(work_gpu, va_space) {
            // Acquire the prior iteration just to make things even slower
            status = uvm_push_begin_acquire(work_gpu->channel_manager,
                                            UVM_CHANNEL_TYPE_GPU_INTERNAL,
                                            &tracker,
                                            &push,
                                            "memset");
            if (status != NV_OK)
                goto out;

            work_gpu->ce_hal->memset_1(&push, uvm_mem_gpu_address_virtual_kernel(dummy_buffer, work_gpu), 0, mem_params.size);
            uvm_push_end(&push);

            status = uvm_tracker_add_push_safe(&tracker, &push);
            if (status != NV_OK)
                goto out;
        }
    }

    // Free every other chunk to keep the suballocation around
    for (i = 0; i < params->num_chunks; i += 2) {
        uvm_pmm_gpu_free(&gpu->pmm, chunks[i], &tracker);
        chunks[i] = NULL;
    }

    // Re-alloc chunks to verify that the returned trackers don't have work for
    // other GPUs (chunk_alloc_user_check() checks that).
    for (i = 0; i < params->num_chunks; i += 2) {
        status = chunk_alloc_user_check(&gpu->pmm, 1, chunk_size, UVM_PMM_ALLOC_FLAGS_NONE, &chunks[i], NULL);
        if (status != NV_OK)
            goto out;
    }

out:
    if (chunks) {
        for (i = 0; i < params->num_chunks; i++) {
            if (chunks[i])
                uvm_pmm_gpu_free(&gpu->pmm, chunks[i], &tracker);
        }
    }

    tracker_status = uvm_tracker_wait_deinit(&tracker);
    uvm_mem_free(dummy_buffer);
    uvm_va_space_up_read(va_space);
    uvm_kvfree(chunks);

    return status == NV_OK ? tracker_status : status;
}
