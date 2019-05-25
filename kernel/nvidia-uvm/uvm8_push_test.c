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

#include "uvm8_global.h"
#include "uvm8_channel.h"
#include "uvm8_hal.h"
#include "uvm8_mem.h"
#include "uvm8_push.h"
#include "uvm8_test.h"
#include "uvm8_test_rng.h"
#include "uvm8_thread_context.h"
#include "uvm8_va_space.h"
#include "uvm8_tracker.h"
#include "uvm8_gpu_semaphore.h"
#include "uvm8_kvmalloc.h"

// Verify that UVM_PUSH_END_SIZE is correct
static NV_STATUS test_push_end_size(uvm_va_space_t *va_space)
{
    NV_STATUS status = NV_OK;
    uvm_gpu_t *gpu;
    NvU32 push_size;
    NvU32 i;

    for_each_va_space_gpu(gpu, va_space) {
        for (i = 0; i < UVM_CHANNEL_TYPE_COUNT; ++i) {
            uvm_push_t push;
            uvm_channel_type_t type = i;
            status = uvm_push_begin(gpu->channel_manager, type, &push, "type %u\n", (unsigned)type);
            TEST_CHECK_GOTO(status == NV_OK, done);

            push_size = uvm_push_get_size(&push);
            uvm_push_end(&push);
            if (uvm_push_get_size(&push) - push_size != UVM_PUSH_END_SIZE) {
                UVM_TEST_PRINT("UVM_PUSH_END_SIZE incorrect, %u instead of %u for GPU %s\n",
                        uvm_push_get_size(&push) - push_size, UVM_PUSH_END_SIZE, gpu->name);
                status = NV_ERR_INVALID_STATE;
                goto done;
            }
        }
    }

done:
    for_each_va_space_gpu(gpu, va_space) {
        uvm_channel_manager_wait(gpu->channel_manager);
    }

    return status;
}

typedef enum {
    TEST_INLINE_ADD,
    TEST_INLINE_GET,
    TEST_INLINE_SINGLE_BUFFER,
    TEST_INLINE_MAX,
} test_inline_type_t;

static NV_STATUS test_push_inline_data_gpu(uvm_gpu_t *gpu)
{
    static const size_t test_sizes[] = { 1, 2, 3, 4, 8, 31, 32, 1023, 1024, 1025, UVM_PUSH_INLINE_DATA_MAX_SIZE };
    NV_STATUS status;
    int i, j;
    int test_inline_type;
    uvm_push_t push;
    uvm_mem_t *mem = NULL;
    char *verif;

    status = uvm_mem_alloc_sysmem_and_map_cpu_kernel(UVM_PUSH_INLINE_DATA_MAX_SIZE, &mem);
    TEST_CHECK_GOTO(status == NV_OK, done);

    status = uvm_mem_map_gpu_kernel(mem, gpu);
    TEST_CHECK_GOTO(status == NV_OK, done);

    verif = (char *)uvm_mem_get_cpu_addr_kernel(mem);

    for (test_inline_type = 0; test_inline_type < TEST_INLINE_MAX; ++test_inline_type) {
        for (i = 0; i < ARRAY_SIZE(test_sizes); ++i) {
            size_t test_size = test_sizes[i];
            uvm_push_inline_data_t data;
            size_t inline_data_size = 0;
            uvm_gpu_address_t data_gpu_address;
            char *inline_buf;

            status = uvm_push_begin(gpu->channel_manager, UVM_CHANNEL_TYPE_GPU_INTERNAL, &push, "Inline data size %zu", test_size);
            TEST_CHECK_GOTO(status == NV_OK, done);

            // Do a noop first to test inline data starting at different offsets
            gpu->host_hal->noop(&push, roundup(min(test_size, (size_t)4096), UVM_METHOD_SIZE));

            switch (test_inline_type) {
                case TEST_INLINE_ADD:
                    uvm_push_inline_data_begin(&push, &data);
                    for (j = 0; j < test_size; ++j) {
                        char value = 1 + i + j;
                        uvm_push_inline_data_add(&data, &value, 1);
                    }
                    inline_data_size = uvm_push_inline_data_size(&data);
                    data_gpu_address = uvm_push_inline_data_end(&data);
                    break;
                case TEST_INLINE_GET:
                    uvm_push_inline_data_begin(&push, &data);
                    inline_buf = (char*)uvm_push_inline_data_get(&data, test_size);
                    inline_data_size = uvm_push_inline_data_size(&data);
                    data_gpu_address = uvm_push_inline_data_end(&data);
                    for (j = 0; j < test_size; ++j)
                        inline_buf[j] = 1 + i + j;
                    break;
                case TEST_INLINE_SINGLE_BUFFER:
                    inline_buf = (char*)uvm_push_get_single_inline_buffer(&push, test_size, &data_gpu_address);
                    inline_data_size = test_size;
                    for (j = 0; j < test_size; ++j)
                        inline_buf[j] = 1 + i + j;
                    break;
            }


            gpu->ce_hal->memcopy(&push, uvm_mem_gpu_address_virtual_kernel(mem, gpu), data_gpu_address, test_size);
            status = uvm_push_end_and_wait(&push);
            TEST_CHECK_GOTO(status == NV_OK, done);

            TEST_CHECK_GOTO(inline_data_size == test_size, done);

            for (j = 0; j < test_size; ++j) {
                char expected = 1 + i + j;
                if (verif[j] != expected) {
                    UVM_TEST_PRINT("size %zu verif[%d] = %d instead of %d\n", test_size, j, verif[j], expected);
                    status = NV_ERR_INVALID_STATE;
                    goto done;
                }
            }
        }
    }
done:
    uvm_mem_free(mem);

    return status;
}

static NV_STATUS test_push_inline_data(uvm_va_space_t *va_space)
{
    uvm_gpu_t *gpu;

    for_each_va_space_gpu(gpu, va_space) {
        TEST_CHECK_RET(test_push_inline_data_gpu(gpu) == NV_OK);
    }

    return NV_OK;
}

// Test that begins UVM_PUSH_MAX_CONCURRENT_PUSHES number of pushes before
// ending any of them on each GPU.
// Notably starting more than a single push is not safe to do outside of a test
// as if multiple threads tried doing so, it could easily deadlock.
static NV_STATUS test_concurrent_pushes(uvm_va_space_t *va_space)
{
    NV_STATUS status = NV_OK;
    uvm_gpu_t *gpu;
    NvU32 i;
    uvm_push_t *pushes;
    uvm_tracker_t tracker = UVM_TRACKER_INIT();

    // As noted above, this test does unsafe things that would be detected by
    // lock tracking, opt-out.
    uvm_thread_context_disable_lock_tracking();

    pushes = uvm_kvmalloc_zero(sizeof(*pushes) * UVM_PUSH_MAX_CONCURRENT_PUSHES);
    if (pushes == NULL) {
        status = NV_ERR_NO_MEMORY;
        goto done;
    }

    for_each_va_space_gpu(gpu, va_space) {
        for (i = 0; i < UVM_PUSH_MAX_CONCURRENT_PUSHES; ++i) {
            uvm_push_t *push = &pushes[i];
            status = uvm_push_begin(gpu->channel_manager, UVM_CHANNEL_TYPE_CPU_TO_GPU, push, "concurrent push %u", i);
            TEST_CHECK_GOTO(status == NV_OK, done);
        }
        for (i = 0; i < UVM_PUSH_MAX_CONCURRENT_PUSHES; ++i) {
            uvm_push_t *push = &pushes[i];
            uvm_push_end(push);
            status = uvm_tracker_add_push(&tracker, push);
            TEST_CHECK_GOTO(status == NV_OK, done);
        }
        TEST_CHECK_GOTO(tracker.size != 0, done);

        status = uvm_tracker_wait(&tracker);
        TEST_CHECK_GOTO(status == NV_OK, done);
    }

done:
    uvm_thread_context_enable_lock_tracking();

    uvm_tracker_deinit(&tracker);

    uvm_kvfree(pushes);

    return status;
}

// Push exactly UVM_MAX_PUSH_SIZE methods while acquiring a semaphore
// This is very tightly coupled with the pushbuffer implementation and method
// sizes, which is not ideal, but allows to test corner cases in the pushbuffer
// management code.
static NV_STATUS test_push_exactly_max_push(uvm_gpu_t *gpu, uvm_push_t *push, uvm_gpu_semaphore_t *sema_to_acquire, NvU32 value)
{
    NV_STATUS status;

    status = uvm_push_begin(gpu->channel_manager, UVM_CHANNEL_TYPE_ANY, push, "Test push");
    if (status != NV_OK)
        return status;

    TEST_CHECK_RET(uvm_push_has_space(push, UVM_MAX_PUSH_SIZE));
    TEST_CHECK_RET(!uvm_push_has_space(push, UVM_MAX_PUSH_SIZE + 1));

    gpu->host_hal->semaphore_acquire(push, sema_to_acquire, value);

    // Push a noop leaving just UVM_PUSH_END_SIZE in the pushbuffer.
    gpu->host_hal->noop(push, UVM_MAX_PUSH_SIZE - uvm_push_get_size(push) - UVM_PUSH_END_SIZE);

    TEST_CHECK_RET(uvm_push_has_space(push, UVM_PUSH_END_SIZE));
    TEST_CHECK_RET(!uvm_push_has_space(push, UVM_PUSH_END_SIZE + 1));
    uvm_push_end(push);

    UVM_ASSERT_MSG(uvm_push_get_size(push) == UVM_MAX_PUSH_SIZE, "push_size %u\n", uvm_push_get_size(push));

    return NV_OK;
}

static NvU32 test_count_idle_chunks(uvm_pushbuffer_t *pushbuffer)
{
    NvU32 i;
    NvU32 count = 0;
    for (i = 0; i < UVM_PUSHBUFFER_CHUNKS; ++i)
        count += test_bit(i, pushbuffer->idle_chunks) ? 1 : 0;
    return count;
}

static NvU32 test_count_available_chunks(uvm_pushbuffer_t *pushbuffer)
{
    NvU32 i;
    NvU32 count = 0;
    for (i = 0; i < UVM_PUSHBUFFER_CHUNKS; ++i)
        count += test_bit(i, pushbuffer->available_chunks) ? 1 : 0;
    return count;
}

// Reuse the whole pushbuffer 4 times, one UVM_MAX_PUSH_SIZE at a time
#define EXTRA_MAX_PUSHES_WHILE_FULL (4 * UVM_PUSHBUFFER_SIZE / UVM_MAX_PUSH_SIZE)

// Test doing pushes of exactly UVM_MAX_PUSH_SIZE size and only allowing them to
// complete one by one.
static NV_STATUS test_max_pushes_on_gpu(uvm_gpu_t *gpu)
{
    NV_STATUS status;

    uvm_tracker_t tracker;
    uvm_gpu_semaphore_t sema;
    NvU32 total_push_size = 0;
    NvU32 push_count = 0;
    NvU32 i;

    uvm_tracker_init(&tracker);

    status = uvm_gpu_semaphore_alloc(gpu->semaphore_pool, &sema);
    TEST_CHECK_GOTO(status == NV_OK, done);

    uvm_gpu_semaphore_set_payload(&sema, 0);

    // Need to wait for all channels to completely idle so that the pushbuffer
    // is in completely idle state when we begin.
    status = uvm_channel_manager_wait(gpu->channel_manager);
    TEST_CHECK_GOTO(status == NV_OK, done);

    while (uvm_pushbuffer_has_space(gpu->channel_manager->pushbuffer)) {
        uvm_push_t push;

        ++push_count;

        status = test_push_exactly_max_push(gpu, &push, &sema, push_count);
        TEST_CHECK_GOTO(status == NV_OK, done);

        total_push_size += uvm_push_get_size(&push);
        uvm_tracker_add_push(&tracker, &push);
    }

    if (total_push_size != UVM_PUSHBUFFER_SIZE) {
        UVM_TEST_PRINT("Unexpected space in the pushbuffer, total push %u\n", total_push_size);
        uvm_pushbuffer_print(gpu->channel_manager->pushbuffer);
        status = NV_ERR_INVALID_STATE;
        goto done;
    }

    TEST_CHECK_GOTO(test_count_available_chunks(gpu->channel_manager->pushbuffer) == 0, done);
    TEST_CHECK_GOTO(test_count_idle_chunks(gpu->channel_manager->pushbuffer) == 0, done);

    for (i = 0; i < EXTRA_MAX_PUSHES_WHILE_FULL; ++i) {
        uvm_push_t push;

        // There should be no space for another push until the sema is
        // incremented. Incrementing the same allows a single push to complete
        // freeing exactly UVM_MAX_PUSH_SIZE space.
        if (uvm_pushbuffer_has_space(gpu->channel_manager->pushbuffer)) {
            UVM_TEST_PRINT("Unexpected space in the pushbuffer for iter %d\n", i);
            uvm_pushbuffer_print(gpu->channel_manager->pushbuffer);
            status = NV_ERR_INVALID_STATE;
            goto done;
        }

        uvm_gpu_semaphore_set_payload(&sema, i + 1);

        ++push_count;

        // Take UVM_MAX_PUSH_SIZE space. This should leave no space left again.
        status = test_push_exactly_max_push(gpu, &push, &sema, push_count);
        TEST_CHECK_GOTO(status == NV_OK, done);

        status = uvm_tracker_add_push(&tracker, &push);
        TEST_CHECK_GOTO(status == NV_OK, done);
    }

done:
    uvm_gpu_semaphore_set_payload(&sema, push_count);
    uvm_tracker_wait_deinit(&tracker);

    uvm_gpu_semaphore_free(&sema);

    return status;
}


// Test doing UVM_PUSHBUFFER_CHUNKS independent pushes expecting each one to use
// a different chunk in the pushbuffer.
static NV_STATUS test_idle_chunks_on_gpu(uvm_gpu_t *gpu)
{
    NV_STATUS status;

    uvm_gpu_semaphore_t sema;
    uvm_tracker_t tracker = UVM_TRACKER_INIT();
    NvU32 i;

    uvm_tracker_init(&tracker);

    status = uvm_gpu_semaphore_alloc(gpu->semaphore_pool, &sema);
    TEST_CHECK_GOTO(status == NV_OK, done);

    uvm_gpu_semaphore_set_payload(&sema, 0);

    // Need to wait for all channels to completely idle so that the pushbuffer
    // is in completely idle state when we begin.
    status = uvm_channel_manager_wait(gpu->channel_manager);
    TEST_CHECK_GOTO(status == NV_OK, done);

    for (i = 0; i < UVM_PUSHBUFFER_CHUNKS; ++i) {
        uvm_push_t push;
        status = uvm_push_begin(gpu->channel_manager, UVM_CHANNEL_TYPE_ANY, &push, "Push using chunk %u", i);
        TEST_CHECK_GOTO(status == NV_OK, done);

        gpu->host_hal->semaphore_acquire(&push, &sema, i + 1);
        uvm_push_end(&push);

        uvm_tracker_add_push(&tracker, &push);

        if (test_count_idle_chunks(gpu->channel_manager->pushbuffer) != UVM_PUSHBUFFER_CHUNKS - i - 1) {
            UVM_TEST_PRINT("Unexpected count of idle chunks in the pushbuffer %u instead of %u\n",
                    test_count_idle_chunks(gpu->channel_manager->pushbuffer), UVM_PUSHBUFFER_CHUNKS - i - 1);
            uvm_pushbuffer_print(gpu->channel_manager->pushbuffer);
            status = NV_ERR_INVALID_STATE;
            goto done;
        }
    }
    uvm_gpu_semaphore_set_payload(&sema, UVM_PUSHBUFFER_CHUNKS + 1);

    status = uvm_channel_manager_wait(gpu->channel_manager);
    TEST_CHECK_GOTO(status == NV_OK, done);

    if (test_count_idle_chunks(gpu->channel_manager->pushbuffer) != UVM_PUSHBUFFER_CHUNKS) {
        UVM_TEST_PRINT("Unexpected count of idle chunks in the pushbuffer %u\n", test_count_idle_chunks(gpu->channel_manager->pushbuffer));
        uvm_pushbuffer_print(gpu->channel_manager->pushbuffer);
        status = NV_ERR_INVALID_STATE;
        goto done;
    }

done:
    uvm_gpu_semaphore_set_payload(&sema, UVM_PUSHBUFFER_CHUNKS + 1);
    uvm_tracker_wait(&tracker);

    uvm_gpu_semaphore_free(&sema);
    uvm_tracker_deinit(&tracker);

    return status;
}

static NV_STATUS test_pushbuffer(void)
{
    uvm_gpu_t *gpu;

    for_each_global_gpu(gpu) {
        TEST_CHECK_RET(test_max_pushes_on_gpu(gpu) == NV_OK);
        TEST_CHECK_RET(test_idle_chunks_on_gpu(gpu) == NV_OK);
    }
    return NV_OK;
}

typedef struct
{
    NvU64 *timestmap_in_pushbuffer;
    NvU64 timestamp;
} timestamp_test_t;

void timestamp_on_complete(void *void_data)
{
    timestamp_test_t *data = (timestamp_test_t *)void_data;

    if (uvm_global_get_status() != NV_OK) {
        // Do nothing if a global error has been set as the callback might be
        // called from teardown where the reference to test data is no longer
        // valid.
        return;
    }

    data->timestamp = *data->timestmap_in_pushbuffer;
}

static NV_STATUS test_timestamp_on_gpu(uvm_gpu_t *gpu)
{
    NV_STATUS status;
    uvm_push_t push;
    timestamp_test_t test_data = {0};
    NvU32 i;
    NvU64 last_stamp = 0;

    for (i = 0; i < 10; ++i) {
        status = uvm_push_begin(gpu->channel_manager, UVM_CHANNEL_TYPE_GPU_INTERNAL, &push, "Releasing a timestamp");
        if (status != NV_OK)
            return status;

        test_data.timestmap_in_pushbuffer = uvm_push_timestamp(&push);
        uvm_push_info_from_push(&push)->on_complete = timestamp_on_complete;
        uvm_push_info_from_push(&push)->on_complete_data = &test_data;
        uvm_push_end(&push);

        // Synchronize the channel manager to make sure the on_complete
        // callbacks have a chance to run.
        status = uvm_channel_manager_wait(gpu->channel_manager);
        TEST_CHECK_RET(status == NV_OK);

        TEST_CHECK_RET(test_data.timestamp != 0);
        TEST_CHECK_RET(test_data.timestamp > last_stamp);
        last_stamp = test_data.timestamp;
    }

    return NV_OK;
}

static NV_STATUS test_timestamp(void)
{
    uvm_gpu_t *gpu;

    for_each_global_gpu(gpu)
        TEST_CHECK_RET(test_timestamp_on_gpu(gpu) == NV_OK);

    return NV_OK;
}

NV_STATUS uvm8_test_push_sanity(UVM_TEST_PUSH_SANITY_PARAMS *params, struct file *filp)
{
    NV_STATUS status;
    uvm_va_space_t *va_space = uvm_va_space_get(filp);

    // Take the global lock as some of the tests rely on being the
    // only thread doing pushes and could deadlock otherwise.
    uvm_mutex_lock(&g_uvm_global.global_lock);
    uvm_va_space_down_read_rm(va_space);

    status = test_push_end_size(va_space);
    if (status != NV_OK)
        goto done;

    status = test_push_inline_data(va_space);
    if (status != NV_OK)
        goto done;

    status = test_concurrent_pushes(va_space);
    if (status != NV_OK)
        goto done;

    status = test_pushbuffer();
    if (status != NV_OK)
        goto done;

    status = test_timestamp();
    if (status != NV_OK)
        goto done;

done:
    uvm_va_space_up_read_rm(va_space);
    uvm_mutex_unlock(&g_uvm_global.global_lock);

    return status;
}
