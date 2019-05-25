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
#include "uvm8_test.h"
#include "uvm8_test_ioctl.h"
#include "uvm8_va_block.h"
#include "uvm8_va_space.h"
#include "uvm8_mmu.h"

static NV_STATUS test_chunk_index_range(NvU64 start, NvU64 size, uvm_gpu_t *gpu)
{
    size_t page_index, chunk_index, last_chunk_index = 0;
    uvm_chunk_size_t chunk_size, test_chunk_size;
    NvU64 addr, next_addr, outer_addr;

    if (fatal_signal_pending(current))
        return NV_ERR_SIGNAL_PENDING;

    outer_addr = start + size;

    for (addr = start; addr < outer_addr;) {
        page_index = (size_t)((addr - start) / PAGE_SIZE);

        chunk_index = uvm_va_block_gpu_chunk_index_range(start, size, gpu, page_index, &chunk_size);
        if (addr == start)
            TEST_CHECK_RET(chunk_index == 0);
        else
            TEST_CHECK_RET(chunk_index == last_chunk_index + 1);

        last_chunk_index = chunk_index;

        TEST_CHECK_RET(chunk_size >= PAGE_SIZE);
        TEST_CHECK_RET(IS_ALIGNED(addr, chunk_size));
        next_addr = addr + chunk_size;
        TEST_CHECK_RET(next_addr <= outer_addr);

        // Verify that this is the largest allowed chunk size
        for_each_chunk_size_rev(test_chunk_size, uvm_mmu_user_chunk_sizes(gpu)) {
            if (IS_ALIGNED(addr, test_chunk_size) && addr + test_chunk_size <= outer_addr) {
                TEST_CHECK_RET(test_chunk_size == chunk_size);
                break;
            }
        }

        // Check that every page covered by this chunk returns the same values
        for (addr += PAGE_SIZE; addr < next_addr; addr += PAGE_SIZE) {
            page_index = (size_t)((addr - start) / PAGE_SIZE);
            last_chunk_index = uvm_va_block_gpu_chunk_index_range(start, size, gpu, page_index, &test_chunk_size);
            TEST_CHECK_RET(last_chunk_index == chunk_index);
            TEST_CHECK_RET(test_chunk_size == chunk_size);
        }
    }

    return NV_OK;
}

static NV_STATUS test_chunk_index(uvm_gpu_t *gpu)
{
    size_t start_page, outer_page;
    NvU64 start;
    NV_STATUS status;

    // Fake a random address aligned to a block boundary
    start = 17*UVM_VA_BLOCK_SIZE;

    for (start_page = 0; start_page < PAGES_PER_UVM_VA_BLOCK; start_page++) {
        for (outer_page = start_page + 1; outer_page <= PAGES_PER_UVM_VA_BLOCK; outer_page++) {
            status = test_chunk_index_range(start + start_page * PAGE_SIZE, (outer_page - start_page) * PAGE_SIZE, gpu);
            if (status != NV_OK)
                return status;
        }
    }

    return NV_OK;
}

NV_STATUS uvm8_test_va_block(UVM_TEST_VA_BLOCK_PARAMS *params, struct file *filp)
{
    uvm_va_space_t *va_space = uvm_va_space_get(filp);
    uvm_gpu_t *gpu;
    NV_STATUS status = NV_OK;

    uvm_va_space_down_read(va_space);

    for_each_va_space_gpu(gpu, va_space)
        TEST_NV_CHECK_GOTO(test_chunk_index(gpu), out);

out:
    uvm_va_space_up_read(va_space);
    return status;
}
