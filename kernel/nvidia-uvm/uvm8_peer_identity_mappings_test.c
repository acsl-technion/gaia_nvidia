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

#include "uvm8_test.h"
#include "uvm8_va_space.h"
#include "uvm8_mem.h"
#include "uvm8_push.h"
#include "uvm8_hal.h"

#define MEM_ALLOCATION_SIZE (4 * 1024 * 1024)

static NV_STATUS try_peer_access_remote_gpu_memory(uvm_gpu_t *local_gpu, uvm_gpu_t *peer_gpu)
{
    NV_STATUS status = NV_OK;
    uvm_mem_t *vidmem = NULL;
    uvm_mem_t *sysmem = NULL;
    uvm_push_t push;
    uvm_gpu_address_t local_gpu_sysmem = {0};
    uvm_gpu_address_t peer_gpu_sysmem = {0};
    uvm_gpu_address_t peer_gpu_vidmem = {0};
    void *cpu_va = NULL;
    volatile NvU32 *cpu_array;
    NvU32 i;

    // allocate CPU memory
    status = uvm_mem_alloc_sysmem_and_map_cpu_kernel(MEM_ALLOCATION_SIZE, &sysmem);
    TEST_CHECK_GOTO(status == NV_OK, cleanup);

    // get CPU address
    cpu_va = uvm_mem_get_cpu_addr_kernel(sysmem);
    TEST_CHECK_GOTO(cpu_va != 0, cleanup);
    cpu_array = (volatile NvU32 *)cpu_va;

    // map sysmem to both GPUs
    status = uvm_mem_map_gpu_kernel(sysmem, local_gpu);
    TEST_CHECK_GOTO(status == NV_OK, cleanup);

    status = uvm_mem_map_gpu_kernel(sysmem, peer_gpu);
    TEST_CHECK_GOTO(status == NV_OK, cleanup);

     // get local GPU address for the sysmem
    local_gpu_sysmem = uvm_mem_gpu_address_virtual_kernel(sysmem, local_gpu);
    TEST_CHECK_GOTO(local_gpu_sysmem.address != 0, cleanup);

    peer_gpu_sysmem = uvm_mem_gpu_address_virtual_kernel(sysmem, peer_gpu);
    TEST_CHECK_GOTO(peer_gpu_sysmem.address != 0, cleanup);

    // allocate vidmem on remote GPU
    status = uvm_mem_alloc_vidmem(MEM_ALLOCATION_SIZE, peer_gpu, &vidmem);
    TEST_CHECK_GOTO(status == NV_OK, cleanup);
    TEST_CHECK_GOTO(IS_ALIGNED(MEM_ALLOCATION_SIZE, vidmem->chunk_size), cleanup);

    // map onto GPU
    status = uvm_mem_map_gpu_kernel(vidmem, peer_gpu);
    TEST_CHECK_GOTO(status == NV_OK, cleanup);

    // get remote GPU virtual address for its vidmem
    peer_gpu_vidmem = uvm_mem_gpu_address_virtual_kernel(vidmem, peer_gpu);
    TEST_CHECK_GOTO(status == NV_OK, cleanup);

    // initialize memory using CPU
    for (i = 0; i < MEM_ALLOCATION_SIZE / sizeof(NvU32); i++)
        cpu_array[i] = i;

    // copy sysmem to remote GPUs memory
    status = uvm_push_begin(peer_gpu->channel_manager,
                            UVM_CHANNEL_TYPE_CPU_TO_GPU,
                            &push,
                            "peer identity mapping test initialization");
    TEST_CHECK_GOTO(status == NV_OK, cleanup);
    peer_gpu->ce_hal->memcopy(&push, peer_gpu_vidmem, peer_gpu_sysmem, MEM_ALLOCATION_SIZE);
    status = uvm_push_end_and_wait(&push);
    TEST_CHECK_GOTO(status == NV_OK, cleanup);

    // set the sysmem back to zero
    memset((void *)cpu_array, '\0', MEM_ALLOCATION_SIZE);

    // use the peer mapping to copy back to sysmem
    status = uvm_push_begin(local_gpu->channel_manager,
                            UVM_CHANNEL_TYPE_GPU_TO_GPU,
                            &push,
                            "peer identity mapping test");
    TEST_CHECK_GOTO(status == NV_OK, cleanup);
    for (i = 0; i < MEM_ALLOCATION_SIZE / vidmem->chunk_size; i++) {
        uvm_gpu_phys_address_t remote_phys_addr = uvm_mem_gpu_physical(vidmem,
                                                                       peer_gpu,
                                                                       vidmem->chunk_size * i,
                                                                       vidmem->chunk_size);
        uvm_gpu_address_t local_gpu_peer = uvm_gpu_peer_memory_address(local_gpu, peer_gpu, remote_phys_addr);
        uvm_gpu_address_t local_gpu_sysmem_offset = local_gpu_sysmem;
        local_gpu_sysmem_offset.address += vidmem->chunk_size * i;
        local_gpu->ce_hal->memcopy(&push, local_gpu_sysmem_offset, local_gpu_peer, vidmem->chunk_size);
    }
    status = uvm_push_end_and_wait(&push);
    TEST_CHECK_GOTO(status == NV_OK, cleanup);

    for (i = 0; i < MEM_ALLOCATION_SIZE / sizeof(NvU32); i++) {
        if (cpu_array[i] != i) {
            UVM_TEST_PRINT("Expected %u at offset %u but got %u\n", i, i, cpu_array[i]);
            status = NV_ERR_INVALID_STATE;
        }
    }

cleanup:
    uvm_mem_free(vidmem);
    uvm_mem_free(sysmem);
    return status;
}

NV_STATUS uvm8_test_peer_identity_mappings(UVM_TEST_PEER_IDENTITY_MAPPINGS_PARAMS *params, struct file *filp)
{
    NV_STATUS status;
    uvm_gpu_t *gpu_a;
    uvm_gpu_t *gpu_b;
    uvm_va_space_t *va_space = uvm_va_space_get(filp);

    uvm_va_space_down_read(va_space);
    gpu_a = uvm_va_space_get_gpu_by_uuid(va_space, &params->gpuA);
    gpu_b = uvm_va_space_get_gpu_by_uuid(va_space, &params->gpuB);

    if (gpu_a == NULL || gpu_b == NULL) {
        status = NV_ERR_INVALID_DEVICE;
        goto done;
    }

    if (!gpu_a->peer_identity_mappings_supported || !gpu_b->peer_identity_mappings_supported) {
        status = NV_WARN_NOTHING_TO_DO;
        goto done;
    }

    status = try_peer_access_remote_gpu_memory(gpu_a, gpu_b);
    if (status != NV_OK)
        goto done;

    status = try_peer_access_remote_gpu_memory(gpu_b, gpu_a);
    if (status != NV_OK)
        goto done;
done:
    uvm_va_space_up_read(va_space);
    return status;
}
