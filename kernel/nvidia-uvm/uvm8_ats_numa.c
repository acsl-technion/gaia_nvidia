/*******************************************************************************
    Copyright (c) 2015, 2016 NVIDIA Corporation

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

#include "nv_uvm_interface.h"
#include "uvm8_api.h"
#include "uvm8_ats_numa.h"
#include "uvm8_global.h"
#include "uvm8_gpu.h"
#include "uvm8_gpu_replayable_faults.h"
#include "uvm8_hal.h"
#include "uvm8_pmm_gpu.h"
#include "uvm8_va_space.h"
#include "uvm_common.h"
#include "uvm_linux.h"

// -----------------------------------------------------------------------------
// TODO: fix these to use conftest.sh protection, and move into uvm_linux.h.
// Better yet, avoid accessing the filesystem from kernel mode entirely (in
// other words, fix bug 1735381), and then this entire section becomes
// unnecessary.

#ifndef NV_ITERATE_DIR_PRESENT
    struct dir_context {
        const filldir_t actor;
        loff_t pos;
    };
    static int iterate_dir(struct file *filp, struct dir_context *ctx)
    {
        UVM_PANIC();
        return 0;
    }
#endif

#ifndef NV_STRNSTR_PRESENT
    static char *strnstr(const char *s1, const char *s2, size_t len)
    {
        return NULL;
    }
#endif

#ifndef NV_KERNEL_WRITE_PRESENT
    static size_t kernel_write(struct file *filp, const char *str, size_t len,
                                loff_t offset)
    {
        return 0;
    }
#endif

#ifndef NV_KSTRTOULL_PRESENT
    static int kstrtoull(const char *s, unsigned int base,
                         unsigned long long *res)
    {
        return 0;
    }
#endif
// end of TODO -----------------------------------------------------------------

// -----------------------------------------------------------------------------
// TODO: fix bug 1735381, and don't do any of this stuff in kernel space:
#define NID_ARG_FMT            "hotpluggable_nodes="

#define NID_PATH               "/sys/devices/system/node/node"
#define MEMBLOCK_PREFIX        "memory"
#define MEMBLOCK_STATE_ATTR    "state"
#define BRING_ONLINE_CMD       "online_movable"
#define BRING_OFFLINE_CMD      "offline"
#define STATE_ONLINE           "online"
#define MEMBLK_SIZE_PATH       "/sys/devices/system/memory/block_size_bytes"
#define MEMORY_PROBE_PATH      "/sys/devices/system/memory/probe"
#define READ_BUFFER_SIZE           100
#define BUF_SIZE                   100
#define BUF_FOR_64BIT_INTEGER_SIZE 20
// end of TODO -----------------------------------------------------------------

typedef enum {
    MEM_ONLINE,
    MEM_OFFLINE
} mem_state_t;

typedef struct struct_uvm_dir_context
{
    struct dir_context ctx;
    int numa_node_id;
    NvU64 memblock_start_id;
    NvU64 memblock_end_id;
} uvm_dir_context_t;

static inline char* mem_state_to_string(mem_state_t state)
{
    switch (state) {
        case MEM_ONLINE:
            return "online";
        case MEM_OFFLINE:
            return "offline";
        default:
            return "invalid_state";
    }
}

// TODO: Bug 1735381: don't open files from within kernel code
static NV_STATUS bad_idea_read_string_from_file(const char *path_to_file,
                                                char *read_buffer,
                                                size_t read_buffer_size)
{
    struct file *filp;
    int read_count;

    filp = filp_open(path_to_file, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        UVM_ERR_PRINT("filp_open failed\n");
        return errno_to_nv_status(PTR_ERR(filp));
    }

    read_count = kernel_read(filp, 0, read_buffer, read_buffer_size - 1);

    filp_close(filp, NULL);

    if (read_count == 0)
        return NV_ERR_INVALID_STATE;
    else if (read_count < 0)
        return errno_to_nv_status(read_count);

    read_buffer[read_count] = '\0';

    // read_count > 0:
    return NV_OK;
}

// TODO: Bug 1735381: don't open files from within kernel code
static NV_STATUS bad_idea_write_string_to_file(const char *path_to_file,
                                               const char *write_buffer,
                                               size_t write_buffer_size)
{
    struct file *filp;
    int write_count;

    filp = filp_open(path_to_file, O_WRONLY, 0);
    if (IS_ERR(filp)) {
        UVM_ERR_PRINT("filp_open failed\n");
        return errno_to_nv_status(PTR_ERR(filp));
    }

    write_count = kernel_write(filp, write_buffer, write_buffer_size, 0);

    filp_close(filp, NULL);

    if ((write_count > 0) && (write_count < write_buffer_size))
        return NV_ERR_INVALID_STATE;
    else if (write_count < 0)
        return errno_to_nv_status(write_count);

    // write_count == write_buffer_size:
    return NV_OK;
}

// Reads a number from a file, and interprets it as a hexadecimal value, even
// though there is typically not any "0x" prefix.
static NV_STATUS bad_idea_read_hex_integer_from_file(const char *path_to_file,
                                                     NvU64 *read_value)
{
    NV_STATUS status;
    char buf[READ_BUFFER_SIZE];

    status = bad_idea_read_string_from_file(path_to_file, buf, sizeof(buf));
    if (status != NV_OK)
        return status;

    return errno_to_nv_status(kstrtoull(buf, 16, read_value));
}

static NV_STATUS read_memblock_size(NvU64 *memblock_size)
{
    // TODO: Bug 1735381: don't open files from within kernel code. In this
    // case, the kernel put the information into sysfs in the first place.
    // Therefore (unless GPL is a problem?), it seems unnecessary to go all the
    // way back through a user-space code path (accessing the sysfs pseudo
    // filesystem), to get that same information.

    return bad_idea_read_hex_integer_from_file(MEMBLK_SIZE_PATH, memblock_size);
}

// This is a callback for iterate_dir. The callback records the range of memory
// block IDs assigned to this NUMA node. The return values are Linux kernel
// errno values, because the caller is Linux's iterate_dir() routine.
static int filldir_get_memblock_id(struct dir_context *ctx,
                                   const char *name,
                                   int name_len,
                                   loff_t offset,
                                   u64 ino,
                                   unsigned int d_type)
{
    uvm_dir_context_t *ats_ctx = container_of(ctx, uvm_dir_context_t, ctx);
    char name_copy[BUF_SIZE];
    NvU64 memblock_id = 0;

    // Check if this is a memory node
    if (!strnstr(name, "memory", name_len))
        return 0;

    if (name_len + 1 > BUF_SIZE)
        return -ERANGE;

    strncpy(name_copy, name, name_len);
    *(name_copy + name_len) = '\0';

    // Convert the memory block ID into an integer
    if (kstrtoull(name_copy + strlen(MEMBLOCK_PREFIX), 0, &memblock_id) != 0) {
        UVM_ERR_PRINT("memblock_id parsing failed. Path: %s\n", name_copy);
        return -ERANGE;
    }

    UVM_DBG_PRINT("Found memblock entry %llu\n", memblock_id);

    // Record the smallest and largest assigned memblock IDs
    ats_ctx->memblock_start_id = min(ats_ctx->memblock_start_id, memblock_id);
    ats_ctx->memblock_end_id = max(ats_ctx->memblock_end_id, memblock_id);

    return 0;
}

// Brings memory block online using the sysfs memory-hotplug interface
//   https://www.kernel.org/doc/Documentation/memory-hotplug.txt
//
// Note, since we don't currently offline memory on driver unload this routine
// silently ignores requests when the existing memblock state matches the desired
// state.
static NV_STATUS change_memblock_state(int numa_node_id, int mem_block_id, mem_state_t new_state)
{
    NV_STATUS status;
    char numa_file_path[BUF_SIZE];
    char buf[BUF_SIZE];
    mem_state_t cur_state;
    const char *cmd;

    sprintf(numa_file_path, "%s%d/%s%d/%s", NID_PATH, numa_node_id, MEMBLOCK_PREFIX,
            mem_block_id, MEMBLOCK_STATE_ATTR);

    status = bad_idea_read_string_from_file(numa_file_path, buf, sizeof(buf));
    if (status != NV_OK)
        goto done;

    cur_state = !!strstr(buf, STATE_ONLINE) ? MEM_ONLINE : MEM_OFFLINE;

    if (cur_state == new_state)
        goto done;

    switch (new_state) {
        case MEM_ONLINE:
            cmd = BRING_ONLINE_CMD;
            break;
        case MEM_OFFLINE:
            cmd = BRING_OFFLINE_CMD;
            break;
        default:
            return NV_ERR_INVALID_ARGUMENT;
    }

    status = bad_idea_write_string_to_file(numa_file_path, cmd, strlen(cmd));

done:
    if (status == NV_OK)
        UVM_DBG_PRINT("Successfully changed state of %s to %s\n", numa_file_path,
                      mem_state_to_string(new_state));
    else
        UVM_ERR_PRINT("Changing state of %s to %s failed: %s\n",
                      numa_file_path, mem_state_to_string(new_state),
                      nvstatusToString(status));

    return status;
}

// Looks through NUMA nodes, finding the upper and lower bounds, and returns those.
// The assumption is that the nodes are physically contiguous, so that the intervening
// nodes do not need to be explicitly returned.
static NV_STATUS gather_memblock_ids_for_node(uvm_gpu_t *gpu,
                                              NvU64 *memblock_start_id,
                                              NvU64 *memblock_end_id)
{
    char numa_file_path[BUF_SIZE];
    struct file *filp;
    int err;
    uvm_dir_context_t ats_ctx = { .ctx.actor = (filldir_t)filldir_get_memblock_id };

    memset(numa_file_path, 0, sizeof(numa_file_path));
    sprintf(numa_file_path, "%s%d", NID_PATH, gpu->numa_info.node_id);

    // TODO: Bug 1735381: don't open files from within kernel code.
    filp = filp_open(numa_file_path, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        UVM_ERR_PRINT("filp_open failed\n");
        return errno_to_nv_status(PTR_ERR(filp));
    }

    ats_ctx.memblock_start_id = ULLONG_MAX;
    ats_ctx.memblock_end_id = 0;
    ats_ctx.numa_node_id = gpu->numa_info.node_id;

    err = iterate_dir(filp, &ats_ctx.ctx);

    filp_close(filp, NULL);

    if (err != 0) {
        UVM_DBG_PRINT("iterate_dir(path: %s) failed: %d\n", numa_file_path, err);
        return errno_to_nv_status(err);
    }

    // If the wrong directory was specified, iterate_dir can return success,
    // even though it never iterated any files in the directory. Make that case
    // also an error, by verifying that ats_ctx.memblock_start_id has been set.
    if (ats_ctx.memblock_start_id == ULLONG_MAX) {
        UVM_DBG_PRINT("Failed to find any files in: %s\n", numa_file_path);
        return NV_ERR_NO_VALID_PATH;
    }

    *memblock_start_id = ats_ctx.memblock_start_id;
    *memblock_end_id = ats_ctx.memblock_end_id;

    return NV_OK;
}

static NV_STATUS change_numa_node_state(uvm_gpu_t *gpu, mem_state_t new_state)
{
    NV_STATUS status;
    NvU64 mem_begin, mem_end;
    NvU64 memblock_begin, memblock_end, memblock_id;
    NvU64 memblock_size = gpu->numa_info.memblock_size;
    NvU64 memblock_start_id = 0;
    NvU64 memblock_end_id = 0;
    NvU64 blocks_changed = 0;

    status = gather_memblock_ids_for_node(gpu, &memblock_start_id, &memblock_end_id);
    if (status != NV_OK)
        return status;
    if (memblock_start_id > memblock_end_id)
        return NV_ERR_OPERATING_SYSTEM;

    UVM_DBG_PRINT("memblock ID range: %llu-%llu, memblock size: 0x%llx\n",
                  memblock_start_id, memblock_end_id, memblock_size);

    mem_begin = gpu->numa_info.region_gpu_addr;
    mem_end   = mem_begin + gpu->numa_info.region_gpu_size;

    UVM_DBG_PRINT("GPU memory begin-end: 0x%llx-0x%llx\n", mem_begin, mem_end);
    UVM_ASSERT(IS_ALIGNED(mem_begin, memblock_size));
    UVM_ASSERT(IS_ALIGNED(mem_end, memblock_size));

    if (new_state == MEM_ONLINE) {
        // Online ALL memblocks backwards first to allow placement into zone movable
        // Issue discussed here: https://patchwork.kernel.org/patch/9625081/
        memblock_id = memblock_end_id;
        do {
            status = change_memblock_state(gpu->numa_info.node_id, memblock_id, new_state);
            if (status == NV_OK)
                blocks_changed++;
        } while (memblock_id-- > memblock_start_id);

        // Now that all memory is in zone movable, OFFLINE memblocks that fall
        // outside of our RESERVED memory range.
        //
        // This is done to avoid the kernel allocating VIDMEM that is managed by
        // RM. Note, since we can only manage memory at memblock granularity offline
        // any memblocks that are only partially covered by the RM reserved memory.
        memblock_id = memblock_start_id;
        do {
           memblock_begin = (memblock_id - memblock_start_id) * memblock_size;
           memblock_end = memblock_begin + memblock_size - 1;
           if ((memblock_begin < mem_begin) || (memblock_end > mem_end)) {
                status = change_memblock_state(gpu->numa_info.node_id, memblock_id, MEM_OFFLINE);
                // Memory onlining _should_ not fail here, however it is possible and
                // has been encountered before.
                //
                // Since this is HW verif-only code, fail hard here to avoid continuing and
                // allocating memory that should not be owned by the system allocator
                // leave the node memory as-is to allow debug post failure.
                if (status != NV_OK) {
                    UVM_ASSERT(0);
                    return status;
                }
                blocks_changed--;
           }
        } while (memblock_id++ < memblock_end_id);
    }
    else if (new_state == MEM_OFFLINE) {
        memblock_id = memblock_start_id;
        do {
            status = change_memblock_state(gpu->numa_info.node_id, memblock_id, MEM_OFFLINE);
            // Ignore failures on the offline/driver unload path for now, it is possible to
            // fail and that case is not currently handled at all (e.g. should block driver unload)
            // Will be handled as part of Bug 1930447
            UVM_ASSERT(status == NV_OK);
            blocks_changed++;
        } while(memblock_id++ < memblock_end_id);
    }

    // Discard the status. Instead: if we got even one block changed, call it good enough
    // and return NV_OK.
    // TODO: figure out how to recover from "some, but not all requested blocks were
    // changed".
    if (blocks_changed * memblock_size < gpu->numa_info.region_gpu_size) {
        UVM_ERR_PRINT("Changing the state of some of the memory to %s failed: %s\n",
                      mem_state_to_string(new_state), nvstatusToString(status));
    }
    if (blocks_changed == 0)
        return NV_ERR_INSUFFICIENT_RESOURCES;

    return NV_OK;
}

static NV_STATUS probe_node_memory(uvm_gpu_t *gpu)
{
    NvBool should_probe = NV_FALSE;
    NvU64 ats_base_addr;
    NvU64 start_addr;
    NvU64 end_addr;
    NvU64 memblock_size = gpu->numa_info.memblock_size;
    char start_addr_str[BUF_SIZE];
    NV_STATUS status = NV_OK;

    status = uvm_rm_locked_call(nvUvmInterfaceGetExportedBaseAddr(&gpu->uuid, &ats_base_addr, &should_probe));
    if (status != NV_OK)
        return status;

    // We can safely skip memory probing on kernels where memory comes enabled
    // (e.g. pseudop9).
    if (!should_probe)
        return NV_OK;

    UVM_ASSERT(IS_ALIGNED(ats_base_addr, gpu->numa_info.memblock_size));

    end_addr = ats_base_addr + gpu->vidmem_size;

    for (start_addr = ats_base_addr;
         start_addr + memblock_size <= end_addr;
         start_addr += memblock_size) {
        sprintf(start_addr_str, "0x%llx", start_addr);

        UVM_INFO_PRINT("Probing memory address %s\n", start_addr_str);

        status = bad_idea_write_string_to_file(MEMORY_PROBE_PATH,
                                               start_addr_str,
                                               strlen(start_addr_str));

        // Checking if memory was already probed (e.g. in the previous invocation
        // of this function).
        if (status == errno_to_nv_status(EEXIST)) {
            status = NV_OK;
        }
        else if (status != NV_OK) {
            UVM_ERR_PRINT("Probing of memory address %s failed: %s\n",
                          start_addr_str,
                          nvstatusToString(status));
            goto done;
        }
    }
done:
    return status;
}

// TODO: support more than one GPU.
NV_STATUS uvm8_ats_numa_bring_mem_online(uvm_gpu_t *gpu)
{
    NV_STATUS status = NV_OK;
    NvU64 ats_page_count;
    UvmPmaAllocationOptions pma_options;

    UVM_ASSERT(gpu->numa_info.enabled);

    if (read_memblock_size(&gpu->numa_info.memblock_size))
        return NV_ERR_INVALID_STATE;

    status = probe_node_memory(gpu);
    if (status != NV_OK) {
        UVM_ERR_PRINT("Probing memory failed: %s\n", nvstatusToString(status));
        return status;
    }

    // Provide one-half of vidmem, to the ATS system. Hard-coded to use 2MB page
    // sizes, in the calculation.
    gpu->numa_info.region_gpu_size = UVM_ALIGN_DOWN(gpu->vidmem_size / 2,
                                                    gpu->numa_info.memblock_size);
    if (gpu->numa_info.region_gpu_size < gpu->numa_info.memblock_size)
        return NV_ERR_NO_MEMORY;

    // Report allocation size
    UVM_DBG_PRINT("Allocating 0x%llx for NUMA\n", gpu->numa_info.region_gpu_size);

    ats_page_count = gpu->numa_info.region_gpu_size / UVM_PAGE_SIZE_2M;

    memset(&pma_options, 0, sizeof(pma_options));
    pma_options.flags = UVM_PMA_ALLOCATE_PINNED     |
                        UVM_PMA_ALLOCATE_CONTIGUOUS |
                        UVM_PMA_ALLOCATE_DONT_EVICT |
                        UVM_PMA_ALLOCATE_FORCE_ALIGNMENT;

    pma_options.alignment = gpu->numa_info.memblock_size;

    status = nvUvmInterfacePmaAllocPages(gpu->pmm.pma,
                                         ats_page_count,
                                         UVM_PAGE_SIZE_2M,
                                         &pma_options,
                                         &gpu->numa_info.region_gpu_addr);
    if (status != NV_OK) {
        UVM_ERR_PRINT("nvUvmInterfacePmaAllocPages failed: %s\n", nvstatusToString(status));
        return status;
    }

    // Otherwise we'll have a memory leak.
    UVM_ASSERT(IS_ALIGNED(gpu->numa_info.region_gpu_addr, gpu->numa_info.memblock_size));

    status = change_numa_node_state(gpu, MEM_ONLINE);
    if (status != NV_OK)
        goto error;

    return status;

error:
    uvm8_ats_numa_put_mem_offline(gpu);
    return status;
}

void uvm8_ats_numa_put_mem_offline(uvm_gpu_t *gpu)
{
    NvU64 ats_page_count;

    // TODO: actually take the NUMA memory node offline. So far, we are only
    // free-ing memory, not really doing all that the function name implies.
    //
    // As it stands, attempting to take the NUMA memory node offline will
    // probably fail, because there's no guarantee that unplug will succeed,
    // even if the whole node belongs to ZONE_MOVABLE.

    ats_page_count = gpu->numa_info.region_gpu_size / UVM_PAGE_SIZE_2M;

    nvUvmInterfacePmaFreePages(gpu->pmm.pma,
                               &gpu->numa_info.region_gpu_addr,
                               ats_page_count,
                               UVM_PAGE_SIZE_2M,
                               UVM_PMA_ALLOCATE_CONTIGUOUS);
}
