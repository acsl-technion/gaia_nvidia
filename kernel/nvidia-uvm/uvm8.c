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

#include "uvm8_api.h"
#include "uvm8_global.h"
#include "uvm8_gpu_replayable_faults.h"
#include "uvm8_init.h"
#include "uvm8_tools_init.h"
#include "uvm8_lock.h"
#include "uvm8_test.h"
#include "uvm8_va_space.h"
#include "uvm8_va_range.h"
#include "uvm8_va_block.h"
#include "uvm8_tools.h"
#include "uvm_common.h"
#include "uvm_linux_ioctl.h"
#include "uvm8_hmm.h"
#include "uvm8_mem.h"

#include "/home/tanya/Linux4.4.115-UCM/include/linux/ucm.h"
#include <linux/list.h>


static struct cdev g_uvm_cdev;

static int uvm_open(struct inode *inode, struct file *filp)
{
    NV_STATUS status = uvm_global_get_status();
    if (status == NV_OK)
        status = uvm_va_space_create(inode, filp);

    return -nv_status_to_errno(status);
}

static int uvm_release(struct inode *inode, struct file *filp)
{
    uvm_va_space_destroy(filp);
//UCM_DBG("Enter\n");
    return -nv_status_to_errno(uvm_global_get_status());
}

static void uvm_destroy_vma_managed(struct vm_area_struct *vma, bool is_uvm_teardown)
{
    uvm_va_range_t *va_range, *va_range_next;
    NvU64 size = 0;

    uvm_assert_rwsem_locked_write(&uvm_va_space_get(vma->vm_file)->lock);
    uvm_for_each_va_range_in_vma_safe(va_range, va_range_next, vma) {
        // On exit_mmap (process teardown), current->mm is cleared so
        // uvm_va_range_vma_current would return NULL.
        UVM_ASSERT(uvm_va_range_vma(va_range) == vma);
        UVM_ASSERT(va_range->node.start >= vma->vm_start);
        UVM_ASSERT(va_range->node.end   <  vma->vm_end);
        size += uvm_va_range_size(va_range);
        if (is_uvm_teardown)
            uvm_va_range_zombify(va_range);
        else
            uvm_va_range_destroy(va_range, NULL);
    }

    if (vma->vm_private_data) {
        uvm_vma_wrapper_destroy(vma->vm_private_data);
        vma->vm_private_data = NULL;
    }
    UVM_ASSERT(size == vma->vm_end - vma->vm_start);
}

static void uvm_destroy_vma_semaphore_pool(struct vm_area_struct *vma)
{
    uvm_va_space_t *va_space;
    uvm_va_range_t *va_range;

    va_space = uvm_va_space_get(vma->vm_file);
    uvm_assert_rwsem_locked(&va_space->lock);
    va_range = uvm_va_range_find(va_space, vma->vm_start);
    UVM_ASSERT(va_range &&
               va_range->node.start   == vma->vm_start &&
               va_range->node.end + 1 == vma->vm_end &&
               va_range->type == UVM_VA_RANGE_TYPE_SEMAPHORE_POOL);
    uvm_mem_unmap_cpu(va_range->semaphore_pool.mem);
}

// If a fault handler is not set, paths like handle_pte_fault in older kernels
// assume the memory is anonymous. That would make debugging this failure harder
// so we force it to fail instead.
static int uvm_vm_fault_sigbus(struct vm_area_struct *vma, struct vm_fault *vmf)
{
    UVM_DBG_PRINT_RL("Fault to address 0x%lx in disabled vma\n", nv_page_fault_va(vmf));
    return VM_FAULT_SIGBUS;
}

static int uvm_vm_fault_sigbus_wrapper(struct vm_fault *vmf)
{
#if defined(NV_VM_OPS_FAULT_REMOVED_VMA_ARG)
    return uvm_vm_fault_sigbus(vmf->vma, vmf);
#else
    return uvm_vm_fault_sigbus(NULL, vmf);
#endif
}

static struct vm_operations_struct uvm_vm_ops_disabled =
{
#if defined(NV_VM_OPS_FAULT_REMOVED_VMA_ARG)
    .fault = uvm_vm_fault_sigbus_wrapper
#else
    .fault = uvm_vm_fault_sigbus
#endif
};

static void uvm_disable_vma(struct vm_area_struct *vma)
{
    // In the case of fork, the kernel has already copied the old PTEs over to
    // the child process, so an access in the child might succeed instead of
    // causing a fault. To force a fault we'll unmap it directly here.
    //
    // Note that since the unmap works on file offset, not virtual address, this
    // unmaps both the old and new vmas.
    //
    // In the case of a move (mremap), the kernel will copy the PTEs over later,
    // so it doesn't matter if we unmap here. However, the new vma's open will
    // immediately be followed by a close on the old vma. We call
    // unmap_mapping_range for the close, which also unmaps the new vma because
    // they have the same file offset.
    unmap_mapping_range(vma->vm_file->f_mapping,
                        vma->vm_pgoff << PAGE_SHIFT,
                        vma->vm_end - vma->vm_start,
                        1);

    vma->vm_ops = &uvm_vm_ops_disabled;

    if (vma->vm_private_data) {
        uvm_vma_wrapper_destroy(vma->vm_private_data);
        vma->vm_private_data = NULL;
    }
}

// We can't return an error from uvm_vm_open so on failed splits
// we'll disable *both* vmas. This isn't great behavior for the
// user, but we don't have many options. We could leave the old VA
// range in place but that breaks the model of vmas always
// completely covering VA ranges. We'd have to be very careful
// handling later splits and closes of both that partially-covered
// VA range, and of the vmas which might or might not cover it any
// more.
//
// A failure likely means we're in OOM territory, so this should not
// be common by any means, and the process might die anyway.
static void uvm_vm_open_failure(struct vm_area_struct *original,
                                struct vm_area_struct *new)
{
    uvm_va_space_t *va_space = uvm_va_space_get(new->vm_file);
    static const bool is_uvm_teardown = false;

    UVM_ASSERT(va_space == uvm_va_space_get(original->vm_file));
    uvm_assert_rwsem_locked_write(&va_space->lock);

    uvm_destroy_vma_managed(original, is_uvm_teardown);
    uvm_disable_vma(original);
    uvm_disable_vma(new);
}

// vm_ops->open cases:
//
// 1) Parent vma is dup'd (fork)
//    This is undefined behavior in the UVM Programming Model. For convenience
//    the parent will continue operating properly, but the child is not
//    guaranteed access to the range.
//
// 2) Original vma is split (munmap, mprotect, mremap, mbind, etc)
//    The UVM Programming Model supports mbind always and supports mprotect if
//    HMM is present. Supporting either of those means all such splitting cases
//    must be handled. This involves splitting the va_range covering the split
//    location. Note that the kernel will never merge us back on two counts: we
//    set VM_MIXEDMAP and we have a ->close callback.
//
// 3) Original vma is moved (mremap)
//    This is undefined behavior in the UVM Programming Model. We'll get an open
//    on the new vma in which we disable operations on the new vma, then a close
//    on the old vma.
//
// Note that since we set VM_DONTEXPAND on the vma we're guaranteed that the vma
// will never increase in size, only shrink/split.
static void uvm_vm_open_managed(struct vm_area_struct *vma)
{
    uvm_va_space_t *va_space = uvm_va_space_get(vma->vm_file);
    uvm_va_range_t *va_range;
    struct vm_area_struct *original;
    NV_STATUS status;
    NvU64 new_end;

    // This is slightly ugly. We need to know the parent vma of this new one,
    // but we can't use the range tree to look up the original because that
    // doesn't handle a vma move operation.
    //
    // However, all of the old vma's fields have been copied into the new vma,
    // and open of the new vma is always called before close of the old (in
    // cases where close will be called immediately afterwards, like move).
    // vma->vm_private_data will thus still point to the original vma that we
    // set in mmap or open.
    //
    // Things to watch out for here:
    // - For splits, the old vma hasn't been adjusted yet so its vm_start and
    //   vm_end region will overlap with this vma's start and end.
    //
    // - For splits and moves, the new vma has not yet been inserted into the
    //   mm's list so vma->vm_prev and vma->vm_next cannot be used, nor will
    //   the new vma show up in find_vma and friends.
    original = ((uvm_vma_wrapper_t*)vma->vm_private_data)->vma;
    vma->vm_private_data = NULL;
    // On fork or move we want to simply disable the new vma
    if (vma->vm_mm != original->vm_mm ||
        (vma->vm_start != original->vm_start && vma->vm_end != original->vm_end)) {
        uvm_disable_vma(vma);
        return;
    }

    // At this point we are guaranteed that the mmap_sem is held in write mode.
    uvm_record_lock_mmap_sem_write(&current->mm->mmap_sem);

    // Split vmas should always fall entirely within the old one, and be on one
    // side.
    UVM_ASSERT(vma->vm_start >= original->vm_start && vma->vm_end <= original->vm_end);
    UVM_ASSERT(vma->vm_start == original->vm_start || vma->vm_end == original->vm_end);

    // The vma is splitting, so create a new range under this vma if necessary.
    // The kernel handles splits in the middle of the vma by doing two separate
    // splits so we just have to handle one vma splitting in two here.
    if (vma->vm_start == original->vm_start)
        new_end = vma->vm_end - 1; // Left split (new_end is inclusive)
    else
        new_end = vma->vm_start - 1; // Right split (new_end is inclusive)

    uvm_va_space_down_write(va_space);

    vma->vm_private_data = uvm_vma_wrapper_alloc(vma);
    if (!vma->vm_private_data) {
        uvm_vm_open_failure(original, vma);
        goto out;
    }

    // There can be multiple va_ranges under the vma already. Check if one spans
    // the new split boundary. If so, split it.
    va_range = uvm_va_range_find(va_space, new_end);
    UVM_ASSERT(va_range);
    UVM_ASSERT(uvm_va_range_vma_current(va_range) == original);
    if (va_range->node.end != new_end) {
        status = uvm_va_range_split(va_range, new_end, NULL);
        if (status != NV_OK) {
            UVM_DBG_PRINT("Failed to split VA range, destroying both: %s. "
                          "original vma [0x%lx, 0x%lx) new vma [0x%lx, 0x%lx)\n",
                          nvstatusToString(status),
                          original->vm_start, original->vm_end,
                          vma->vm_start, vma->vm_end);
            uvm_vm_open_failure(original, vma);
            goto out;
        }
    }

    // Point va_ranges to the new vma
    uvm_for_each_va_range_in_vma(va_range, vma) {
        UVM_ASSERT(uvm_va_range_vma_current(va_range) == original);
        va_range->managed.vma_wrapper = vma->vm_private_data;
    }

out:
    uvm_va_space_up_write(va_space);
    uvm_record_unlock_mmap_sem_write(&current->mm->mmap_sem);
}

static void uvm_vm_close_managed(struct vm_area_struct *vma)
{
    uvm_va_space_t *va_space = uvm_va_space_get(vma->vm_file);
    uvm_gpu_t *gpu;
    bool is_uvm_teardown = false;
//UCM_DBG("Enter\n");
    if (current->mm != NULL)
        uvm_record_lock_mmap_sem_write(&current->mm->mmap_sem);

    if (current->mm == NULL) {
        // current->mm will be NULL on process teardown. In that case, we want
        // to stop all user channels before unmapping the managed allocations to
        // avoid spurious MMU faults in the system log. That involves making RM
        // calls, so we have to do that with the VA space lock in read mode.
        uvm_va_space_down_read_rm(va_space);
        is_uvm_teardown = va_space->initialization_flags & UVM_INIT_FLAGS_DISABLE_TEARDOWN_ON_PROCESS_EXIT;
        if (!is_uvm_teardown && !atomic_read(&va_space->user_channels_stopped))
            uvm_va_space_stop_all_user_channels(va_space);
        uvm_va_space_up_read_rm(va_space);
    }

    // See uvm_mmap for why we need this in addition to mmap_sem
    uvm_va_space_down_write(va_space);

    uvm_destroy_vma_managed(vma, is_uvm_teardown);

    // Notify GPU address spaces that the fault buffer needs to be flushed to avoid finding stale entries
    // that can be attributed to new VA ranges reallocated at the same address
    for_each_gpu_in_mask(gpu, &va_space->registered_gpu_va_spaces) {
        uvm_gpu_va_space_t *gpu_va_space = uvm_gpu_va_space_get(va_space, gpu);
        UVM_ASSERT(gpu_va_space);

        gpu_va_space->needs_fault_buffer_flush = true;
    }
    uvm_va_space_up_write(va_space);

    if (current->mm != NULL)
        uvm_record_unlock_mmap_sem_write(&current->mm->mmap_sem);
//    UCM_DBG("Done\n");
}

static int uvm_vm_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
    uvm_va_space_t *va_space = uvm_va_space_get(vma->vm_file);
    uvm_va_block_t *va_block;
    NvU64 fault_addr = nv_page_fault_va(vmf);
    bool is_write = vmf->flags & FAULT_FLAG_WRITE;
    NV_STATUS status = uvm_global_get_status();
    bool tools_enabled;
    uvm_processor_mask_t gpus_to_check_for_ecc;
    NvU64 cpu_wakeup_time_stamp = 0;

    if (status != NV_OK)
        goto convert_error;

    // The mmap_sem might be held in write mode, but the mode doesn't matter for
    // the purpose of lock ordering and we don't rely on it being in write
    // anywhere so just record it as read mode in all cases.
    uvm_record_lock_mmap_sem_read(&vma->vm_mm->mmap_sem);

    do {
        bool do_sleep = false;
        if (status == NV_WARN_MORE_PROCESSING_REQUIRED) {
            NvU64 now = NV_GETTIME();
            if (now < cpu_wakeup_time_stamp)
                do_sleep = true;

            if (do_sleep)
                uvm_tools_record_throttling_start(va_space, fault_addr, UVM_CPU_ID);

            // Drop the VA space lock while we sleep
            uvm_va_space_up_read(va_space);

            // usleep_range is preferred because msleep has a 20ms granularity
            // and udelay uses a busy-wait loop. usleep_range uses high-resolution
            // timers and, by adding a range, the Linux scheduler may coalesce
            // our wakeup with others, thus saving some interrupts.
            if (do_sleep) {
                unsigned long nap_us = (cpu_wakeup_time_stamp - now) / 1000;

                usleep_range(nap_us, nap_us + nap_us / 2);
            }
        }

        uvm_va_space_down_read(va_space);

        if (do_sleep)
            uvm_tools_record_throttling_end(va_space, fault_addr, UVM_CPU_ID);

        status = uvm_va_block_find_create(va_space, fault_addr, &va_block);
        if (status != NV_OK) {
            UVM_ASSERT_MSG(status == NV_ERR_NO_MEMORY, "status: %s\n", nvstatusToString(status));
            goto out;
        }

        // Watch out, current->mm might not be vma->vm_mm
        UVM_ASSERT(vma == uvm_va_range_vma(va_block->va_range));

        // Loop until thrashing goes away.
        status = uvm_va_block_cpu_fault(va_block, fault_addr, is_write, &gpus_to_check_for_ecc, &cpu_wakeup_time_stamp);
    } while (status == NV_WARN_MORE_PROCESSING_REQUIRED);

out:
    if (status != NV_OK) {
        UvmEventFatalReason reason;

        reason = uvm_tools_status_to_fatal_fault_reason(status);
        UVM_ASSERT(reason != UvmEventFatalReasonInvalid);

        uvm_tools_record_cpu_fatal_fault(va_space, fault_addr, is_write, reason);
    }

    tools_enabled = va_space->tools.enabled;

    if (status == NV_OK)
        uvm_gpu_retain_mask(&gpus_to_check_for_ecc);

    uvm_va_space_up_read(va_space);
    uvm_record_unlock_mmap_sem_read(&vma->vm_mm->mmap_sem);

    if (status == NV_OK) {
        uvm_gpu_t *gpu;
        for_each_gpu_in_mask(gpu, &gpus_to_check_for_ecc) {
            status = uvm_gpu_check_ecc_error(gpu);
            if (status != NV_OK)
                break;
        }
        uvm_gpu_release_mask(&gpus_to_check_for_ecc);
    }

    if (tools_enabled)
        uvm_tools_flush_events();

    // TODO: Bug 1766594: If we serviced this fault by migrating from the GPU,
    //       set ret |= VM_FAULT_MAJOR.

convert_error:
    switch (status) {
        case NV_OK:
            return VM_FAULT_NOPAGE;
        case NV_ERR_NO_MEMORY:
            return VM_FAULT_OOM;
        default:
            return VM_FAULT_SIGBUS;
    }
}

static int uvm_vm_fault_wrapper(struct vm_fault *vmf)
{
#if defined(NV_VM_OPS_FAULT_REMOVED_VMA_ARG)
    return uvm_vm_fault(vmf->vma, vmf);
#else
    return uvm_vm_fault(NULL, vmf);
#endif
}

static struct vm_operations_struct uvm_vm_ops_managed =
{
    .open         = uvm_vm_open_managed,
    .close        = uvm_vm_close_managed,

#if defined(NV_VM_OPS_FAULT_REMOVED_VMA_ARG)
    .fault        = uvm_vm_fault_wrapper,
    .page_mkwrite = uvm_vm_fault_wrapper,
#else
    .fault        = uvm_vm_fault,
    .page_mkwrite = uvm_vm_fault,
#endif
};

static struct file *uvm_vm_get_mmaped_file(struct vm_area_struct *vma, unsigned long start, unsigned long end)
{
	struct uvm_va_mappings_struct *map = uvm_get_cpu_mapping(get_shared_mem_va_space(), start, end); 

//	UCM_DBG("enter for virt_addr = 0x%llx\n", start);

	if (!map)
		return NULL;
	return map->cpu_vma->vm_file;
}

unsigned long int uvm_get_cpu_addr(struct vm_area_struct *vma, unsigned long start, unsigned long end)
{
	struct uvm_va_mappings_struct *map = uvm_get_cpu_mapping(get_shared_mem_va_space(), start, end); 

	if (!map)
		return 0;
//UCM_DBG("returning 0x%llx\n", map->cpu_vma->vm_start);
	return map->cpu_vma->vm_start;
}

static int uvm_vm_retrive_16cached_pages_multi_orig(unsigned long virt_addr, struct page *cpu_pages[])
{
	uvm_va_space_t *va_space = get_shared_mem_va_space();
	uvm_va_block_t *va_block;
	NV_STATUS status = NV_OK;
	int ret = 0, i;
	uvm_va_block_region_t block_region;
	uvm_va_block_context_t *block_context = uvm_va_block_context_alloc();
	//struct page *ucm_page;
	NvU64 page_index ;
	int num_pages = 16;

	uvm_mem_t dst_mem;

	if (!cpu_pages) {
		UCM_ERR("cpu_page = null\n");
		return 0;
	}
//UCM_DBG("Enter for virtaddr=0x%llx, num_pages = %d\n ", virt_addr, num_pages);
	if (!block_context) {
		UCM_ERR("cpublock_context = null\n");
		return 0;
	}

	uvm_va_space_down_read(va_space);
//	UCM_ERR("looking for a block\n");
	status = uvm_va_block_find(va_space, virt_addr, &va_block);
	if (status != NV_OK)
        goto out;

//	if (virt_addr + PAGE_SIZE * num_pages > va_block->end) {
//		UCM_ERR("Cant get %d pages from 0x%llx, block ends at 0x%llx\n", num_pages, virt_addr, va_block->end);
//		goto out;
//	}

	dst_mem.backing_gpu = NULL;
	dst_mem.chunk_size = PAGE_SIZE;
	dst_mem.chunks_count = num_pages;
	dst_mem.sysmem.pages = uvm_kvmalloc_zero(sizeof(*dst_mem.sysmem.pages) * num_pages);
    if (!dst_mem.sysmem.pages) {
        ret = NV_ERR_NO_MEMORY;
        goto out;
    }
    dst_mem.size = PAGE_SIZE * num_pages;

    for (i = 0; i < 16; i++) {
		struct page *page = cpu_pages[i];
		if (!page) {
			UCM_ERR("NULL page!!! i = %d\n", i);
			uvm_kvfree(dst_mem.sysmem.pages);
			goto out;
		}
		ret++;
		dst_mem.sysmem.pages[i] = page;
	}

    //UCM_DBG("mapping cpu page\n ");
	//dst_mem.kernel.cpu_addr = kmap(cpu_page);


    dst_mem.kernel.cpu_addr = vmap(dst_mem.sysmem.pages, num_pages, VM_MAP, PAGE_KERNEL);

    if (dst_mem.chunk_size != PAGE_SIZE) {
    	UCM_ERR("Map failed\n");
		ret = NV_ERR_NO_MEMORY;
		goto out;
    }

    if (!dst_mem.kernel.cpu_addr) {
    	UCM_ERR("Map failed\n");
    	status = NV_ERR_NO_MEMORY;
    	goto out;
    }

	status = uvm_va_block_read_to_cpu(va_block, &dst_mem, virt_addr, PAGE_SIZE * num_pages);
	if (status != NV_OK) {
		UCM_DBG("uvm_va_block_read_to_cpu for vrt_addr=0x%llx failed status = %d\n", virt_addr, status);
		vunmap(dst_mem.kernel.cpu_addr);
		goto out;
	}
//UCM_DBG("uvm_va_block_read_to_cpu for vrt_addr=0x%llx worked\n", virt_addr);

	page_index = uvm_va_block_cpu_page_index(va_block, virt_addr);
//	UCM_DBG("page_index=%ld\n ", page_index);
	memcpy(va_block->cpu.pages_diff[page_index], dst_mem.kernel.cpu_addr, PAGE_SIZE * num_pages);
	//kunmap(cpu_page);

	if (dst_mem.kernel.cpu_addr != NULL) {
		vunmap(dst_mem.kernel.cpu_addr);
		dst_mem.kernel.cpu_addr = NULL;
	} else
		UCM_ERR("How come cpu_addr = null\n");

	uvm_kvfree(dst_mem.sysmem.pages);
	ret =  num_pages;

out:
	uvm_va_space_up_read(va_space);
	uvm_va_block_context_free(block_context);
//	UCM_DBG("Done ret = %d\n", ret);
	return ret;
}

static int uvm_vm_retrive_16cached_pages_multi(unsigned long virt_addr, struct page *cpu_pages[])
{
	uvm_va_space_t *va_space = get_shared_mem_va_space();
	uvm_va_block_t *va_block;
	NV_STATUS status = NV_OK;
	int ret = 0, i;
	uvm_va_block_region_t block_region;
	//struct page *ucm_page;
	NvU64 page_index ;

	uvm_mem_t *stage_mem;
	void *stage_addr;
	char *tmp_addr;

	if (!cpu_pages) {
		UCM_ERR("cpu_page = null\n");
		return 0;
	}

//	if (cpu_pages[0]->index/16 > 490)
//		UCM_DBG("Enter for virtaddr=0x%llx first page idx=%d, last page idx=%d, gpu page idx=%lld\n ",
//				virt_addr, cpu_pages[0]->index, cpu_pages[15]->index, cpu_pages[0]->index/16);

	status = uvm_mem_alloc_sysmem_and_map_cpu_kernel(PAGE_SIZE *16, &stage_mem, PAGE_SIZE *16);
	if (status != NV_OK) {
		UCM_ERR("failed to allocate mem\n");
		return status;
	}
	stage_addr = uvm_mem_get_cpu_addr_kernel(stage_mem);
	uvm_va_space_down_read_rm(va_space);
	{

	//	UCM_ERR("looking for a block\n");
		status = uvm_va_block_find_create(va_space, virt_addr, &va_block);
		if (status != NV_OK) {
			UCM_ERR("failed\n");
			uvm_va_space_up_read_rm(va_space);
			goto out;
		}

		status = UVM_VA_BLOCK_LOCK_RETRY(va_block, NULL,
				uvm_va_block_read_to_cpu(va_block, stage_mem, virt_addr, PAGE_SIZE*16));

		page_index = uvm_va_block_cpu_page_index(va_block, virt_addr);
		// For simplicity, check for ECC errors on all GPUs registered in the VA
		// space as tools read/write is not on a perf critical path.
		if (status == NV_OK)
			status = uvm_gpu_check_ecc_error_mask(&va_space->registered_gpus);
	}
	if (status != NV_OK) {
		UCM_DBG("uvm_va_block_read_to_cpu for vrt_addr=0x%llx failed status = %d\n", virt_addr, status);
		uvm_mem_free(stage_mem);
		goto out;
	}

	for (i =0; i < 16; i++){/*
		uvm_va_space_down_read_rm(va_space);
		status = UVM_VA_BLOCK_LOCK_RETRY(va_block, NULL,
					uvm_va_block_read_to_cpu(va_block, stage_mem, virt_addr, PAGE_SIZE));
		if (status == NV_OK)
			status = uvm_gpu_check_ecc_error_mask(&va_space->registered_gpus);
		uvm_va_space_up_read_rm(va_space);*/

		tmp_addr = (char *)kmap(cpu_pages[i]);
		memcpy(tmp_addr, stage_addr + i*4096, PAGE_SIZE);

		//aardvark
	//	if (*tmp_addr != 'a' || *(tmp_addr+1) != 'a' || *(tmp_addr+2) != 'r' || *(tmp_addr+3) != 'd')
	//		UCM_ERR("i=%d : %c%c%c%c  gpu page idx =%lld\n",i, *tmp_addr, *(tmp_addr+1), *(tmp_addr+2), *(tmp_addr+3), cpu_pages[0]->index/16);
		// Update the shadow copy as well since we merged the changes to the cpu page
		memcpy(va_block->cpu.pages_diff[page_index+i], tmp_addr, PAGE_SIZE);
		kunmap(cpu_pages[i]);
	}

	uvm_va_space_up_read_rm(va_space);
	uvm_mem_free(stage_mem);
	ret =  16;

out:

//	UCM_DBG("Done ret = %d\n", ret);
	return ret;
}

static long int zero_page[512] = {0};
static int uvm_vm_retrive_cached_page(unsigned long virt_addr, struct page *cpu_page)
{
	uvm_va_space_t *va_space = get_shared_mem_va_space();
	int ret = 0;	int i;
	uvm_va_block_t *block;
	NV_STATUS status = NV_OK;
	int page_idx = 0;
	char *tmp_addr;
	long int *shadow, *from_gpu, *merged;

	uvm_mem_t *stage_mem;
	void *stage_addr;
//UCM_DBG("Eneter\n");
	status = uvm_mem_alloc_sysmem_and_map_cpu_kernel(PAGE_SIZE, &stage_mem, 0);
	if (status != NV_OK) {
		UCM_ERR("failed to allocate mem\n");
		return status;
	}
	 stage_addr = uvm_mem_get_cpu_addr_kernel(stage_mem);

	// The RM flavor of the lock is needed to perform ECC checks.
	{
		uvm_va_space_down_read_rm(va_space);
		status = uvm_va_block_find_create(va_space, virt_addr, &block);
		if (status != NV_OK) {
			UCM_ERR("failed\n");
			uvm_va_space_up_read_rm(va_space);
			goto out;
		}
		status = UVM_VA_BLOCK_LOCK_RETRY(block, NULL,
							 uvm_va_block_read_to_cpu(block, stage_mem, virt_addr, PAGE_SIZE));
		page_idx = uvm_va_block_cpu_page_index(block, virt_addr);
		// For simplicity, check for ECC errors on all GPUs registered in the VA
		// space as tools read/write is not on a perf critical path.
		if (status == NV_OK)
			status = uvm_gpu_check_ecc_error_mask(&va_space->registered_gpus);

		uvm_va_space_up_read_rm(va_space);
	}

	if (status != NV_OK) {
		UCM_ERR("read failed\n");
		goto out;
	}

	tmp_addr = (char *)kmap(cpu_page);
	/*
	 * Before I do a plain memcpy of 4KB I need to make sure the page was not updated by the GPU
	 * if it was, I need to merge the changes into the cpu page.
	 * Before doing that I need to first understand if the cpu page contains data and I need to
	 * merge or just get the page. This can be done bu comparing the cpu page to 0. I assume newly
	 * allocated page will be zerowed out.
	 */
#if 0
	if (!memcmp( tmp_addr, zero_page, PAGE_SIZE)) {
		char *gpu_data = (char *)uvm_mem_get_cpu_addr_kernel(stage_mem);
	//	UCM_DBG("The cpu page is clean - idx = %ld. gpu page data =%c%c%c\n",
	//			cpu_page->index, *gpu_data, *(gpu_data +1), *(gpu_data+2));
		memcpy(tmp_addr, uvm_mem_get_cpu_addr_kernel(stage_mem), PAGE_SIZE);
	} else
#endif
	if (!memcmp( block->cpu.pages_diff[page_idx], uvm_mem_get_cpu_addr_kernel(stage_mem), PAGE_SIZE)) {
		memcpy(tmp_addr, uvm_mem_get_cpu_addr_kernel(stage_mem), PAGE_SIZE);
	}else {
		//If I got here need to get diff from gpu
		shadow = (long int *)block->cpu.pages_diff[page_idx];
		from_gpu = (long int*)uvm_mem_get_cpu_addr_kernel(stage_mem);
		merged = (long int *)tmp_addr;
		for (i = 0; i < PAGE_SIZE/sizeof(long int) ; i++) {
			if (shadow[i] != from_gpu[i])
				merged[i] =  from_gpu[i];
		}
	}
	// Update the shadow copy as well since we merged the changes to the cpu page
	memcpy(block->cpu.pages_diff[page_idx], tmp_addr, PAGE_SIZE);

done:
	kunmap(cpu_page);

//	uvm_mem_unmap_cpu(stage_addr);
	uvm_mem_free(stage_mem);
out:

	//UCM_DBG("Done ret = %d for idx=%ld\n", ret, cpu_page->index);
	return ret;
}

static int uvm_vm_retrive_16cached_pages(unsigned long virt_addr, struct page *cpu_pages[])
{
	int i;
	int ret = 0;
	for (i = 0; i< 16; i++)
		ret += (!uvm_vm_retrive_cached_page(virt_addr + PAGE_SIZE*i, cpu_pages[i]) ? 1 : 0);
	return ret;
}

static int uvm_vm_retrive_cached_page_old(unsigned long virt_addr, struct page *cpu_page)
{
	uvm_va_space_t *va_space = get_shared_mem_va_space();
	uvm_va_block_t *va_block;
	NV_STATUS status = NV_OK;
	int ret = -1, i;
	uvm_va_block_region_t block_region;
	NvU64 page_index ;

	uvm_mem_t dst_mem;

	if (!cpu_page) {
		UCM_ERR("cpu_page = null\n");
		return 0;
	}

//	uvm_va_space_down_read(va_space);
UCM_ERR("Read from GPU virt addr 0x%llx. page flags = 0x%llx\n", virt_addr, cpu_page->flags);

	dst_mem.backing_gpu = NULL;
	dst_mem.chunk_size = PAGE_SIZE;
	dst_mem.chunks_count = 1;
	dst_mem.sysmem.pages = uvm_kvmalloc_zero(sizeof(*dst_mem.sysmem.pages));
    if (!dst_mem.sysmem.pages) {
        ret = NV_ERR_NO_MEMORY;
        goto out;
    }
    dst_mem.size = PAGE_SIZE;
    dst_mem.sysmem.pages[0] = cpu_page;

    //UCM_DBG("mapping cpu page\n ");
	//dst_mem.kernel.cpu_addr = kmap(cpu_page);


    dst_mem.kernel.cpu_addr = vmap(dst_mem.sysmem.pages, 1, VM_MAP, PAGE_KERNEL);

    if (!dst_mem.kernel.cpu_addr) {
    	UCM_ERR("Map failed\n");
    	status = NV_ERR_NO_MEMORY;
    	uvm_kvfree(dst_mem.sysmem.pages);
    	goto out;
    }

    // The RM flavor of the lock is needed to perform ECC checks.
	uvm_va_space_down_read_rm(va_space);
	status = uvm_va_block_find_create(va_space, virt_addr, &va_block);
	if (status != NV_OK) {
		uvm_va_space_up_read_rm(va_space);
		goto out;
	}
	status = UVM_VA_BLOCK_LOCK_RETRY(va_block, NULL,
			                     uvm_va_block_read_to_cpu(va_block, &dst_mem, virt_addr, PAGE_SIZE));
	// For simplicity, check for ECC errors on all GPUs registered in the VA
	// space as tools read/write is not on a perf critical path.
	if (status == NV_OK)
		status = uvm_gpu_check_ecc_error_mask(&va_space->registered_gpus);

	uvm_va_space_up_read_rm(va_space);
	if (status != NV_OK) {
		UCM_DBG("uvm_va_block_read_to_cpu for vrt_addr=0x%llx failed status = %d\n", virt_addr, status);
		vunmap(dst_mem.kernel.cpu_addr);
		uvm_kvfree(dst_mem.sysmem.pages);
		goto out;
	}
//UCM_DBG("uvm_va_block_read_to_cpu for vrt_addr=0x%llx worked\n", virt_addr);

	page_index = uvm_va_block_cpu_page_index(va_block, virt_addr);
//	UCM_DBG("page_index=%ld\n ", page_index);
	memcpy(va_block->cpu.pages_diff[page_index], dst_mem.kernel.cpu_addr, PAGE_SIZE);
	//kunmap(cpu_page);

	if (dst_mem.kernel.cpu_addr != NULL) {
		vunmap(dst_mem.kernel.cpu_addr);
		dst_mem.kernel.cpu_addr = NULL;
	} else
		UCM_ERR("How come cpu_addr = null\n");

	uvm_kvfree(dst_mem.sysmem.pages);
	ret =  0;

out:
	UCM_DBG("Done for idx = %d. ret = %d\n", cpu_page->index, ret);
	return ret;
}

static int uvm_vm_invalidate_cached_page(struct vm_area_struct *vma, unsigned long virt_addr)
{
	uvm_va_space_t *va_space = get_shared_mem_va_space();
	uvm_va_block_t *va_block;
	NV_STATUS status = NV_OK;
	int ret = -1, i;
	size_t page_index;
	uvm_va_block_context_t *block_context = uvm_va_block_context_alloc();
	 uvm_gpu_t *gpu;


	UCM_DBG("enter for virt_addr = 0x%llx\n", virt_addr);

	uvm_va_space_down_read(va_space);
	status = uvm_va_block_find(va_space, virt_addr, &va_block);
	if (status != NV_OK) {
		UCM_ERR("Didn't find block\n");
        goto out;
	}
	
	page_index = (virt_addr - va_block->start)/PAGE_SIZE;
	//need to migrate the pages back to CPU. 
	if (page_index % 16)
		UCM_DBG("No aligned to page size idx=%d\n\n\n\n\n", page_index);

	gpu = uvm_processor_mask_find_first_gpu(&va_space->registered_gpus);
	uvm_mutex_lock(&va_block->lock);
	status = UVM_VA_BLOCK_RETRY_LOCKED(va_block, NULL, block_evict_pages_from_gpu(va_block, gpu));
	if (status != NV_OK) {
		UCM_ERR("Failed to evict GPU pages on GPU unregister: %s, GPU %s\n", nvstatusToString(status), gpu->name);
		uvm_global_set_fatal_error(status);
		uvm_mutex_unlock(&va_block->lock);
		goto out;
	}
	uvm_mutex_unlock(&va_block->lock);

	for (i = page_index; i <= page_index + 15; i++) {
		va_block->cpu.page_from_cache[i] = false;
	}
//UCM_DBG("invalidated block [0x%llx, 0x%llx]\n",va_block->start, va_block->end);

	ret = 0;

out:
	uvm_va_space_up_read(va_space);
	uvm_va_block_context_free(block_context);
	return ret;
}

static int uvm_vm_is_gpu_page_dirty(struct vm_area_struct *shared_vma, struct page *gpu_page) {
	uvm_va_space_t *va_space = get_shared_mem_va_space();
	int ret = 0;	int i;
	uvm_va_block_t *block;
	NV_STATUS status = NV_OK;
	struct ucm_page_data *pdata = (struct ucm_page_data *)gpu_page->private;
	unsigned long gpu_page_addr = pdata->shared_addr;
	int page_idx = 0;

	//bring the pages from gpu by simulating a page fault
	ret = 0;//uvm_vm_fault(shared_vma, &vmf);

	//compare to the cpu cached version
	for (i = 0; i <16; i++) {
		uvm_mem_t *stage_mem;
		void *stage_addr;

		status = uvm_mem_alloc_sysmem_and_map_cpu_kernel(PAGE_SIZE, &stage_mem, 0);
		if (status != NV_OK)
			return status;
		 stage_addr = uvm_mem_get_cpu_addr_kernel(stage_mem);

		// The RM flavor of the lock is needed to perform ECC checks.
		uvm_va_space_down_read_rm(va_space);
		status = uvm_va_block_find_create(va_space, gpu_page_addr + i*PAGE_SIZE, &block);
		if (status != NV_OK) {
			uvm_va_space_up_read_rm(va_space);
			break;
		}
		status = UVM_VA_BLOCK_LOCK_RETRY(block, NULL,
		                     uvm_va_block_read_to_cpu(block, stage_mem, gpu_page_addr + i*PAGE_SIZE, PAGE_SIZE));
		page_idx = uvm_va_block_cpu_page_index(block, gpu_page_addr + i*PAGE_SIZE);
		// For simplicity, check for ECC errors on all GPUs registered in the VA
		// space as tools read/write is not on a perf critical path.
		if (status == NV_OK)
			status = uvm_gpu_check_ecc_error_mask(&va_space->registered_gpus);

		uvm_va_space_up_read_rm(va_space);
		if (status != NV_OK)
			break;

		if (memcmp(stage_addr , block->cpu.pages_diff[page_idx], PAGE_SIZE)) {
			ret = 1;
		//	UCM_DBG("gpu page dirty at virt addr virt addr 0x%llx \n", gpu_page_addr);
			break;
		}// else
		//	UCM_DBG("gpu page CLEAN at virt addr virt addr 0x%llx \n", gpu_page_addr);
		uvm_mem_free(stage_mem);
	}
//	uvm_mem_unmap_cpu(stage_addr);

out:

//	UCM_DBG("Done ret = %d\n", ret);
	return ret;
}


struct vm_ucm_operations_struct uvm_ucm_ops_managed =
{
	.get_mmaped_file = uvm_vm_get_mmaped_file,
	.get_cpu_addr = uvm_get_cpu_addr,
	.invalidate_cached_page = uvm_vm_invalidate_cached_page,
	.retrive_cached_page = uvm_vm_retrive_cached_page,
	.retrive_16cached_pages = uvm_vm_retrive_16cached_pages_multi, //uvm_vm_retrive_16cached_pages2,
	.is_gpu_page_dirty = uvm_vm_is_gpu_page_dirty,
};

// vm operations on semaphore pool allocations only control CPU mappings. Unmapping GPUs,
// freeing the allocation, and destroying the va_range are handled by UVM_FREE.
static void uvm_vm_open_semaphore_pool(struct vm_area_struct *vma)
{
    struct vm_area_struct *origin_vma = (struct vm_area_struct *)vma->vm_private_data;
    uvm_va_space_t *va_space = uvm_va_space_get(origin_vma->vm_file);
    uvm_va_range_t *va_range;
    bool is_fork = (vma->vm_mm != origin_vma->vm_mm);
    NV_STATUS status;

    uvm_record_lock_mmap_sem_write(&current->mm->mmap_sem);

    uvm_va_space_down_write(va_space);

    va_range = uvm_va_range_find(va_space, origin_vma->vm_start);
    UVM_ASSERT(va_range);
    UVM_ASSERT_MSG(va_range->type == UVM_VA_RANGE_TYPE_SEMAPHORE_POOL &&
                   va_range->node.start == origin_vma->vm_start &&
                   va_range->node.end + 1 == origin_vma->vm_end,
                   "origin vma [0x%llx, 0x%llx); va_range [0x%llx, 0x%llx) type %d\n",
                   (NvU64)origin_vma->vm_start, (NvU64)origin_vma->vm_end, va_range->node.start,
                   va_range->node.end + 1, va_range->type);

    // Semaphore pool vmas do not have vma wrappers, but some functions will
    // assume vm_private_data is a wrapper.
    vma->vm_private_data = NULL;

    if (is_fork) {
        // If we forked, leave the parent vma alone.
        uvm_disable_vma(vma);
        // uvm_disable_vma unmaps in the parent as well; remap it.
        uvm_processor_mask_clear(&va_range->semaphore_pool.mem->mapped_on, UVM_CPU_ID);
        status = uvm_mem_map_cpu(va_range->semaphore_pool.mem, origin_vma);
        if (status != NV_OK) {
            UVM_DBG_PRINT("Failed to remap semaphore pool to CPU for parent after fork; status = %d (%s)",
                    status, nvstatusToString(status));
            origin_vma->vm_ops = &uvm_vm_ops_disabled;
        }
    }
    else {
        origin_vma->vm_private_data = NULL;
        origin_vma->vm_ops = &uvm_vm_ops_disabled;
        vma->vm_ops = &uvm_vm_ops_disabled;
        uvm_mem_unmap_cpu(va_range->semaphore_pool.mem);
    }

    uvm_va_space_up_write(va_space);

    uvm_record_unlock_mmap_sem_write(&current->mm->mmap_sem);
}

// vm operations on semaphore pool allocations only control CPU mappings. Unmapping GPUs,
// freeing the allocation, and destroying the va_range are handled by UVM_FREE.
static void uvm_vm_close_semaphore_pool(struct vm_area_struct *vma)
{
    uvm_va_space_t *va_space = uvm_va_space_get(vma->vm_file);

    if (current->mm != NULL)
        uvm_record_lock_mmap_sem_write(&current->mm->mmap_sem);

    uvm_va_space_down_read(va_space);

    uvm_destroy_vma_semaphore_pool(vma);

    uvm_va_space_up_read(va_space);

    if (current->mm != NULL)
        uvm_record_unlock_mmap_sem_write(&current->mm->mmap_sem);
}

static struct vm_operations_struct uvm_vm_ops_semaphore_pool =
{
    .open         = uvm_vm_open_semaphore_pool,
    .close        = uvm_vm_close_semaphore_pool,

#if defined(NV_VM_OPS_FAULT_REMOVED_VMA_ARG)
    .fault        = uvm_vm_fault_sigbus_wrapper,
#else
    .fault        = uvm_vm_fault_sigbus,
#endif
};

static int uvm_mmap(struct file *filp, struct vm_area_struct *vma)
{
    uvm_va_space_t *va_space = uvm_va_space_get(filp);
    uvm_va_range_t *va_range;
    NV_STATUS status = uvm_global_get_status();
    int ret = 0;
    bool vma_wrapper_allocated = false;

    if (status != NV_OK)
        return -nv_status_to_errno(status);

    uvm_record_lock_mmap_sem_write(&current->mm->mmap_sem);

    // UVM mappings are required to set offset == VA. This simplifies things
    // since we don't have to worry about address aliasing (except for fork,
    // handled separately) and it makes unmap_mapping_range simpler.
    if (vma->vm_start != (vma->vm_pgoff << PAGE_SHIFT)) {
        UVM_DBG_PRINT_RL("vm_start 0x%lx != vm_pgoff 0x%lx\n", vma->vm_start, vma->vm_pgoff << PAGE_SHIFT);
        ret = -EINVAL;
        goto out;
    }

    // Enforce shared read/writable mappings so we get all fault callbacks
    // without the kernel doing COW behind our backs. The user can still call
    // mprotect to change protections, but that will only hurt user space.
    if ((vma->vm_flags & (VM_SHARED|VM_READ|VM_WRITE)) !=
                         (VM_SHARED|VM_READ|VM_WRITE)) {
        UVM_DBG_PRINT_RL("User requested non-shared or non-writable mapping\n");
        ret = -EINVAL;
        goto out;
    }

    // VM_MIXEDMAP      Required to use vm_insert_page
    //
    // VM_DONTEXPAND    mremap can grow a vma in place without giving us any
    //                  callback. We need to prevent this so our ranges stay
    //                  up-to-date with the vma. This flag doesn't prevent
    //                  mremap from moving the mapping elsewhere, nor from
    //                  shrinking it. We can detect both of those cases however
    //                  with vm_ops->open() and vm_ops->close() callbacks.
    //
    // Using VM_DONTCOPY would be nice, but madvise(MADV_DOFORK) can reset that
    // so we have to handle vm_open on fork anyway. We could disable MADV_DOFORK
    // with VM_IO, but that causes other mapping issues.
    vma->vm_flags |= VM_MIXEDMAP | VM_DONTEXPAND;

    vma->vm_ops = &uvm_vm_ops_managed;
    vma->ucm_vm_ops = &uvm_ucm_ops_managed;

UCM_DBG("Setting vma 0x%llx as gpu_managed (file = %s)\n", vma, filp->f_path.dentry->d_iname);
    vma->gpu_mapped_shared = true;

    // This identity assignment is needed so uvm_vm_open can find its parent vma
    vma->vm_private_data = uvm_vma_wrapper_alloc(vma);
    if (!vma->vm_private_data) {
        ret = -ENOMEM;
        goto out;
    }
    vma_wrapper_allocated = true;

    // The kernel has taken mmap_sem in write mode, but that doesn't prevent
    // this va_space from being modified by the GPU fault path or from the ioctl
    // path where we don't have this mm for sure, so we have to lock the VA
    // space directly.
    uvm_va_space_down_write(va_space);

    // uvm_va_range_create_mmap will catch collisions. Below are some example
    // cases which can cause collisions. There may be others.
    // 1) An overlapping range was previously created with an ioctl, for example
    //    for an external mapping.
    // 2) This file was passed to another process via a UNIX domain socket
    status = uvm_va_range_create_mmap(va_space, vma->vm_private_data, NULL);

    if (status == NV_ERR_UVM_ADDRESS_IN_USE) {
        // If the mmap is for a semaphore pool, the VA range will have been
        // allocated by a previous ioctl, and the mmap just creates the CPU
        // mapping.
        va_range = uvm_va_range_find(va_space, vma->vm_start);
        if (va_range && va_range->node.start == vma->vm_start &&
                va_range->node.end + 1 == vma->vm_end &&
                va_range->type == UVM_VA_RANGE_TYPE_SEMAPHORE_POOL) {
            uvm_vma_wrapper_destroy(vma->vm_private_data);
            vma_wrapper_allocated = false;
            vma->vm_private_data = vma;
            vma->vm_ops = &uvm_vm_ops_semaphore_pool;
            status = uvm_mem_map_cpu(va_range->semaphore_pool.mem, vma);
        }
    }

    if (status != NV_OK) {
        UVM_DBG_PRINT_RL("Failed to create or map VA range for vma [0x%lx, 0x%lx): %s\n",
                         vma->vm_start, vma->vm_end, nvstatusToString(status));
        ret = -nv_status_to_errno(status);
    }

    uvm_va_space_up_write(va_space);

out:
    if (ret != 0 && vma_wrapper_allocated)
        uvm_vma_wrapper_destroy(vma->vm_private_data);

    uvm_record_unlock_mmap_sem_write(&current->mm->mmap_sem);

    return ret;
}

static long uvm_unlocked_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    switch (cmd)
    {
        case UVM_DEINITIALIZE:
            return 0;

        UVM_ROUTE_CMD_STACK(UVM_INITIALIZE,                     uvm_api_initialize);
        UVM_ROUTE_CMD_STACK(UVM_IS_8_SUPPORTED,                 uvm_api_is_8_supported);
        UVM_ROUTE_CMD_STACK(UVM_PAGEABLE_MEM_ACCESS,            uvm_api_pageable_mem_access);
        UVM_ROUTE_CMD_STACK(UVM_PAGEABLE_MEM_ACCESS_ON_GPU,     uvm_api_pageable_mem_access_on_gpu);
        UVM_ROUTE_CMD_STACK(UVM_REGISTER_GPU,                   uvm_api_register_gpu);
        UVM_ROUTE_CMD_STACK(UVM_UNREGISTER_GPU,                 uvm_api_unregister_gpu);
        UVM_ROUTE_CMD_STACK(UVM_CREATE_RANGE_GROUP,             uvm_api_create_range_group);
        UVM_ROUTE_CMD_STACK(UVM_DESTROY_RANGE_GROUP,            uvm_api_destroy_range_group);
        UVM_ROUTE_CMD_STACK(UVM_ENABLE_PEER_ACCESS,             uvm_api_enable_peer_access);
        UVM_ROUTE_CMD_STACK(UVM_DISABLE_PEER_ACCESS,            uvm_api_disable_peer_access);
        UVM_ROUTE_CMD_STACK(UVM_SET_RANGE_GROUP,                uvm_api_set_range_group);
        UVM_ROUTE_CMD_ALLOC(UVM_MAP_EXTERNAL_ALLOCATION,        uvm_api_map_external_allocation);
        UVM_ROUTE_CMD_STACK(UVM_FREE,                           uvm_api_free);
        UVM_ROUTE_CMD_STACK(UVM_PREVENT_MIGRATION_RANGE_GROUPS, uvm_api_prevent_migration_range_groups);
        UVM_ROUTE_CMD_STACK(UVM_ALLOW_MIGRATION_RANGE_GROUPS,   uvm_api_allow_migration_range_groups);
        UVM_ROUTE_CMD_STACK(UVM_SET_PREFERRED_LOCATION,         uvm_api_set_preferred_location);
        UVM_ROUTE_CMD_STACK(UVM_UNSET_PREFERRED_LOCATION,       uvm_api_unset_preferred_location);
        UVM_ROUTE_CMD_STACK(UVM_SET_ACCESSED_BY,                uvm_api_set_accessed_by);
        UVM_ROUTE_CMD_STACK(UVM_UNSET_ACCESSED_BY,              uvm_api_unset_accessed_by);
        UVM_ROUTE_CMD_STACK(UVM_REGISTER_GPU_VASPACE,           uvm_api_register_gpu_va_space);
        UVM_ROUTE_CMD_STACK(UVM_UNREGISTER_GPU_VASPACE,         uvm_api_unregister_gpu_va_space);
        UVM_ROUTE_CMD_STACK(UVM_REGISTER_CHANNEL,               uvm_api_register_channel);
        UVM_ROUTE_CMD_STACK(UVM_UNREGISTER_CHANNEL,             uvm_api_unregister_channel);
        UVM_ROUTE_CMD_STACK(UVM_ENABLE_READ_DUPLICATION,        uvm_api_enable_read_duplication);
        UVM_ROUTE_CMD_STACK(UVM_DISABLE_READ_DUPLICATION,       uvm_api_disable_read_duplication);
        UVM_ROUTE_CMD_STACK(UVM_MIGRATE,                        uvm_api_migrate);
        UVM_ROUTE_CMD_STACK(UVM_ENABLE_SYSTEM_WIDE_ATOMICS,     uvm_api_enable_system_wide_atomics);
        UVM_ROUTE_CMD_STACK(UVM_DISABLE_SYSTEM_WIDE_ATOMICS,    uvm_api_disable_system_wide_atomics);
        UVM_ROUTE_CMD_STACK(UVM_TOOLS_READ_PROCESS_MEMORY,      uvm_api_tools_read_process_memory);
        UVM_ROUTE_CMD_STACK(UVM_TOOLS_WRITE_PROCESS_MEMORY,     uvm_api_tools_write_process_memory);
        UVM_ROUTE_CMD_STACK(UVM_TOOLS_GET_PROCESSOR_UUID_TABLE, uvm_api_tools_get_processor_uuid_table);
        UVM_ROUTE_CMD_STACK(UVM_MAP_DYNAMIC_PARALLELISM_REGION, uvm_api_map_dynamic_parallelism_region);
        UVM_ROUTE_CMD_STACK(UVM_UNMAP_EXTERNAL_ALLOCATION,      uvm_api_unmap_external_allocation);
        UVM_ROUTE_CMD_STACK(UVM_MIGRATE_RANGE_GROUP,            uvm_api_migrate_range_group);
        UVM_ROUTE_CMD_STACK(UVM_TOOLS_FLUSH_EVENTS,             uvm_api_tools_flush_events);
        UVM_ROUTE_CMD_ALLOC(UVM_ALLOC_SEMAPHORE_POOL,           uvm_api_alloc_semaphore_pool);
        UVM_ROUTE_CMD_STACK(UVM_CLEAN_UP_ZOMBIE_RESOURCES,      uvm_api_clean_up_zombie_resources);
	UVM_ROUTE_CMD_STACK(UVM_MAP_VMA_RANGE,			uvm_api_map_vma_range);
	UVM_ROUTE_CMD_STACK(UVM_UNMAP_VMA_RANGE,          	uvm_api_unmap_vma_range);
	UVM_ROUTE_CMD_STACK(UVM_TOUCH_RANGE,          		uvm_api_touch_vma_range);
    }

    // Try the test ioctls if none of the above matched
    return uvm8_test_ioctl(filp, cmd, arg);
}

static const struct file_operations uvm_fops =
{
    .open            = uvm_open,
    .release         = uvm_release,
    .mmap            = uvm_mmap,
    .unlocked_ioctl  = uvm_unlocked_ioctl,
#if NVCPU_IS_X86_64 && defined(NV_FILE_OPERATIONS_HAS_COMPAT_IOCTL)
    .compat_ioctl    = uvm_unlocked_ioctl,
#endif
    .owner           = THIS_MODULE,
};



int uvm8_init(dev_t uvm_base_dev)
{
    bool initialized_globals = false;
    bool added_device = false;
    int ret = -ENODEV;
    dev_t uvm_dev = MKDEV(MAJOR(uvm_base_dev), NVIDIA_UVM_PRIMARY_MINOR_NUMBER);
    NV_STATUS status;

    status = uvm_global_init();
    if (status != NV_OK) {
        UVM_ERR_PRINT("uvm_global_init() failed: %s\n", nvstatusToString(status));
        goto error;
    }
    initialized_globals = true;

    uvm_init_character_device(&g_uvm_cdev, &uvm_fops);
    ret = cdev_add(&g_uvm_cdev, uvm_dev, 1);
    if (ret != 0) {
        UVM_ERR_PRINT("cdev_add (major %u, minor %u) failed: %d\n", MAJOR(uvm_dev), MINOR(uvm_dev), ret);
        goto error;
    }
    added_device = true;

    ret = uvm_tools_init(uvm_base_dev);
    if (ret != 0) {
        UVM_ERR_PRINT("uvm_tools_init() failed: %d\n", ret);
        goto error;
    }

    uvm_hmm_init();

    return 0;

error:
    if (added_device)
        cdev_del(&g_uvm_cdev);

    if (initialized_globals)
        uvm_global_exit();

    return ret;
}

void uvm8_exit(void)
{
    uvm_tools_exit();
    cdev_del(&g_uvm_cdev);

    uvm_global_exit();
}

NV_STATUS uvm8_initialize(UVM_INITIALIZE_PARAMS *params, struct file *filp)
{
    NV_STATUS status = NV_OK;
    uvm_va_space_t *va_space = uvm_va_space_get(filp);

    if ((params->flags & ~UVM_INIT_FLAGS_MASK))
        return NV_ERR_INVALID_ARGUMENT;

    uvm_va_space_down_write(va_space);
    if (va_space->initialized) {
        // Already initialized - check if parameters match
        if (params->flags != va_space->initialization_flags)
            status = NV_ERR_INVALID_ARGUMENT;
    }
    else {
        va_space->initialization_flags = params->flags;
        va_space->initialized = true;
    }
    uvm_va_space_up_write(va_space);

    return status;
}

bool uvm_file_is_nvidia_uvm(struct file *filp)
{
    return (filp != NULL) && (filp->f_op == &uvm_fops);
}
