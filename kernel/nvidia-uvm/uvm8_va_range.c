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
#include "uvm_linux.h"
#include "uvm8_api.h"
#include "uvm8_va_range.h"
#include "uvm8_va_block.h"
#include "uvm8_kvmalloc.h"
#include "uvm8_map_external.h"
#include "uvm8_perf_thrashing.h"
#include "nv_uvm_interface.h"

static struct kmem_cache *g_uvm_va_range_cache __read_mostly;
static struct kmem_cache *g_uvm_vma_wrapper_cache __read_mostly;

NV_STATUS uvm_va_range_init(void)
{
    g_uvm_va_range_cache = NV_KMEM_CACHE_CREATE("uvm_va_range_t", uvm_va_range_t);
    if (!g_uvm_va_range_cache)
        return NV_ERR_NO_MEMORY;

    g_uvm_vma_wrapper_cache = NV_KMEM_CACHE_CREATE("uvm_vma_wrapper_t", uvm_vma_wrapper_t);
    if (!g_uvm_vma_wrapper_cache)
        return NV_ERR_NO_MEMORY;

    return uvm_va_block_init();
}

void uvm_va_range_exit(void)
{
    uvm_va_block_exit();
    kmem_cache_destroy_safe(&g_uvm_va_range_cache);
    kmem_cache_destroy_safe(&g_uvm_vma_wrapper_cache);
}

static NvU64 block_calc_start(uvm_va_range_t *va_range, size_t index)
{
    NvU64 range_start = UVM_VA_BLOCK_ALIGN_DOWN(va_range->node.start);
    NvU64 block_start = range_start + index * UVM_VA_BLOCK_SIZE;
    NvU64 start = max(va_range->node.start, block_start);
    UVM_ASSERT(start < va_range->node.end);
    return start;
}

static NvU64 block_calc_end(uvm_va_range_t *va_range, size_t index)
{
    NvU64 start = block_calc_start(va_range, index);
    NvU64 block_end = UVM_VA_BLOCK_ALIGN_UP(start + 1) - 1; // Inclusive end
    NvU64 end = min(va_range->node.end, block_end);
    UVM_ASSERT(end > va_range->node.start);
    return end;
}

// Called before the range's bounds have been adjusted. This may not actually
// shrink the blocks array. For example, if the shrink attempt fails then
// va_range's old array is left intact. This may waste memory, but it means this
// function cannot fail.
static void blocks_array_shrink(uvm_va_range_t *va_range, size_t new_num_blocks)
{
    size_t new_size = new_num_blocks * sizeof(va_range->blocks[0]);
    atomic_long_t *new_blocks;

    UVM_ASSERT(va_range->type == UVM_VA_RANGE_TYPE_MANAGED);
    UVM_ASSERT(va_range->blocks);
    UVM_ASSERT(uvm_kvsize(va_range->blocks) >= uvm_va_range_num_blocks(va_range) * sizeof(va_range->blocks[0]));
    UVM_ASSERT(new_num_blocks);
    UVM_ASSERT(new_num_blocks <= uvm_va_range_num_blocks(va_range));

    // TODO: Bug 1766579: This could be optimized by only shrinking the array
    //       when the new size is half of the old size or some similar
    //       threshold. Need to profile this on real apps to see if that's worth
    //       doing.

    new_blocks = uvm_kvrealloc(va_range->blocks, new_size);
    if (!new_blocks) {
        // If we failed to allocate a smaller array, just leave the old one as-is
        UVM_DBG_PRINT("Failed to shrink range [0x%llx, 0x%llx] from %Zu blocks to %Zu blocks\n",
                      va_range->node.start,
                      va_range->node.end,
                      uvm_kvsize(va_range->blocks) / sizeof(va_range->blocks[0]),
                      new_num_blocks);
        return;
    }

    va_range->blocks = new_blocks;
}

static uvm_va_range_t *uvm_va_range_alloc(uvm_va_space_t *va_space, NvU64 start, NvU64 end)
{
    uvm_va_range_t *va_range = kmem_cache_zalloc(g_uvm_va_range_cache, NV_UVM_GFP_FLAGS);
    if (!va_range)
        return NULL;

    uvm_assert_rwsem_locked_write(&va_space->lock);

    va_range->va_space = va_space;
    va_range->node.start = start;
    va_range->node.end = end;

    // The range is inserted into the VA space tree only at the end of creation,
    // so clear the node so the destroy path knows whether to remove it.
    RB_CLEAR_NODE(&va_range->node.rb_node);

    nv_kref_init(&va_range->kref);

    return va_range;
}

static uvm_va_range_t *uvm_va_range_alloc_managed(uvm_va_space_t *va_space, NvU64 start, NvU64 end)
{
    uvm_va_range_t *va_range = NULL;

    va_range = uvm_va_range_alloc(va_space, start, end);
    if (!va_range)
        goto error;

    va_range->type = UVM_VA_RANGE_TYPE_MANAGED;

    va_range->read_duplication = UVM_READ_DUPLICATION_UNSET;
    va_range->preferred_location = UVM8_MAX_PROCESSORS;

    va_range->blocks = uvm_kvmalloc_zero(uvm_va_range_num_blocks(va_range) * sizeof(va_range->blocks[0]));
    if (!va_range->blocks) {
        UVM_DBG_PRINT("Failed to allocate %Zu blocks\n", uvm_va_range_num_blocks(va_range));
        goto error;
    }

    return va_range;

error:
    uvm_va_range_destroy(va_range, NULL);
    return NULL;
}

NV_STATUS uvm_va_range_create_mmap(uvm_va_space_t *va_space,
                                   uvm_vma_wrapper_t *vma_wrapper,
                                   uvm_va_range_t **out_va_range)
{
    NV_STATUS status;
    struct vm_area_struct *vma = vma_wrapper->vma;
    uvm_va_range_t *va_range = NULL;

    // vma->vm_end is exclusive but va_range end is inclusive
    va_range = uvm_va_range_alloc_managed(va_space, vma->vm_start, vma->vm_end - 1);
    if (!va_range) {
        status = NV_ERR_NO_MEMORY;
        goto error;
    }

    va_range->managed.vma_wrapper = vma_wrapper;

    status = uvm_range_tree_add(&va_space->va_range_tree, &va_range->node);
    if (status != NV_OK)
        goto error;

    if (out_va_range)
        *out_va_range = va_range;

    return NV_OK;

error:
    uvm_va_range_destroy(va_range, NULL);
    return status;
}

NV_STATUS uvm_va_range_create_external(uvm_va_space_t *va_space,
                                       NvU64 start,
                                       NvU64 length,
                                       uvm_va_range_t **out_va_range)
{
    NV_STATUS status;
    uvm_va_range_t *va_range = NULL;

    va_range = uvm_va_range_alloc(va_space, start, start + length - 1);
    if (!va_range) {
        status = NV_ERR_NO_MEMORY;
        goto error;
    }

    va_range->type = UVM_VA_RANGE_TYPE_EXTERNAL;

    status = uvm_range_tree_add(&va_space->va_range_tree, &va_range->node);
    if (status != NV_OK)
        goto error;

    if (out_va_range)
        *out_va_range = va_range;

    return NV_OK;

error:
    uvm_va_range_destroy(va_range, NULL);
    return status;
}

NV_STATUS uvm_va_range_create_channel(uvm_va_space_t *va_space,
                                      NvU64 start,
                                      NvU64 end,
                                      uvm_va_range_t **out_va_range)
{
    NV_STATUS status;
    uvm_va_range_t *va_range = NULL;

    va_range = uvm_va_range_alloc(va_space, start, end);
    if (!va_range) {
        status = NV_ERR_NO_MEMORY;
        goto error;
    }

    va_range->type = UVM_VA_RANGE_TYPE_CHANNEL;
    INIT_LIST_HEAD(&va_range->channel.local_node);

    status = uvm_range_tree_add(&va_space->va_range_tree, &va_range->node);
    if (status != NV_OK)
        goto error;

    if (out_va_range)
        *out_va_range = va_range;

    return NV_OK;

error:
    uvm_va_range_destroy(va_range, NULL);
    return status;
}

NV_STATUS uvm_va_range_create_sked_reflected(uvm_va_space_t *va_space,
                                             NvU64 start,
                                             NvU64 length,
                                             uvm_va_range_t **out_va_range)
{
    NV_STATUS status;
    uvm_va_range_t *va_range = NULL;

    va_range = uvm_va_range_alloc(va_space, start, start + length - 1);
    if (!va_range) {
        status = NV_ERR_NO_MEMORY;
        goto error;
    }

    va_range->type = UVM_VA_RANGE_TYPE_SKED_REFLECTED;

    status = uvm_range_tree_add(&va_space->va_range_tree, &va_range->node);
    if (status != NV_OK)
        goto error;

    if (out_va_range)
        *out_va_range = va_range;

    return NV_OK;

error:
    uvm_va_range_destroy(va_range, NULL);
    return status;
}

NV_STATUS uvm_va_range_create_semaphore_pool(uvm_va_space_t *va_space,
                                             NvU64 start,
                                             NvU64 length,
                                             UvmGpuMappingAttributes *per_gpu_attrs,
                                             NvU32 per_gpu_attrs_count,
                                             uvm_va_range_t **out_va_range)
{
    static const uvm_mem_gpu_mapping_attrs_t default_attrs = {
            .protection = UVM_PROT_READ_WRITE_ATOMIC,
            .is_volatile = true
    };

    NV_STATUS status;
    uvm_va_range_t *va_range = NULL;
    uvm_mem_alloc_params_t mem_alloc_params = { 0 };
    NvU32 i;

    va_range = uvm_va_range_alloc(va_space, start, start + length - 1);
    if (!va_range) {
        status = NV_ERR_NO_MEMORY;
        goto error;
    }

    va_range->type = UVM_VA_RANGE_TYPE_SEMAPHORE_POOL;
    uvm_tracker_init(&va_range->semaphore_pool.tracker);
    uvm_mutex_init(&va_range->semaphore_pool.tracker_lock, UVM_LOCK_ORDER_SEMA_POOL_TRACKER);

    status = uvm_range_tree_add(&va_space->va_range_tree, &va_range->node);
    if (status != NV_OK)
        goto error;

    mem_alloc_params.page_size = UVM_PAGE_SIZE_DEFAULT;
    mem_alloc_params.size = length;
    mem_alloc_params.user_addr = (void *)start;
    mem_alloc_params.user_va_space = va_space;
    status = uvm_mem_alloc(&mem_alloc_params, &va_range->semaphore_pool.mem);
    if (status != NV_OK)
        goto error;

    va_range->semaphore_pool.default_gpu_attrs = default_attrs;
    va_range->semaphore_pool.owner = NULL;
    for (i = 0; i < UVM8_MAX_GPUS; i++)
        va_range->semaphore_pool.gpu_attrs[i] = default_attrs;
    for (i = 0; i < per_gpu_attrs_count; i++) {
        uvm_gpu_t *gpu;
        uvm_mem_gpu_mapping_attrs_t attrs = default_attrs;
        status = uvm_mem_translate_gpu_attributes(&per_gpu_attrs[i], va_space, &gpu, &attrs);
        if (status != NV_OK)
            goto error;
        if (!attrs.is_volatile) {
            // At most 1 GPU can have this memory cached, in which case it is the 'owner' GPU.
            if (va_range->semaphore_pool.owner != NULL) {
                UVM_DBG_PRINT("Caching of semaphore pool requested on >1 GPU.");
                status = NV_ERR_INVALID_ARGUMENT;
                goto error;
            }
            va_range->semaphore_pool.owner = gpu;
        }
        va_range->semaphore_pool.gpu_attrs[gpu->id - 1] = attrs;
    }

    if (out_va_range)
        *out_va_range = va_range;

    return NV_OK;

error:
    uvm_va_range_destroy(va_range, NULL);
    return status;
}

static void uvm_va_range_destroy_managed(uvm_va_range_t *va_range)
{
    uvm_va_block_t *block;
    uvm_va_block_t *block_tmp;
    uvm_perf_event_data_t event_data;

    UVM_ASSERT(va_range->type == UVM_VA_RANGE_TYPE_MANAGED);

    if (va_range->blocks) {
        // Unmap and drop our ref count on each block
        for_each_va_block_in_va_range_safe(va_range, block, block_tmp)
            uvm_va_block_kill(block);

        uvm_kvfree(va_range->blocks);
    }

    event_data.range_destroy.range = va_range;
    uvm_perf_event_notify(&va_range->va_space->perf_events, UVM_PERF_EVENT_RANGE_DESTROY, &event_data);

    uvm_range_group_assign_range(va_range->va_space, NULL, va_range->node.start, va_range->node.end);
}

static void uvm_va_range_destroy_external(uvm_va_range_t *va_range, struct list_head *deferred_free_list)
{
    uvm_gpu_t *gpu;

    if (uvm_processor_mask_empty(&va_range->external.mapped_gpus))
        return;

    UVM_ASSERT(deferred_free_list);

    for_each_gpu_in_mask(gpu, &va_range->external.mapped_gpus)
        uvm_ext_gpu_map_destroy(va_range, gpu, deferred_free_list);

    UVM_ASSERT(uvm_processor_mask_empty(&va_range->external.mapped_gpus));
}

static void uvm_va_range_destroy_channel(uvm_va_range_t *va_range)
{
    uvm_gpu_va_space_t *gpu_va_space = va_range->channel.gpu_va_space;
    uvm_membar_t membar;

    // Unmap the buffer
    if (gpu_va_space && va_range->channel.pt_range_vec.ranges) {
        if (va_range->channel.aperture == UVM_APERTURE_VID)
            membar = UVM_MEMBAR_GPU;
        else
            membar = UVM_MEMBAR_SYS;

        uvm_page_table_range_vec_clear_ptes(&va_range->channel.pt_range_vec, membar);
        uvm_page_table_range_vec_deinit(&va_range->channel.pt_range_vec);
    }

    UVM_ASSERT(va_range->channel.ref_count == 0);
    if (va_range->channel.is_local)
        list_del(&va_range->channel.local_node);

    // Channel unregister handles releasing this descriptor back to RM
    va_range->channel.rm_descriptor = 0;
}

static void uvm_va_range_destroy_sked_reflected(uvm_va_range_t *va_range)
{
    uvm_gpu_va_space_t *gpu_va_space = va_range->sked_reflected.gpu_va_space;

    if (!gpu_va_space || !va_range->sked_reflected.pt_range_vec.ranges)
        return;

    // The SKED reflected mapping has no physical backing and hence no physical
    // accesses can be pending to it and no membar is needed.
    uvm_page_table_range_vec_clear_ptes(&va_range->sked_reflected.pt_range_vec, UVM_MEMBAR_NONE);
    uvm_page_table_range_vec_deinit(&va_range->sked_reflected.pt_range_vec);

    va_range->sked_reflected.gpu_va_space = NULL;
}

static void uvm_va_range_destroy_semaphore_pool(uvm_va_range_t *va_range)
{
    NV_STATUS status = uvm_tracker_wait_deinit(&va_range->semaphore_pool.tracker);
    if (status != NV_OK) {
        UVM_ASSERT_MSG(status == uvm_global_get_status(),
                "uvm_tracker_wait() returned %d (%s) in uvm_va_range_destroy_semaphore_pool()",
                status, nvstatusToString(status));
    }
    uvm_mem_free(va_range->semaphore_pool.mem);
    va_range->semaphore_pool.mem = NULL;
}

static void va_range_free(nv_kref_t *nv_kref)
{
    uvm_va_range_t *va_range = container_of(nv_kref, uvm_va_range_t, kref);
    UVM_ASSERT(!va_range->va_space);
    kmem_cache_free(g_uvm_va_range_cache, va_range);
}

void uvm_va_range_release(uvm_va_range_t *va_range)
{
    if (va_range)
        nv_kref_put(&va_range->kref, va_range_free);
}

void uvm_va_range_destroy(uvm_va_range_t *va_range, struct list_head *deferred_free_list)
{
    if (!va_range)
        return;

    UVM_ASSERT(va_range->va_space);

    if (!RB_EMPTY_NODE(&va_range->node.rb_node))
        uvm_range_tree_remove(&va_range->va_space->va_range_tree, &va_range->node);

    switch (va_range->type) {
        case UVM_VA_RANGE_TYPE_INVALID:
            // Skip partially-created ranges with unset types
            break;
        case UVM_VA_RANGE_TYPE_MANAGED:
            uvm_va_range_destroy_managed(va_range);
            break;
        case UVM_VA_RANGE_TYPE_EXTERNAL:
            uvm_va_range_destroy_external(va_range, deferred_free_list);
            break;
        case UVM_VA_RANGE_TYPE_CHANNEL:
            uvm_va_range_destroy_channel(va_range);
            break;
        case UVM_VA_RANGE_TYPE_SKED_REFLECTED:
            uvm_va_range_destroy_sked_reflected(va_range);
            break;
        case UVM_VA_RANGE_TYPE_SEMAPHORE_POOL:
            uvm_va_range_destroy_semaphore_pool(va_range);
            break;
        default:
            UVM_ASSERT_MSG(0, "[0x%llx, 0x%llx] has type %d\n",
                           va_range->node.start, va_range->node.end, va_range->type);
    }

    // Clear the VA space to indicate that this VA range is dead.
    va_range->va_space = NULL;

    uvm_va_range_release(va_range);
}

void uvm_va_range_zombify(uvm_va_range_t *va_range)
{
    if (!va_range)
        return;

    UVM_ASSERT(va_range->type == UVM_VA_RANGE_TYPE_MANAGED);
    UVM_ASSERT(va_range->managed.vma_wrapper);

    // Destroy will be done by uvm_destroy_vma_managed
    va_range->managed.vma_wrapper = NULL;
}

NV_STATUS uvm_api_clean_up_zombie_resources(UVM_CLEAN_UP_ZOMBIE_RESOURCES_PARAMS *params, struct file *filp)
{
    uvm_va_space_t *va_space = uvm_va_space_get(filp);
    uvm_va_range_t *va_range, *va_range_next;

    uvm_va_space_down_write(va_space);

    uvm_for_each_va_range_safe(va_range, va_range_next, va_space) {
        if (uvm_va_range_is_managed_zombie(va_range))
            uvm_va_range_destroy(va_range, NULL);
    }

    uvm_va_space_up_write(va_space);

    return NV_OK;
}

/**
 * uvm_api_map_vma_range() - Add a mapping between uvm_va_space_t and vm_area_struct
 *
 * This function adds a mapping between nvidia va_space and the vm_area
 * created for the mmaped file. It receives two addreses (in params):
 * uvm_base - the virtual address as returned by cudaMAllocManaged. Should
 *	    fall in the limits of current->mm->vma["nvidia_uvm"] -> [vm_start, vm_end]
 * cpu_base - the virtual address returned by mmap("myfile"). Pointing
 *	    to the base of vm_are_struct allocated in process memory space for the
 *	    mmaped file
 */
NV_STATUS uvm_api_map_vma_range(UVM_MAP_VMA_RANGE_PARAMS *params, struct file *filp)
{
    uvm_va_space_t *va_space = get_shared_mem_va_space();//uvm_va_space_get(filp);
    int i = 0;
    struct vm_area_struct *cpu_vma; //this is the vma created for map
    struct vm_area_struct *uvm_vma; //this is the vma created for uvm
    NV_STATUS ret = NV_OK;
    struct uvm_va_mappings_struct *new_map;
    
    //UCM_DBG("(file=%s) enter for uvm_base = 0x%llx cpu_base = 0x%llx\n", filp->f_path.dentry->d_iname,
//	params->uvm_base, params->cpu_base);

    if (!va_space) {
	UCM_ERR("va_space is null\n");
	ret = NV_ERR_GENERIC;
	goto out;
    }
    uvm_va_space_down_write(va_space);

	/* locate cpu vma in our mm ciresponding to params->cpu_base */
    cpu_vma = current->mm->mmap;
    while (i < current->mm->map_count && cpu_vma) {
	if (cpu_vma->vm_start == params->cpu_base && cpu_vma->gpu_mapped) {
		//UCM_DBG(" found cpu_vma! =%p\n", cpu_vma);
		break;
	}
	cpu_vma = cpu_vma->vm_next;
	i++;
    }
	if (!cpu_vma) {
		UCM_ERR("didn find cpu_vma for the given addr 0x%llx:\n", params->cpu_base);
		ret = NV_ERR_GENERIC;
		goto out;
	}

	/* locate uvm vma in our mm that is marked as gpu_managed */
    uvm_vma = current->mm->mmap;
    while (i < current->mm->map_count && uvm_vma) {
	if (uvm_vma->gpu_mapped_shared) {
		//UCM_DBG(" found uvm_vma! =%p\n", uvm_vma);
		break;
	}
	uvm_vma = uvm_vma->vm_next;
	i++;
    }
	if (!uvm_vma) {
		UCM_ERR("didn find uvm_vma for the given process\n");
		ret = NV_ERR_GENERIC;
		goto out;
	}

	new_map = &va_space->mmap_array[va_space->mmap_arr_idx++];
	if (new_map->mapped) {
		UCM_ERR("Entry at idx %d mapped\n", --va_space->mmap_arr_idx);
		ret = NV_ERR_GENERIC;
		goto out;
	}
	new_map->uvm_vma = uvm_vma;
	new_map->start = params->uvm_base;
	new_map->cpu_vma = cpu_vma;
	new_map->end = new_map->start + (cpu_vma->vm_end - cpu_vma->vm_start);
	new_map->mapped = true;

	BUG_ON(!cpu_vma->vm_file);
	INIT_LIST_HEAD(&cpu_vma->vm_file->f_mapping->gpu_lra);
	cpu_vma->vm_file->f_mapping->gpu_cached_data_sz = 0;
	cpu_vma->vm_file->f_mapping->gpu_cache_sz = 10;
//UCM_DBG("added new mapping at (uvm_vma=0x%llx) idx %d for nvidia_vma[0x%llx - 0x%llx], cpu_vma[0x%llx, 0x%llx]\n",
//va_space, va_space->mmap_arr_idx-1, new_map->start, new_map->end, cpu_vma->vm_start, cpu_vma->vm_end);

out:
    uvm_va_space_up_write(va_space);
    return ret;
}

static void cleanup_cache(struct vm_area_struct *cpu_vma) {

	int unmapped_error = 0;
	int error = -EINVAL;
	struct file *mfile = NULL;
	//struct pagevec pvec;
	int nr_pages;
	pgoff_t index, end;

	int num_gpu_pages = 0;
	index = 0;
	end = (cpu_vma->vm_end - cpu_vma->vm_start)/PAGE_SIZE;

	if (!cpu_vma)
		return;
	while ((index <= end) ) {
		unsigned i;
		int gpu_page_idx = -1;
		int *pages_idx;
		unsigned long tagged, tagged_gpu;

		pages_idx = (int*)kzalloc(sizeof(int)*(end - index + 1), GFP_KERNEL);
		if (!pages_idx) {
			UCM_ERR("Error allocating memory!\n");
			goto out;
		}
		nr_pages = find_get_taged_pages_idx(cpu_vma->vm_file->f_mapping, &index,
				end - index + 1, pages_idx, PAGECACHE_TAG_ON_GPU);

		if (!nr_pages) {
			//UCM_DBG("No pages taged as ON_GPU: index = %ld, nrpages=%ld\n", index, end - index + 1);
			break;
		}
		UCM_DBG("got %d pages taged ON_GPU\n", nr_pages);
		for (i = 0; i < nr_pages; i++) {
			int page_idx = pages_idx[i];
			/* until radix tree lookup accepts end_index */
			if (page_idx > end) {
				continue;
			}
			if (1) { //(gpu_page_idx == -1) || (gpu_page_idx != page_idx % 16)) {
				struct page *gpu_page = pagecache_get_gpu_page(cpu_vma->vm_file->f_mapping, page_idx, GPU_NVIDIA, true);
				if (gpu_page) {
					struct mem_cgroup *memcg = mem_cgroup_begin_page_stat(gpu_page);
					unsigned long flags;
					struct address_space *mapping = cpu_vma->vm_file->f_mapping;

					__set_page_locked(gpu_page);
					spin_lock_irqsave(&mapping->tree_lock, flags);
					__delete_from_page_cache_gpu(gpu_page, NULL, memcg, GPU_NVIDIA);
					spin_unlock_irqrestore(&mapping->tree_lock, flags);
					mem_cgroup_end_page_stat(memcg);
					__clear_page_locked(gpu_page);
					num_gpu_pages++;
				}
			}
		}
		kfree(pages_idx);
	}

out:
UCM_DBG("done. num_gpu_pages=%d \n",num_gpu_pages);
	return ;
}

/**
 * uvm_api_unmap_vma_range() - TODO
 *
 */
NV_STATUS uvm_api_unmap_vma_range(UVM_UNMAP_VMA_RANGE_PARAMS *params, struct file *filp)
{
    uvm_va_space_t *va_space =  get_shared_mem_va_space();//uvm_va_space_get(filp);
    int i = 0;
    NV_STATUS ret = NV_OK;
    struct uvm_va_mappings_struct *new_map;
    //UCM_DBG("enter for uvm_base = 0x%llx and uvm_va=%p\n", params->uvm_base, va_space);

    // Locate current mapping in the array
    for (i = 0; i < va_space->mmap_arr_idx; i++) {
	new_map = &va_space->mmap_array[i];
	if (new_map->start == params->uvm_base) {
//UCM_DBG("founed the entry for addr 0x%llx at idx %dnew_map->cpu_vma = 0x%llx\n", new_map->start, i, new_map->cpu_vma);
		//cleanup_cache(new_map->cpu_vma);
		new_map->mapped = false;
		va_space->mmap_arr_idx--;
		return ret;
	}
    }
    UCM_ERR("didnt find the mapping for addr 0x%llx\n", new_map->start);
    return NV_ERR_GENERIC;
}
#if 1
/**
 * uvm_api_touch_vma_range() - TODO
 *
 */
NV_STATUS uvm_api_touch_vma_range(UVM_TOUCH_RANGE_PARAMS *params, struct file *filp)
{
    uvm_va_space_t *va_space = get_shared_mem_va_space();//uvm_va_space_get(filp);
    int i = 0;
    NV_STATUS ret = NV_OK;
    struct vm_area_struct *uvm_vma;
    NvU64 fault_addr = params->start_addr;
    
    uvm_vma = current->mm->mmap;
    while (i < current->mm->map_count && uvm_vma) {
        if (uvm_vma->gpu_mapped_shared) {
            //    UCM_DBG(" found uvm_vma! =%p\n", uvm_vma);
                break;
        }
        uvm_vma = uvm_vma->vm_next;
        i++;
    }
	va_space->skip_cache = !va_space->skip_cache;
//UCM_DBG("Set va_space->skip_cache to %s\n", (va_space->skip_cache ? "true" : "false"));

    params->rmStatus = ret;
    return ret;
}
#endif
/**
 * uvm_get_uvm_mmap_addr() - Return the corresponding addr in vm_area of the mmaped file
 * va_space - pointer to uvm_va_space_t created for the current user
 * cpu_addr -??? 

 * When a page fault occurs in shared_memory ptr for addr that is mmaped to 
 * a file (via UVM_MAP_VMA_RANGE IOCTL in va_space->mmap_array[]), we need
 * to get the coresponding ptr in vm_arrea of the mmaped file in order to
 * have access to page cache and all relevant cb for reading the data from
 * disk. This function returns this addr.
 */
struct vm_area_struct *uvm_va_to_cpu_vma(uvm_va_space_t *va_space, NvU64 shared_addr)
{
	int i;
//UCM_DBG("uvm_va_space(%p)->mmap_arr_idx = %d, addr=0x%llx\n", va_space, va_space->mmap_arr_idx, shared_addr);
	for (i = 0; i < va_space->mmap_arr_idx; i++) {
		struct uvm_va_mappings_struct *map = &va_space->mmap_array[i];
		if ((map->start == shared_addr || map->start < shared_addr)  && 
		     map->end > shared_addr) {
//			UCM_DBG("found mapping for shared 0x%llx at idx %d. \n", 
//				shared_addr, i);
			return map->uvm_vma;
		}
//		UCM_DBG("shared_addr 0x%llx not part of uvm va space %p\n", shared_addr, va_space);
	}

	return NULL;
}

static NV_STATUS uvm_va_range_add_gpu_va_space_managed(uvm_va_range_t *va_range, uvm_gpu_va_space_t *gpu_va_space)
{
    uvm_va_block_t *va_block;
    uvm_va_space_t *va_space = va_range->va_space;
    NV_STATUS status = NV_OK;
    // by this time, the gpu is already in the registration mask.
    bool should_disable_read_duplication = va_range->read_duplication == UVM_READ_DUPLICATION_ENABLED &&
                                           uvm_va_space_can_read_duplicate(va_space, NULL) !=
                                           uvm_va_space_can_read_duplicate(va_space, gpu_va_space->gpu);

    // Now that we have a GPU VA space, map any VA ranges for which this GPU is
    // a UVM-Lite GPU or has accessed_by set.
    if (uvm_processor_mask_test(&va_range->accessed_by, gpu_va_space->gpu->id) ||
        uvm_processor_mask_test(&va_range->uvm_lite_gpus, gpu_va_space->gpu->id)) {
        for_each_va_block_in_va_range(va_range, va_block) {
            status = uvm_va_block_set_accessed_by(va_block, gpu_va_space->gpu->id);
            if (status != NV_OK)
                return status;
        }
    }

    if (should_disable_read_duplication)
        status = uvm_va_range_unset_read_duplication(va_range);

    return status;
}

NV_STATUS uvm_va_range_add_gpu_va_space(uvm_va_range_t *va_range, uvm_gpu_va_space_t *gpu_va_space)
{
    uvm_mem_gpu_mapping_attrs_t *attrs;

    switch (va_range->type) {
        case UVM_VA_RANGE_TYPE_MANAGED:
            return uvm_va_range_add_gpu_va_space_managed(va_range, gpu_va_space);
        case UVM_VA_RANGE_TYPE_SEMAPHORE_POOL:
            attrs = &va_range->semaphore_pool.gpu_attrs[gpu_va_space->gpu->id - 1];
            return uvm_mem_map_gpu_user(va_range->semaphore_pool.mem, gpu_va_space->gpu, attrs);
        default:
            return NV_OK;
    }
}

void uvm_va_range_remove_gpu_va_space_managed(uvm_va_range_t *va_range, uvm_gpu_va_space_t *gpu_va_space)
{
    uvm_va_block_t *va_block;
    uvm_va_space_t *va_space = va_range->va_space;
    bool should_enable_read_duplicate;

    uvm_assert_rwsem_locked_write(&va_space->lock);

    should_enable_read_duplicate = va_range->read_duplication == UVM_READ_DUPLICATION_ENABLED &&
                                   uvm_va_space_can_read_duplicate(va_space, NULL) !=
                                   uvm_va_space_can_read_duplicate(va_space, gpu_va_space->gpu);

    for_each_va_block_in_va_range(va_range, va_block) {
        uvm_mutex_lock(&va_block->lock);
        uvm_va_block_remove_gpu_va_space(va_block, gpu_va_space);
        uvm_mutex_unlock(&va_block->lock);

        if (should_enable_read_duplicate)
            uvm_va_block_set_read_duplication(va_block, &va_space->va_block_context);
    }
}

void uvm_va_range_remove_gpu_va_space(uvm_va_range_t *va_range,
                                      uvm_gpu_va_space_t *gpu_va_space,
                                      struct list_head *deferred_free_list)
{
    switch (va_range->type) {
        case UVM_VA_RANGE_TYPE_MANAGED:
            uvm_va_range_remove_gpu_va_space_managed(va_range, gpu_va_space);
            break;
        case UVM_VA_RANGE_TYPE_EXTERNAL:
            // This function does nothing if the GPU has no mappings in the VA
            // range.
            UVM_ASSERT(deferred_free_list);
            uvm_ext_gpu_map_destroy(va_range, gpu_va_space->gpu, deferred_free_list);
            break;
        case UVM_VA_RANGE_TYPE_CHANNEL:
            // All channels under this GPU VA space should've been removed before
            // removing the GPU VA space.
            UVM_ASSERT(va_range->channel.gpu_va_space != gpu_va_space);
            break;
        case UVM_VA_RANGE_TYPE_SKED_REFLECTED:
            if (va_range->sked_reflected.gpu_va_space == gpu_va_space)
                uvm_va_range_destroy_sked_reflected(va_range);
            break;
        case UVM_VA_RANGE_TYPE_SEMAPHORE_POOL:
            uvm_mem_unmap_gpu(va_range->semaphore_pool.mem, gpu_va_space->gpu);
            break;
        default:
            UVM_ASSERT_MSG(0, "[0x%llx, 0x%llx] has type %d\n",
                           va_range->node.start, va_range->node.end, va_range->type);
    }
}

static NV_STATUS uvm_va_range_enable_peer_managed(uvm_va_range_t *va_range, uvm_gpu_t *gpu0, uvm_gpu_t *gpu1)
{
    NV_STATUS status;
    uvm_va_block_t *va_block;
    bool gpu0_accessed_by = uvm_processor_mask_test(&va_range->accessed_by, gpu0->id);
    bool gpu1_accessed_by = uvm_processor_mask_test(&va_range->accessed_by, gpu1->id);

    if (!gpu0_accessed_by && !gpu1_accessed_by)
        return NV_OK;

    for_each_va_block_in_va_range(va_range, va_block) {
        // For UVM-Lite at most one GPU needs to map the peer GPU if it's the
        // preferred location, but it doesn't hurt to just try mapping both.
        if (gpu0_accessed_by) {
            status = uvm_va_block_set_accessed_by(va_block, gpu0->id);
            if (status != NV_OK)
                return status;
        }

        if (gpu1_accessed_by) {
            status = uvm_va_block_set_accessed_by(va_block, gpu1->id);
            if (status != NV_OK)
                return status;
        }
    }

    return NV_OK;
}

NV_STATUS uvm_va_range_enable_peer(uvm_va_range_t *va_range, uvm_gpu_t *gpu0, uvm_gpu_t *gpu1)
{
    switch (va_range->type) {
        case UVM_VA_RANGE_TYPE_MANAGED:
            return uvm_va_range_enable_peer_managed(va_range, gpu0, gpu1);
        case UVM_VA_RANGE_TYPE_EXTERNAL:
            // UVM_VA_RANGE_TYPE_EXTERNAL doesn't create new mappings when enabling peer access
            return NV_OK;
        case UVM_VA_RANGE_TYPE_CHANNEL:
            // UVM_VA_RANGE_TYPE_CHANNEL should never have peer mappings
            return NV_OK;
        case UVM_VA_RANGE_TYPE_SKED_REFLECTED:
            // UVM_VA_RANGE_TYPE_SKED_REFLECTED should never have peer mappings
            return NV_OK;
        case UVM_VA_RANGE_TYPE_SEMAPHORE_POOL:
            // UVM_VA_RANGE_TYPE_SEMAPHORE_POOL should never have peer mappings
            return NV_OK;
        default:
            UVM_ASSERT_MSG(0, "[0x%llx, 0x%llx] has type %d\n",
                           va_range->node.start, va_range->node.end, va_range->type);
            return NV_ERR_NOT_SUPPORTED;
    }
}

static void uvm_va_range_disable_peer_external(uvm_va_range_t *va_range,
                                               uvm_gpu_t *gpu0,
                                               uvm_gpu_t *gpu1,
                                               struct list_head *deferred_free_list)
{
    uvm_ext_gpu_map_t *ext_gpu_map;

    // If GPU 0 has a mapping to GPU 1, remove GPU 0's mapping
    ext_gpu_map = uvm_va_range_ext_gpu_map(va_range, gpu0);
    if (ext_gpu_map && ext_gpu_map->aperture == uvm_gpu_peer_aperture(gpu0, gpu1)) {
        UVM_ASSERT(deferred_free_list);
        uvm_ext_gpu_map_destroy(va_range, gpu0, deferred_free_list);
    }

    // If GPU 1 has a mapping to GPU 0, remove GPU 1's mapping
    ext_gpu_map = uvm_va_range_ext_gpu_map(va_range, gpu1);
    if (ext_gpu_map && ext_gpu_map->aperture == uvm_gpu_peer_aperture(gpu1, gpu0)) {
        UVM_ASSERT(deferred_free_list);
        uvm_ext_gpu_map_destroy(va_range, gpu1, deferred_free_list);
    }
}

static void uvm_va_range_disable_peer_managed(uvm_va_range_t *va_range, uvm_gpu_t *gpu0, uvm_gpu_t *gpu1)
{
    uvm_va_block_t *va_block;
    uvm_gpu_t *uvm_lite_gpu_to_unmap = NULL;

    bool uvm_lite_mode = uvm_processor_mask_test(&va_range->uvm_lite_gpus, gpu0->id) &&
                         uvm_processor_mask_test(&va_range->uvm_lite_gpus, gpu1->id);

    if (uvm_lite_mode) {
        // In UVM-Lite mode, the UVM-Lite GPUs can only have mappings to the the
        // preferred location. If peer mappings are being disabled to the
        // preferred location, then unmap the other GPU.
        // Nothing to do otherwise.
        if (va_range->preferred_location == gpu0->id)
            uvm_lite_gpu_to_unmap = gpu1;
        else if (va_range->preferred_location == gpu1->id)
            uvm_lite_gpu_to_unmap = gpu0;
        else
            return;
    }

    for_each_va_block_in_va_range(va_range, va_block) {
        uvm_mutex_lock(&va_block->lock);
        if (uvm_lite_mode)
            uvm_va_block_unmap_preferred_location_uvm_lite(va_block, uvm_lite_gpu_to_unmap);
        else
            uvm_va_block_disable_peer(va_block, gpu0, gpu1);
        uvm_mutex_unlock(&va_block->lock);
    }

    if (uvm_lite_mode && !uvm_range_group_all_migratable(va_range->va_space, va_range->node.start, va_range->node.end)) {
        UVM_ASSERT(uvm_lite_gpu_to_unmap);

        // Migration is prevented, but we had to unmap a UVM-Lite GPU. Update
        // the accessed by and UVM-Lite GPUs masks as it cannot be considered a
        // UVM-Lite GPU any more.
        uvm_va_range_unset_accessed_by(va_range, uvm_lite_gpu_to_unmap->id);
    }
}

void uvm_va_range_disable_peer(uvm_va_range_t *va_range,
                               uvm_gpu_t *gpu0,
                               uvm_gpu_t *gpu1,
                               struct list_head *deferred_free_list)
{

    switch (va_range->type) {
        case UVM_VA_RANGE_TYPE_MANAGED:
            uvm_va_range_disable_peer_managed(va_range, gpu0, gpu1);
            break;
        case UVM_VA_RANGE_TYPE_EXTERNAL:
            uvm_va_range_disable_peer_external(va_range, gpu0, gpu1, deferred_free_list);
            break;
        case UVM_VA_RANGE_TYPE_CHANNEL:
            // UVM_VA_RANGE_TYPE_CHANNEL should never have peer mappings
            break;
        case UVM_VA_RANGE_TYPE_SKED_REFLECTED:
            // UVM_VA_RANGE_TYPE_SKED_REFLECTED should never have peer mappings
            break;
        case UVM_VA_RANGE_TYPE_SEMAPHORE_POOL:
            // UVM_VA_RANGE_TYPE_SEMAPHORE_POOL should never have peer mappings
            break;
        default:
            UVM_ASSERT_MSG(0, "[0x%llx, 0x%llx] has type %d\n",
                           va_range->node.start, va_range->node.end, va_range->type);
    }
}

static void uvm_va_range_unregister_gpu_managed(uvm_va_range_t *va_range, uvm_gpu_t *gpu)
{
    uvm_va_block_t *va_block;

    // Reset preferred location and accessed-by of VA ranges if needed
    // Note: ignoring the return code of uvm_va_range_set_preferred_location since this
    // will only return on error when setting a preferred location, not on a reset
    if (va_range->preferred_location == gpu->id)
        (void)uvm_va_range_set_preferred_location(va_range, UVM8_MAX_PROCESSORS);

    uvm_va_range_unset_accessed_by(va_range, gpu->id);

    // Migrate and free any remaining resident allocations on this GPU
    for_each_va_block_in_va_range(va_range, va_block)
        uvm_va_block_unregister_gpu(va_block, gpu);
}

// The GPU being unregistered can't have any remaining mappings, since those
// were removed when the corresponding GPU VA space was removed. However, other
// GPUs could still have mappings to memory resident on this GPU, so we have to
// unmap those.
static void uvm_va_range_unregister_gpu_external(uvm_va_range_t *va_range,
                                                 uvm_gpu_t *gpu,
                                                 struct list_head *deferred_free_list)
{
    uvm_ext_gpu_map_t *ext_gpu_map;
    uvm_gpu_t *other_gpu;

    for_each_gpu_in_mask(other_gpu, &va_range->external.mapped_gpus) {
        UVM_ASSERT(other_gpu != gpu);

        ext_gpu_map = uvm_va_range_ext_gpu_map(va_range, other_gpu);
        UVM_ASSERT(ext_gpu_map);

        if (ext_gpu_map->owning_gpu == gpu) {
            UVM_ASSERT(deferred_free_list);
            uvm_ext_gpu_map_destroy(va_range, other_gpu, deferred_free_list);
        }
    }
}

static void uvm_va_range_unregister_gpu_semaphore_pool(uvm_va_range_t *va_range, uvm_gpu_t *gpu)
{
    NV_STATUS status;

    // All ranges for this GPU should have been unmapped by GPU VA space
    // unregister, which should have already happened.
    UVM_ASSERT(!uvm_processor_mask_test(&va_range->semaphore_pool.mem->mapped_on, gpu->id));
    uvm_mutex_lock(&va_range->semaphore_pool.tracker_lock);
    status = uvm_tracker_wait(&va_range->semaphore_pool.tracker);
    uvm_mutex_unlock(&va_range->semaphore_pool.tracker_lock);
    if (status != NV_OK)
        UVM_ASSERT(status == uvm_global_get_status());

    uvm_mem_unmap_gpu_phys(va_range->semaphore_pool.mem, gpu);

    va_range->semaphore_pool.gpu_attrs[gpu->id - 1] = va_range->semaphore_pool.default_gpu_attrs;
    if (va_range->semaphore_pool.owner == gpu)
        va_range->semaphore_pool.owner = NULL;
}

void uvm_va_range_unregister_gpu(uvm_va_range_t *va_range, uvm_gpu_t *gpu, struct list_head *deferred_free_list)
{
    switch (va_range->type) {
        case UVM_VA_RANGE_TYPE_MANAGED:
            uvm_va_range_unregister_gpu_managed(va_range, gpu);
            break;
        case UVM_VA_RANGE_TYPE_EXTERNAL:
            uvm_va_range_unregister_gpu_external(va_range, gpu, deferred_free_list);
            break;
        case UVM_VA_RANGE_TYPE_CHANNEL:
            // All ranges should have been destroyed by GPU VA space unregister,
            // which should have already happened.
            UVM_ASSERT(va_range->channel.gpu_va_space->gpu != gpu);
            break;
        case UVM_VA_RANGE_TYPE_SKED_REFLECTED:
            // All ranges for this GPU should have been unmapped by GPU VA space
            // unregister (uvm_va_range_destroy_sked_reflected), which should
            // have already happened.
            if (va_range->sked_reflected.gpu_va_space != NULL)
                UVM_ASSERT(va_range->sked_reflected.gpu_va_space->gpu != gpu);
            break;
        case UVM_VA_RANGE_TYPE_SEMAPHORE_POOL:
            uvm_va_range_unregister_gpu_semaphore_pool(va_range, gpu);
            break;
        default:
            UVM_ASSERT_MSG(0, "[0x%llx, 0x%llx] has type %d\n",
                           va_range->node.start, va_range->node.end, va_range->type);
    }
}

// Split existing's blocks into new. new's blocks array has already been
// allocated. This is called before existing's range node is split, so it
// overlaps new. new is always in the upper region of existing.
//
// The caller will do the range tree split.
//
// If this fails it leaves existing unchanged.
static NV_STATUS uvm_va_range_split_blocks(uvm_va_range_t *existing, uvm_va_range_t *new)
{
    uvm_va_block_t *old_block, *block = NULL;
    size_t existing_blocks, split_index, new_index = 0;
    NV_STATUS status;

    UVM_ASSERT(new->node.start >  existing->node.start);
    UVM_ASSERT(new->node.end   <= existing->node.end);

    split_index = uvm_va_range_block_index(existing, new->node.start);

    // Handle a block spanning the split point
    if (block_calc_start(existing, split_index) != new->node.start) {
        // If a populated block actually spans the split point, we have to split
        // the block. Otherwise just account for the extra entry in the arrays.
        old_block = uvm_va_range_block(existing, split_index);
        if (old_block) {
            UVM_ASSERT(old_block->start < new->node.start);
            status = uvm_va_block_split(old_block, new->node.start - 1, &block, new);
            if (status != NV_OK)
                return status;

            // No memory barrier is needed since we're holding the va_space lock in
            // write mode, so no other thread can access the blocks array.
            atomic_long_set(&new->blocks[0], (long)block);
        }

        new_index = 1;
    }

    // uvm_va_block_split gets first crack at injecting an error. If it did so,
    // we wouldn't be here. However, not all splits will call uvm_va_block_split
    // so we need an extra check here. We can't push this injection later since
    // all paths past this point assume success, so they modify existing's
    // state.
    if (existing->inject_split_error) {
        UVM_ASSERT(!block);
        existing->inject_split_error = false;
        return NV_ERR_NO_MEMORY;
    }

    existing_blocks = split_index + new_index;

    // Copy existing's blocks over to new, accounting for the explicit
    // assignment above in case we did a block split. There are two general
    // cases:
    //
    // No split:
    //                                    split_index
    //                                         v
    //  existing (before) [----- A ----][----- B ----][----- C ----]
    //  existing (after)  [----- A ----]
    //  new                             [----- B ----][----- C ----]
    //
    // Split:
    //                                    split_index
    //                                         v
    //  existing (before) [----- A ----][----- B ----][----- C ----]
    //  existing (after   [----- A ----][- B -]
    //  new                                    [- N -][----- C ----]
    //                                            ^new->blocks[0]

    // Note, if we split the last block of existing, this won't iterate at all.
    for (; new_index < uvm_va_range_num_blocks(new); new_index++) {
        block = uvm_va_range_block(existing, split_index + new_index);
        if (!block) {
            // new's array was cleared at allocation
            UVM_ASSERT(uvm_va_range_block(new, new_index) == NULL);
            continue;
        }

        // As soon as we make this assignment and drop the lock, the reverse
        // mapping code can start looking at new, so new must be ready to go.
        uvm_mutex_lock(&block->lock);
        UVM_ASSERT(block->va_range == existing);
 WARN_ON(!new);
        block->va_range = new;
        uvm_mutex_unlock(&block->lock);

        // No memory barrier is needed since we're holding the va_space lock in
        // write mode, so no other thread can access the blocks array.
        atomic_long_set(&new->blocks[new_index], (long)block);
        atomic_long_set(&existing->blocks[split_index + new_index], (long)NULL);
    }

    blocks_array_shrink(existing, existing_blocks);

    return NV_OK;
}

NV_STATUS uvm_va_range_split(uvm_va_range_t *existing_va_range,
                             NvU64 new_end,
                             uvm_va_range_t **new_va_range)
{
    uvm_va_space_t *va_space = existing_va_range->va_space;
    uvm_va_range_t *new = NULL;
    uvm_perf_event_data_t event_data;
    NV_STATUS status;

    UVM_ASSERT(existing_va_range->type == UVM_VA_RANGE_TYPE_MANAGED);
    UVM_ASSERT(new_end > existing_va_range->node.start);
    UVM_ASSERT(new_end < existing_va_range->node.end);
    UVM_ASSERT(PAGE_ALIGNED(new_end + 1));
    uvm_assert_rwsem_locked_write(&va_space->lock);

    new = uvm_va_range_alloc_managed(va_space, new_end + 1, existing_va_range->node.end);
    if (!new) {
        status = NV_ERR_NO_MEMORY;
        goto error;
    }

    // The new va_range is under the same vma. If this is a uvm_vm_open, the
    // caller takes care of updating existing's vma_wrapper for us.
    new->managed.vma_wrapper = existing_va_range->managed.vma_wrapper;

    // Copy over state before splitting blocks so any block lookups happening
    // concurrently on the eviction path will see the new range's data.
    new->read_duplication = existing_va_range->read_duplication;
    new->preferred_location = existing_va_range->preferred_location;
    memcpy(&new->accessed_by, &existing_va_range->accessed_by, sizeof(new->accessed_by));
    memcpy(&new->uvm_lite_gpus, &existing_va_range->uvm_lite_gpus, sizeof(new->uvm_lite_gpus));

    status = uvm_va_range_split_blocks(existing_va_range, new);
    if (status != NV_OK)
        goto error;

    // Finally, update the VA range tree
    uvm_range_tree_split(&va_space->va_range_tree, &existing_va_range->node, &new->node);

    if (new->type == UVM_VA_RANGE_TYPE_MANAGED) {
        event_data.range_shrink.range = new;
        uvm_perf_event_notify(&va_space->perf_events, UVM_PERF_EVENT_RANGE_SHRINK, &event_data);
    }

    if (new_va_range)
        *new_va_range = new;
    return NV_OK;

error:
    uvm_va_range_destroy(new, NULL);
    return status;

}

static inline uvm_va_range_t *uvm_va_range_container(uvm_range_tree_node_t *node)
{
    if (!node)
        return NULL;
    return container_of(node, uvm_va_range_t, node);
}

uvm_va_range_t *uvm_va_range_find(uvm_va_space_t *va_space, NvU64 addr)
{
    uvm_assert_rwsem_locked(&va_space->lock);
    return uvm_va_range_container(uvm_range_tree_find(&va_space->va_range_tree, addr));
}

uvm_va_range_t *uvm_va_space_iter_first(uvm_va_space_t *va_space, NvU64 start, NvU64 end)
{
    uvm_range_tree_node_t *node = uvm_range_tree_iter_first(&va_space->va_range_tree, start, end);
    return uvm_va_range_container(node);
}

uvm_va_range_t *uvm_va_space_iter_next(uvm_va_range_t *va_range, NvU64 end)
{
    uvm_range_tree_node_t *node;

    // Handling a NULL va_range here makes uvm_for_each_va_range_in_safe much
    // less messy
    if (!va_range)
        return NULL;

    node = uvm_range_tree_iter_next(&va_range->va_space->va_range_tree, &va_range->node, end);
    return uvm_va_range_container(node);
}

size_t uvm_va_range_num_blocks(uvm_va_range_t *va_range)
{
    NvU64 start = UVM_VA_BLOCK_ALIGN_DOWN(va_range->node.start);
    NvU64 end   = UVM_VA_BLOCK_ALIGN_UP(va_range->node.end); // End is inclusive
    return (end - start) / UVM_VA_BLOCK_SIZE;
}

size_t uvm_va_range_block_index(uvm_va_range_t *va_range, NvU64 addr)
{
    size_t addr_index, start_index, index;

    UVM_ASSERT(addr >= va_range->node.start);
    UVM_ASSERT(addr <= va_range->node.end);
    UVM_ASSERT(va_range->type == UVM_VA_RANGE_TYPE_MANAGED);

    // Each block will cover as much space as possible within the aligned
    // UVM_VA_BLOCK_SIZE, up to the parent VA range boundaries. In other words,
    // the entire VA space can be broken into UVM_VA_BLOCK_SIZE chunks. Even if
    // there are multiple ranges (and thus multiple blocks) per actual
    // UVM_VA_BLOCK_SIZE chunk, none of those will have more than 1 block unless
    // they span a UVM_VA_BLOCK_SIZE alignment boundary.
    addr_index = (size_t)(addr / UVM_VA_BLOCK_SIZE);
    start_index = (size_t)(va_range->node.start / UVM_VA_BLOCK_SIZE);

    index = addr_index - start_index;
    UVM_ASSERT(index < uvm_va_range_num_blocks(va_range));
    return index;
}

NV_STATUS uvm_va_range_block_create(uvm_va_range_t *va_range, size_t index, uvm_va_block_t **out_block)
{
    uvm_va_block_t *block, *old;
    NV_STATUS status;

    block = uvm_va_range_block(va_range, index);
    if (!block) {
        // No block has been created here yet, so allocate one and attempt to
        // insert it. Note that this runs the risk of an out-of-memory error
        // when multiple threads race and all concurrently allocate a block for
        // the same address. This should be extremely rare. There is also
        // precedent in the Linux kernel, which does the same thing for demand-
        // allocation of anonymous pages.
        status = uvm_va_block_create(va_range,
                                     block_calc_start(va_range, index),
                                     block_calc_end(va_range, index),
                                     &block);
        if (status != NV_OK)
            return status;

        // Try to insert it
        old = (uvm_va_block_t *)nv_atomic_long_cmpxchg(&va_range->blocks[index],
                                                      (long)NULL,
                                                      (long)block);
        if (old) {
            // Someone else beat us on the insert
            uvm_va_block_release(block);
            block = old;
        }
    }

    *out_block = block;
    return NV_OK;
}

uvm_va_block_t *uvm_va_range_block_next(uvm_va_range_t *va_range, uvm_va_block_t *va_block)
{
    uvm_va_space_t *va_space = va_range->va_space;
    size_t i = 0;

    uvm_assert_rwsem_locked(&va_space->lock);

    UVM_ASSERT(va_range->type == UVM_VA_RANGE_TYPE_MANAGED);

    if (va_block)
        i = uvm_va_range_block_index(va_range, va_block->start) + 1;

    for (; i < uvm_va_range_num_blocks(va_range); i++) {
        va_block = uvm_va_range_block(va_range, i);
        if (va_block) {
            UVM_ASSERT(va_block->va_range == va_range);
            UVM_ASSERT(uvm_va_range_block_index(va_range, va_block->start) == i);
            return va_block;
        }
    }

    return NULL;
}

static NV_STATUS range_unmap_mask(uvm_va_range_t *va_range, uvm_processor_mask_t *mask)
{
    NV_STATUS status = NV_OK;
    NV_STATUS block_status;
    uvm_va_space_t *va_space = va_range->va_space;
    uvm_va_block_t *block;
    uvm_va_block_region_t region;

    UVM_ASSERT_MSG(va_range->type == UVM_VA_RANGE_TYPE_MANAGED, "type 0x%x\n", va_range->type);
    uvm_assert_rwsem_locked_write(&va_space->lock);

    for_each_va_block_in_va_range(va_range, block) {
        region = uvm_va_block_region_from_block(block);
        uvm_mutex_lock(&block->lock);
        block_status = uvm_va_block_unmap_mask(block, &va_space->va_block_context, mask, region, NULL);
        uvm_mutex_unlock(&block->lock);
        if (status == NV_OK)
            status = block_status;
    }

    return status;
}

static NV_STATUS range_unmap(uvm_va_range_t *va_range, uvm_processor_id_t processor)
{
    uvm_processor_mask_t mask;

    UVM_ASSERT_MSG(va_range->type == UVM_VA_RANGE_TYPE_MANAGED, "type 0x%x\n", va_range->type);

    uvm_processor_mask_zero(&mask);
    uvm_processor_mask_set(&mask, processor);

    return range_unmap_mask(va_range, &mask);
}

static NV_STATUS range_map_uvm_lite_gpus(uvm_va_range_t *va_range)
{
    NV_STATUS status = NV_OK;
    uvm_va_block_t *va_block;
    uvm_va_block_context_t *va_block_context;

    UVM_ASSERT(va_range->type == UVM_VA_RANGE_TYPE_MANAGED);

    if (uvm_processor_mask_empty(&va_range->uvm_lite_gpus))
        return NV_OK;

    va_block_context = uvm_va_block_context_alloc();
    if (!va_block_context)
        return NV_ERR_NO_MEMORY;

    for_each_va_block_in_va_range(va_range, va_block) {
        // UVM-Lite GPUs always map with RWA
        status = UVM_VA_BLOCK_LOCK_RETRY(va_block, NULL,
                uvm_va_block_map_mask(va_block,
                                      va_block_context,
                                      &va_range->uvm_lite_gpus,
                                      uvm_va_block_region_from_block(va_block),
                                      NULL,
                                      UVM_PROT_READ_WRITE_ATOMIC,
                                      UvmEventMapRemoteCauseCoherence));
        if (status != NV_OK)
            break;
    }

    uvm_va_block_context_free(va_block_context);
    return status;
}

// Calculate the mask of GPUs that should follow the UVM-Lite behaviour
static void calc_uvm_lite_gpus_mask(uvm_va_space_t *va_space,
                                    uvm_processor_id_t preferred_location,
                                    uvm_processor_mask_t *accessed_by_mask,
                                    uvm_processor_mask_t *uvm_lite_gpus)
{
    uvm_gpu_id_t gpu_id;

    uvm_assert_rwsem_locked_write(&va_space->lock);

    // Zero out the mask first
    uvm_processor_mask_zero(uvm_lite_gpus);

    // If no preferred location is set then there are no GPUs following the UVM-Lite behavior
    if (preferred_location == UVM8_MAX_PROCESSORS)
        return;

    // If the preferred location is a faultable GPU, then no GPUs should follow
    // the UVM-Lite behaviour.
    if (preferred_location != UVM_CPU_ID && uvm_processor_mask_test(&va_space->faultable_processors, preferred_location))
        return;

    // Otherwise add all non-faultable GPUs to the UVM-Lite mask that have
    // accessed by set.
    for_each_gpu_id_in_mask(gpu_id, accessed_by_mask) {
        if (!uvm_processor_mask_test(&va_space->faultable_processors, gpu_id))
            uvm_processor_mask_set(uvm_lite_gpus, gpu_id);
    }

    // And the preferred location if it's a GPU
    if (preferred_location != UVM_CPU_ID)
        uvm_processor_mask_set(uvm_lite_gpus, preferred_location);
}

// Update the mask of GPUs that follow the UVM-Lite behaviour
static void range_update_uvm_lite_gpus_mask(uvm_va_range_t *va_range)
{
    UVM_ASSERT(va_range->type == UVM_VA_RANGE_TYPE_MANAGED);
    calc_uvm_lite_gpus_mask(va_range->va_space,
                            va_range->preferred_location,
                            &va_range->accessed_by,
                            &va_range->uvm_lite_gpus);
}

NV_STATUS uvm_va_range_set_preferred_location(uvm_va_range_t *va_range, uvm_processor_id_t preferred_location)
{
    NV_STATUS status;
    uvm_processor_mask_t gpus;
    uvm_processor_mask_t old_uvm_lite_gpus;
    uvm_processor_mask_t new_uvm_lite_gpus;
    uvm_gpu_id_t gpu_id;
    uvm_range_group_range_iter_t iter;
    uvm_range_group_range_t *rgr = NULL;
    uvm_processor_id_t old_preferred_location = va_range->preferred_location;

    size_t i;
    uvm_assert_rwsem_locked_write(&va_range->va_space->lock);
    UVM_ASSERT(va_range->type == UVM_VA_RANGE_TYPE_MANAGED);

    if (va_range->preferred_location == preferred_location)
        return NV_OK;

    // Mark all range group ranges within this VA range as migrated since the preferred location has changed.
    uvm_range_group_for_each_range_in(rgr, va_range->va_space, va_range->node.start, va_range->node.end) {
        uvm_spin_lock(&rgr->range_group->migrated_ranges_lock);
        if (list_empty(&rgr->range_group_migrated_list_node))
            list_move_tail(&rgr->range_group_migrated_list_node, &rgr->range_group->migrated_ranges);
        uvm_spin_unlock(&rgr->range_group->migrated_ranges_lock);
    }

    // Calculate the new UVM-Lite GPUs mask, but don't update va_range state so
    // that we can keep block_page_check_mappings() happy while updating the
    // mappings.
    calc_uvm_lite_gpus_mask(va_range->va_space, preferred_location, &va_range->accessed_by, &new_uvm_lite_gpus);

    // If the range contains non-migratable range groups, check that new UVM-Lite GPUs
    // can all map the new preferred location.
    if (!uvm_range_group_all_migratable(va_range->va_space, va_range->node.start, va_range->node.end) &&
        preferred_location != UVM8_MAX_PROCESSORS &&
        !uvm_processor_mask_subset(&new_uvm_lite_gpus,
                                   &va_range->va_space->accessible_from[preferred_location]))
        return NV_ERR_INVALID_DEVICE;

    if (preferred_location == UVM8_MAX_PROCESSORS) {
        uvm_range_group_for_each_migratability_in_safe(&iter,
                                                       va_range->va_space,
                                                       va_range->node.start,
                                                       va_range->node.end) {
            if (!iter.migratable) {
                // Clear the range group assocation for any unmigratable ranges if there is no preferred location
                status = uvm_range_group_assign_range(va_range->va_space, NULL, iter.start, iter.end);
                if (status != NV_OK)
                    return status;
            }
        }
    }

    // Save the old UVM-Lite GPUs
    uvm_processor_mask_copy(&old_uvm_lite_gpus, &va_range->uvm_lite_gpus);

    // Unmap all old and new UVM-Lite GPUs
    //  - GPUs that stop being UVM-Lite need to be unmapped so that they don't
    //    have stale mappings to the old preferred location.
    //  - GPUs that will continue to be UVM-Lite GPUs or are new UVM-Lite GPUs
    //    need to be unmapped so that the new preferred location can be mapped.
    uvm_processor_mask_or(&gpus, &old_uvm_lite_gpus, &new_uvm_lite_gpus);
    status = range_unmap_mask(va_range, &gpus);
    if (status != NV_OK)
        return status;

    // Now update the va_range state
    va_range->preferred_location = preferred_location;
    uvm_processor_mask_copy(&va_range->uvm_lite_gpus, &new_uvm_lite_gpus);

    // GPUs that stop being UVM-Lite, but are in the accessed_by mask need to
    // have any possible mappings established.
    uvm_processor_mask_andnot(&gpus, &old_uvm_lite_gpus, &new_uvm_lite_gpus);
    uvm_processor_mask_and(&gpus, &gpus, &va_range->accessed_by);

    for_each_gpu_id_in_mask(gpu_id, &gpus) {
        uvm_va_block_t *va_block;
        for_each_va_block_in_va_range(va_range, va_block) {
            status = uvm_va_block_set_accessed_by(va_block, gpu_id);
            if (status != NV_OK)
                return status;
        }
    }

    // The preferred location changed, so:
    // - everything is dirty because the new processor may not have up-to-date
    //   data.
    // - pages pinned due to thrashing on the old preferred location, need to
    //   be unpinned.
    for (i = 0; i < uvm_va_range_num_blocks(va_range); i++) {
        uvm_va_block_t *va_block = uvm_va_range_block(va_range, i);
        if (va_block) {
            uvm_va_block_retry_t va_block_retry;
            uvm_mutex_lock(&va_block->lock);
            uvm_va_block_mark_cpu_dirty(va_block);

            // Notify the thrashing detection policy
            status = UVM_VA_BLOCK_RETRY_LOCKED(va_block,
                                               &va_block_retry,
                                               uvm_perf_thrashing_change_preferred_location(va_block,
                                                                                            preferred_location,
                                                                                            old_preferred_location));
            uvm_mutex_unlock(&va_block->lock);
        }
    }

    // And lastly map all of the current UVM-Lite GPUs to the resident pages on
    // the new preferred location. Anything that's not resident right now will
    // get mapped on the next PreventMigration().
    return range_map_uvm_lite_gpus(va_range);
}

NV_STATUS uvm_va_range_set_accessed_by(uvm_va_range_t *va_range, uvm_processor_id_t processor_id)
{
    NV_STATUS status;
    uvm_va_block_t *va_block;
    uvm_processor_mask_t new_uvm_lite_gpus;

    // If the range belongs to a non-migratable range group and that processor_id is a non-faultable GPU,
    // check it can map the preferred location
    if (!uvm_range_group_all_migratable(va_range->va_space, va_range->node.start, va_range->node.end) &&
        processor_id != UVM_CPU_ID &&
        !uvm_processor_mask_test(&va_range->va_space->faultable_processors, processor_id) &&
        !uvm_processor_mask_test(&va_range->va_space->accessible_from[va_range->preferred_location], processor_id))
        return NV_ERR_INVALID_DEVICE;

    uvm_processor_mask_set(&va_range->accessed_by, processor_id);

    // If a GPU is already a UVM-Lite GPU then there is nothing else to do.
    if (uvm_processor_mask_test(&va_range->uvm_lite_gpus, processor_id))
        return NV_OK;

    // Calculate the new UVM-Lite GPUs mask, but don't update it in the va range
    // yet so that we can keep block_page_check_mappings() happy while updating
    // the mappings.
    calc_uvm_lite_gpus_mask(va_range->va_space,
                            va_range->preferred_location,
                            &va_range->accessed_by,
                            &new_uvm_lite_gpus);

    if (uvm_processor_mask_test(&new_uvm_lite_gpus, processor_id)) {
        // GPUs that become UVM-Lite GPUs need to unmap everything so that they
        // can map the preferred location.
        status = range_unmap(va_range, processor_id);
        if (status != NV_OK)
            return status;
    }

    uvm_processor_mask_copy(&va_range->uvm_lite_gpus, &new_uvm_lite_gpus);

    for_each_va_block_in_va_range(va_range, va_block) {
        status = uvm_va_block_set_accessed_by(va_block, processor_id);
        if (status != NV_OK)
            return status;
    }

    return NV_OK;
}

void uvm_va_range_unset_accessed_by(uvm_va_range_t *va_range, uvm_processor_id_t processor_id)
{
    uvm_range_group_range_t *rgr = NULL;

    // Mark all range group ranges within this VA range as migrated. We do this to force
    // uvm_range_group_set_migration_policy to re-check the policy state since we're changing it here.
    uvm_range_group_for_each_range_in(rgr, va_range->va_space, va_range->node.start, va_range->node.end) {
        uvm_spin_lock(&rgr->range_group->migrated_ranges_lock);
        if (list_empty(&rgr->range_group_migrated_list_node))
            list_move_tail(&rgr->range_group_migrated_list_node, &rgr->range_group->migrated_ranges);
        uvm_spin_unlock(&rgr->range_group->migrated_ranges_lock);
    }

    uvm_processor_mask_clear(&va_range->accessed_by, processor_id);

    // If a UVM-Lite GPU is being removed from the accessed_by mask, it will
    // also stop being a UVM-Lite GPU unless it's also the preferred location.
    if (uvm_processor_mask_test(&va_range->uvm_lite_gpus, processor_id) && va_range->preferred_location != processor_id)
        range_unmap(va_range, processor_id);

    range_update_uvm_lite_gpus_mask(va_range);
}

NV_STATUS uvm_va_range_set_read_duplication(uvm_va_range_t *va_range)
{
    NV_STATUS status = NV_OK;
    uvm_va_block_t *va_block;
    uvm_va_block_context_t *va_block_context;

    if (va_range->read_duplication == UVM_READ_DUPLICATION_ENABLED)
        return NV_OK;

    va_block_context = uvm_va_block_context_alloc();
    if (!va_block_context)
        return NV_ERR_NO_MEMORY;

    for_each_va_block_in_va_range(va_range, va_block) {
        status = uvm_va_block_set_read_duplication(va_block, va_block_context);
        if (status != NV_OK)
            break;
    }

    uvm_va_block_context_free(va_block_context);

    return status;
}

NV_STATUS uvm_va_range_unset_read_duplication(uvm_va_range_t *va_range)
{
    NV_STATUS status = NV_OK;
    uvm_va_block_t *va_block;
    uvm_va_block_context_t *va_block_context;

    if (va_range->read_duplication == UVM_READ_DUPLICATION_DISABLED)
        return NV_OK;

    va_block_context = uvm_va_block_context_alloc();
    if (!va_block_context)
        return NV_ERR_NO_MEMORY;

    for_each_va_block_in_va_range(va_range, va_block) {
        status = uvm_va_block_unset_read_duplication(va_block, va_block_context);
        if (status != NV_OK)
            break;
    }

    uvm_va_block_context_free(va_block_context);

    return status;
}

NV_STATUS uvm_va_space_split_as_needed(uvm_va_space_t *va_space,
                                       NvU64 addr,
                                       uvm_va_range_is_split_needed_t split_needed_cb,
                                       void *data)
{
    uvm_va_range_t *va_range;
    NV_STATUS status;

    UVM_ASSERT(va_space);
    UVM_ASSERT(PAGE_ALIGNED(addr));

    uvm_assert_rwsem_locked_write(&va_space->lock);

    va_range = uvm_va_range_find(va_space, addr);
    if (!va_range)
        return NV_OK;

    // If the VA range doesn't span addr, we're done
    if (addr == va_range->node.start)
        return NV_OK;

    // Only managed ranges can be split
    if (va_range->type != UVM_VA_RANGE_TYPE_MANAGED)
        return NV_ERR_INVALID_ADDRESS;

    if (split_needed_cb(va_range, data)) {
        status = uvm_va_range_split(va_range, addr - 1, NULL);
        if (status != NV_OK)
            return status;
    }

    return NV_OK;
}

NV_STATUS uvm_va_space_split_span_as_needed(uvm_va_space_t *va_space,
                                            NvU64 start_addr,
                                            NvU64 end_addr,
                                            uvm_va_range_is_split_needed_t split_needed_cb,
                                            void *data)
{
    NV_STATUS status;

    status = uvm_va_space_split_as_needed(va_space, start_addr, split_needed_cb, data);
    if (status != NV_OK)
        return status;

    return uvm_va_space_split_as_needed(va_space, end_addr, split_needed_cb, data);
}

uvm_vma_wrapper_t *uvm_vma_wrapper_alloc(struct vm_area_struct *vma)
{
    uvm_vma_wrapper_t *vma_wrapper = kmem_cache_zalloc(g_uvm_vma_wrapper_cache, NV_UVM_GFP_FLAGS);
    if (!vma_wrapper)
        return NULL;

    vma_wrapper->vma = vma;
    uvm_init_rwsem(&vma_wrapper->lock, UVM_LOCK_ORDER_LEAF);

    return vma_wrapper;
}

void uvm_vma_wrapper_destroy(uvm_vma_wrapper_t *vma_wrapper)
{
    if (!vma_wrapper)
        return;

    uvm_assert_rwsem_unlocked(&vma_wrapper->lock);

    kmem_cache_free(g_uvm_vma_wrapper_cache, vma_wrapper);
}

uvm_prot_t uvm_va_range_logical_prot(uvm_va_range_t *va_range)
{
    uvm_prot_t logical_prot;
    struct vm_area_struct *vma;

    UVM_ASSERT(va_range);
    UVM_ASSERT_MSG(va_range->type == UVM_VA_RANGE_TYPE_MANAGED, "type: %d\n", va_range->type);

    vma = uvm_va_range_vma(va_range);

    if (!(vma->vm_flags & VM_READ))
        logical_prot = UVM_PROT_NONE;
    else if (!(vma->vm_flags & VM_WRITE))
        logical_prot = UVM_PROT_READ_ONLY;
    else
        logical_prot = UVM_PROT_READ_WRITE_ATOMIC;

    return logical_prot;
}

static bool fault_check_range_permission(uvm_va_range_t *va_range, uvm_fault_access_type_t access_type)
{
    uvm_prot_t logical_prot = uvm_va_range_logical_prot(va_range);
    uvm_prot_t fault_prot = uvm_fault_access_type_to_prot(access_type);

    return fault_prot <= logical_prot;
}

NV_STATUS uvm_va_range_check_logical_permissions(uvm_va_range_t *va_range,
                                                 uvm_processor_id_t processor_id,
                                                 uvm_fault_type_t access_type,
                                                 bool allow_migration)
{
    // - CPU permissions are checked later by block_map_cpu_page.
    //   TODO: Bug 1766124: permissions are checked by block_map_cpu_page
    //         because it can also be called from change_pte. Make change_pte
    //         call this function and only check CPU permissions here.
    // - We only check GPUs if uvm_enable_builtin_tests because the Linux kernel can change vm_flags
    //   at any moment (for example on mprotect) and here we are not guaranteed to have
    //   vma->vm_mm->mmap_sem. During tests we ensure that this scenario does not happen
    if (uvm_enable_builtin_tests &&
        processor_id != UVM_CPU_ID && !fault_check_range_permission(va_range, access_type)) {
        // Insufficient access privileges
        return NV_ERR_INVALID_ACCESS_TYPE;
    }

    // Non-migratable range:
    // - CPU accesses are always fatal, regardless of the VA range residency
    // - GPU accesses are fatal if the GPU can't map the preferred location
    if (!allow_migration) {
        if (processor_id == UVM_CPU_ID)
            return NV_ERR_INVALID_OPERATION;
        else
            return uvm_processor_mask_test(&va_range->va_space->accessible_from[va_range->preferred_location],
                                           processor_id) ? NV_OK : NV_ERR_INVALID_ACCESS_TYPE;
    }

    return NV_OK;
}



static NvU64 sked_reflected_pte_maker(uvm_page_table_range_vec_t *range_vec, NvU64 offset, void *caller_data)
{
    (void)caller_data;

    return range_vec->tree->hal->make_sked_reflected_pte();
}

static NV_STATUS uvm_map_sked_reflected_range(uvm_va_space_t *va_space, UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS *params)
{
    NV_STATUS status;
    uvm_va_range_t *va_range = NULL;
    uvm_gpu_t *gpu;
    uvm_gpu_va_space_t *gpu_va_space;
    uvm_page_tree_t *page_tables;

    if (uvm_api_range_invalid_4k(params->base, params->length))
        return NV_ERR_INVALID_ADDRESS;

    uvm_va_space_down_write(va_space);

    gpu = uvm_va_space_get_gpu_by_uuid_with_gpu_va_space(va_space, &params->gpuUuid);
    if (!gpu) {
        status = NV_ERR_INVALID_DEVICE;
        goto done;
    }

    // Only GK110+ supports CNP and SKED reflected mappings
    if (!uvm_gpu_is_gk110_plus(gpu)) {
        status = NV_ERR_INVALID_DEVICE;
        goto done;
    }

    // Check if the GPU can access the VA
    if (!uvm_gpu_can_address(gpu, params->base + params->length)) {
        status = NV_ERR_OUT_OF_RANGE;
        goto done;
    }

    gpu_va_space = va_space->gpu_va_spaces[gpu->id - 1];
    page_tables = &gpu_va_space->page_tables;

    // The VA range must exactly cover one supported GPU page
    if (!is_power_of_2(params->length) ||
        !IS_ALIGNED(params->base, params->length) ||
        !uvm_mmu_page_size_supported(page_tables, params->length)) {
        status = NV_ERR_INVALID_ADDRESS;
        goto done;
    }

    status = uvm_va_range_create_sked_reflected(va_space, params->base, params->length, &va_range);
    if (status != NV_OK) {
        UVM_DBG_PRINT_RL("Failed to create sked reflected VA range [0x%llx, 0x%llx)\n",
                params->base, params->base + params->length);
        goto done;
    }

    va_range->sked_reflected.gpu_va_space = gpu_va_space;

    status = uvm_page_table_range_vec_init(page_tables,
                                           va_range->node.start,
                                           uvm_va_range_size(va_range),
                                           params->length,
                                           &va_range->sked_reflected.pt_range_vec);
    if (status != NV_OK)
        goto done;

    status = uvm_page_table_range_vec_write_ptes(&va_range->sked_reflected.pt_range_vec,
            UVM_MEMBAR_NONE, sked_reflected_pte_maker, NULL);

    if (status != NV_OK)
        goto done;

done:
    if (status != NV_OK && va_range != NULL)
        uvm_va_range_destroy(va_range, NULL);

    uvm_va_space_up_write(va_space);

    return status;
}

NV_STATUS uvm_api_map_dynamic_parallelism_region(UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS *params, struct file *filp)
{
    uvm_va_space_t *va_space = uvm_va_space_get(filp);

    // Notably the ranges created by the UvmMapDynamicParallelismRegion() API
    // are referred to as "SKED reflected ranges" internally as it's more
    // descriptive.
    return uvm_map_sked_reflected_range(va_space, params);
}

NV_STATUS uvm_api_alloc_semaphore_pool(UVM_ALLOC_SEMAPHORE_POOL_PARAMS *params, struct file *filp)
{
    NV_STATUS status;
    uvm_va_space_t *va_space = uvm_va_space_get(filp);
    uvm_va_range_t *va_range = NULL;
    uvm_gpu_t *gpu;
    uvm_mem_gpu_mapping_attrs_t *attrs;

    if (uvm_api_range_invalid(params->base, params->length))
        return NV_ERR_INVALID_ADDRESS;
    if (params->gpuAttributesCount > UVM_MAX_GPUS)
        return NV_ERR_INVALID_ARGUMENT;

    uvm_va_space_down_write(va_space);

    status = uvm_va_range_create_semaphore_pool(va_space, params->base, params->length,
            params->perGpuAttributes, params->gpuAttributesCount, &va_range);
    if (status != NV_OK) {
        uvm_va_space_up_write(va_space);
        return status;
    }

    for_each_gpu_in_mask(gpu, &va_space->registered_gpu_va_spaces) {
        attrs = &va_range->semaphore_pool.gpu_attrs[gpu->id - 1];
        status = uvm_mem_map_gpu_user(va_range->semaphore_pool.mem, gpu, attrs);
        if (status != NV_OK)
            goto done;
    }

done:
    if (status != NV_OK)
        uvm_va_range_destroy(va_range, NULL);
    uvm_va_space_up_write(va_space);
    return status;
}

NV_STATUS uvm8_test_va_range_info(UVM_TEST_VA_RANGE_INFO_PARAMS *params, struct file *filp)
{
    uvm_va_space_t *va_space;
    uvm_va_range_t *va_range;
    uvm_processor_id_t processor_id;
    struct vm_area_struct *vma;
    NV_STATUS status = NV_OK;

    va_space = uvm_va_space_get(filp);

    uvm_down_read_mmap_sem(&current->mm->mmap_sem);
    uvm_va_space_down_read(va_space);

    va_range = uvm_va_range_find(va_space, params->lookup_address);
    if (!va_range) {
        status = NV_ERR_INVALID_ADDRESS;
        goto out;
    }

    params->va_range_start = va_range->node.start;
    params->va_range_end   = va_range->node.end;

    // -Wall implies -Wenum-compare, so cast through int to avoid warnings
    BUILD_BUG_ON((int)UVM_READ_DUPLICATION_UNSET    != (int)UVM_TEST_READ_DUPLICATION_UNSET);
    BUILD_BUG_ON((int)UVM_READ_DUPLICATION_ENABLED  != (int)UVM_TEST_READ_DUPLICATION_ENABLED);
    BUILD_BUG_ON((int)UVM_READ_DUPLICATION_DISABLED != (int)UVM_TEST_READ_DUPLICATION_DISABLED);
    BUILD_BUG_ON((int)UVM_READ_DUPLICATION_MAX      != (int)UVM_TEST_READ_DUPLICATION_MAX);
    params->read_duplication = va_range->read_duplication;

    if (va_range->preferred_location == UVM8_MAX_PROCESSORS)
        memset(&params->preferred_location, 0, sizeof(params->preferred_location));
    else
        uvm_processor_uuid_from_id(&params->preferred_location, va_range->preferred_location);

    BUILD_BUG_ON((int)UVM8_MAX_GPUS       != (int)UVM_MAX_GPUS);
    BUILD_BUG_ON((int)UVM8_MAX_PROCESSORS != (int)UVM_MAX_PROCESSORS);

    params->accessed_by_count = 0;
    for_each_id_in_mask(processor_id, &va_range->accessed_by)
        uvm_processor_uuid_from_id(&params->accessed_by[params->accessed_by_count++], processor_id);

    // -Wall implies -Wenum-compare, so cast through int to avoid warnings
    BUILD_BUG_ON((int)UVM_TEST_VA_RANGE_TYPE_INVALID        != (int)UVM_VA_RANGE_TYPE_INVALID);
    BUILD_BUG_ON((int)UVM_TEST_VA_RANGE_TYPE_MANAGED        != (int)UVM_VA_RANGE_TYPE_MANAGED);
    BUILD_BUG_ON((int)UVM_TEST_VA_RANGE_TYPE_EXTERNAL       != (int)UVM_VA_RANGE_TYPE_EXTERNAL);
    BUILD_BUG_ON((int)UVM_TEST_VA_RANGE_TYPE_CHANNEL        != (int)UVM_VA_RANGE_TYPE_CHANNEL);
    BUILD_BUG_ON((int)UVM_TEST_VA_RANGE_TYPE_SKED_REFLECTED != (int)UVM_VA_RANGE_TYPE_SKED_REFLECTED);
    BUILD_BUG_ON((int)UVM_TEST_VA_RANGE_TYPE_SEMAPHORE_POOL != (int)UVM_VA_RANGE_TYPE_SEMAPHORE_POOL);
    BUILD_BUG_ON((int)UVM_TEST_VA_RANGE_TYPE_MAX            != (int)UVM_VA_RANGE_TYPE_MAX);
    params->type = va_range->type;

    switch (va_range->type) {
        case UVM_VA_RANGE_TYPE_MANAGED:
            if (!va_range->managed.vma_wrapper) {
                params->managed.is_zombie = NV_TRUE;
                goto out;
            }
            params->managed.is_zombie = NV_FALSE;
            vma = uvm_va_range_vma_current(va_range);
            if (!vma) {
                // We aren't in the same mm as the one which owns the vma
                params->managed.owned_by_calling_process = NV_FALSE;
                goto out;
            }
            params->managed.owned_by_calling_process = NV_TRUE;
            params->managed.vma_start = vma->vm_start;
            params->managed.vma_end   = vma->vm_end - 1;
            break;
        default:
            break;
    }

out:
    uvm_va_space_up_read(va_space);
    uvm_up_read_mmap_sem(&current->mm->mmap_sem);
    return status;
}

NV_STATUS uvm8_test_va_range_split(UVM_TEST_VA_RANGE_SPLIT_PARAMS *params, struct file *filp)
{
    uvm_va_space_t *va_space = uvm_va_space_get(filp);
    uvm_va_range_t *va_range;
    NV_STATUS status = NV_OK;

    if (!PAGE_ALIGNED(params->split_address + 1))
        return NV_ERR_INVALID_ADDRESS;

    uvm_va_space_down_write(va_space);

    va_range = uvm_va_range_find(va_space, params->split_address);
    if (!va_range ||
        va_range->node.end == params->split_address ||
        va_range->type != UVM_VA_RANGE_TYPE_MANAGED) {
        status = NV_ERR_INVALID_ADDRESS;
        goto out;
    }

    status = uvm_va_range_split(va_range, params->split_address, NULL);

out:
    uvm_va_space_up_write(va_space);
    return status;
}

NV_STATUS uvm8_test_va_range_inject_split_error(UVM_TEST_VA_RANGE_INJECT_SPLIT_ERROR_PARAMS *params,
                                                struct file *filp)
{
    uvm_va_space_t *va_space = uvm_va_space_get(filp);
    uvm_va_range_t *va_range;
    NV_STATUS status = NV_OK;

    uvm_va_space_down_write(va_space);

    va_range = uvm_va_range_find(va_space, params->lookup_address);
    if (!va_range || va_range->type != UVM_VA_RANGE_TYPE_MANAGED) {
        status = NV_ERR_INVALID_ADDRESS;
        goto out;
    }

    va_range->inject_split_error = true;

out:
    uvm_va_space_up_write(va_space);
    return status;
}
