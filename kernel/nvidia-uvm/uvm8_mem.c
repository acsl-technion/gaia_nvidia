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

#include "uvm8_mem.h"
#include "uvm8_mmu.h"
#include "uvm8_va_space.h"
#include "uvm8_gpu.h"
#include "uvm8_global.h"
#include "uvm8_kvmalloc.h"
#include "uvm8_push.h"
#include "uvm8_range_allocator.h"
#include "uvm8_hal.h"
#include "uvm_linux.h"

static uvm_range_allocator_t g_free_ranges;
static bool g_mem_initialized;

NV_STATUS uvm_mem_global_init(void)
{
    NV_STATUS status = uvm_range_allocator_init(UVM_MEM_VA_SIZE, &g_free_ranges);
    if (status != NV_OK)
        return status;

    g_mem_initialized = true;

    return NV_OK;
}

void uvm_mem_global_exit(void)
{
    if (!g_mem_initialized)
        return;

    uvm_range_allocator_deinit(&g_free_ranges);
}

NV_STATUS uvm_mem_translate_gpu_attributes(UvmGpuMappingAttributes *attrs,
        uvm_va_space_t *va_space, uvm_gpu_t **gpu_out, uvm_mem_gpu_mapping_attrs_t *attrs_out)
{
    uvm_gpu_t *gpu;

    switch (attrs->gpuMappingType) {
        case UvmGpuMappingTypeDefault:
            break;
        case UvmGpuMappingTypeReadWriteAtomic:
            attrs_out->protection = UVM_PROT_READ_WRITE_ATOMIC;
            break;
        case UvmGpuMappingTypeReadWrite:
            attrs_out->protection = UVM_PROT_READ_WRITE;
            break;
        case UvmGpuMappingTypeReadOnly:
            attrs_out->protection = UVM_PROT_READ_ONLY;
            break;
        default:
            return NV_ERR_INVALID_ARGUMENT;
    }

    switch (attrs->gpuCachingType) {
        case UvmGpuCachingTypeDefault:
            break;
        case UvmGpuCachingTypeForceUncached:
            attrs_out->is_volatile = true;
            break;
        case UvmGpuCachingTypeForceCached:
            attrs_out->is_volatile = false;
            break;
        default:
            return NV_ERR_INVALID_ARGUMENT;
    }

    gpu = uvm_va_space_get_gpu_by_uuid(va_space, &attrs->gpuUuid);
    if (!gpu)
        return NV_ERR_INVALID_DEVICE;

    if (gpu_out)
        *gpu_out = gpu;

    return NV_OK;
}

uvm_chunk_sizes_mask_t uvm_mem_kernel_chunk_sizes(uvm_gpu_t *gpu)
{
    // Get the mmu mode hal directly as the internal address space tree has not
    // been created yet.
    uvm_mmu_mode_hal_t *hal = gpu->arch_hal->mmu_mode_hal(gpu->big_page.internal_size);

    return hal->page_sizes();
}

static NvU32 pick_chunk_size(uvm_mem_t *mem)
{
    NvU32 biggest_page_size;

    if (uvm_mem_is_sysmem(mem))
        return PAGE_SIZE;

    biggest_page_size = uvm_mmu_biggest_page_size(&mem->backing_gpu->address_space_tree);

    if (mem->size < mem->backing_gpu->big_page.internal_size)
        return UVM_PAGE_SIZE_4K;
    else if (mem->size < biggest_page_size)
        return mem->backing_gpu->big_page.internal_size;
    else
        return biggest_page_size;
}

static NvU32 pick_gpu_page_size(uvm_mem_t *mem, uvm_gpu_t *gpu, uvm_page_tree_t *gpu_page_tree)
{
    if (uvm_mem_is_vidmem(mem)) {
        // For vidmem allocations the chunk size is picked out of the supported
        // page sizes and can be used directly.
        return mem->chunk_size;
    }

    // For sysmem, check whether the GPU supports mapping it with large pages.
    if (gpu->can_map_sysmem_with_large_pages) {
        // If it's supported, pick the largest page size not bigger than
        // the chunk size.
        return uvm_mmu_biggest_page_size_up_to(gpu_page_tree, mem->chunk_size);
    }

    // Otherwise just use 4K.
    return UVM_PAGE_SIZE_4K;
}

static void uvm_mem_free_vidmem_chunks(uvm_mem_t *mem)
{
    size_t i;

    UVM_ASSERT(uvm_mem_is_vidmem(mem));

    if (!mem->vidmem.chunks)
        return;

    for (i = 0; i < mem->chunks_count; ++i) {
        // On allocation error PMM guarantees the chunks array to be zeroed so
        // just check for NULL.
        if (mem->vidmem.chunks[i] == NULL)
            break;
        uvm_pmm_gpu_free(&mem->backing_gpu->pmm, mem->vidmem.chunks[i], NULL);
    }

    uvm_kvfree(mem->vidmem.chunks);
    mem->vidmem.chunks = NULL;
}

static void uvm_mem_free_sysmem_chunks(uvm_mem_t *mem)
{
    size_t i;

    UVM_ASSERT(uvm_mem_is_sysmem(mem));

    if (!mem->sysmem.pages)
        return;

    for (i = 0; i < mem->chunks_count; ++i) {
        if (!mem->sysmem.pages[i])
            break;
        __free_pages(mem->sysmem.pages[i], get_order(mem->chunk_size));
    }

    uvm_kvfree(mem->sysmem.pages);
    mem->sysmem.pages = NULL;
}

static void uvm_mem_free_chunks(uvm_mem_t *mem)
{
    if (uvm_mem_is_sysmem(mem))
        uvm_mem_free_sysmem_chunks(mem);
    else
        uvm_mem_free_vidmem_chunks(mem);
}

static NV_STATUS uvm_mem_alloc_sysmem_chunks(uvm_mem_t *mem, size_t size)
{
    NV_STATUS status = NV_OK;
    size_t i;
    gfp_t gfp_flags = NV_UVM_GFP_FLAGS;

    UVM_ASSERT(mem->chunk_size >= PAGE_SIZE);
    UVM_ASSERT(PAGE_ALIGNED(mem->chunk_size));

    mem->sysmem.pages = uvm_kvmalloc_zero(sizeof(*mem->sysmem.pages) * mem->chunks_count);
    if (!mem->sysmem.pages) {
        status = NV_ERR_NO_MEMORY;
        goto error;
    }

    if (mem->is_user_allocation)
        gfp_flags |= __GFP_ZERO;
    for (i = 0; i < mem->chunks_count; ++i) {
        mem->sysmem.pages[i] = alloc_pages(gfp_flags, get_order(mem->chunk_size));
        if (!mem->sysmem.pages[i]) {
            status = NV_ERR_NO_MEMORY;
            goto error;
        }
    }

    return NV_OK;

error:
    uvm_mem_free_sysmem_chunks(mem);
    return status;
}

static NV_STATUS uvm_mem_alloc_vidmem_chunks(uvm_mem_t *mem, size_t size)
{
    NV_STATUS status = NV_OK;

    UVM_ASSERT(uvm_mem_is_vidmem(mem));
    UVM_ASSERT(!mem->is_user_allocation);

    mem->vidmem.chunks = uvm_kvmalloc_zero(mem->chunks_count * sizeof(*mem->vidmem.chunks));
    if (!mem->vidmem.chunks)
        return NV_ERR_NO_MEMORY;

    status = uvm_pmm_gpu_alloc_kernel(&mem->backing_gpu->pmm, mem->chunks_count, mem->chunk_size, UVM_PMM_ALLOC_FLAGS_NONE,
            mem->vidmem.chunks, NULL);
    if (status != NV_OK) {
        UVM_ERR_PRINT("pmm_gpu_alloc(count=%zd, size=0x%x) failed: %s\n", mem->chunks_count, mem->chunk_size, nvstatusToString(status));
        return status;
    }

    return NV_OK;
}

static NV_STATUS uvm_mem_alloc_chunks(uvm_mem_t *mem)
{
    if (uvm_mem_is_sysmem(mem))
        return uvm_mem_alloc_sysmem_chunks(mem, mem->physical_allocation_size);
    else
        return uvm_mem_alloc_vidmem_chunks(mem, mem->physical_allocation_size);
}

static const char *uvm_mem_physical_source(uvm_mem_t *mem)
{
    if (uvm_mem_is_vidmem(mem))
        return mem->backing_gpu->name;
    else
        return "CPU";
}

NV_STATUS uvm_mem_map_kernel(uvm_mem_t *mem, uvm_processor_mask_t *mask)
{
    uvm_gpu_t *gpu;
    NV_STATUS status;

    UVM_ASSERT(!mem->is_user_allocation);

    if (!mask)
        return NV_OK;

    if (uvm_processor_mask_test(mask, UVM_CPU_ID)) {
        status = uvm_mem_map_cpu(mem, NULL);
        if (status != NV_OK)
            return status;
    }

    for_each_gpu_in_mask(gpu, mask) {
        status = uvm_mem_map_gpu_kernel(mem, gpu);
        if (status != NV_OK)
            return status;
    }
    return NV_OK;
}

NV_STATUS uvm_mem_alloc(uvm_mem_alloc_params_t *params, uvm_mem_t **mem_out)
{
    NV_STATUS status = NV_OK;
    uvm_mem_t *mem = NULL;

    if (params->size == 0) {
        UVM_ASSERT(params->size != 0);
        return NV_ERR_INVALID_ARGUMENT;
    }

    mem = uvm_kvmalloc_zero(sizeof(*mem));
    if (mem == NULL)
        return NV_ERR_NO_MEMORY;

    mem->is_user_allocation = (params->user_va_space != NULL);
    if (params->user_va_space) {
        mem->user.va_space = params->user_va_space;
        mem->user.addr = params->user_addr;
    }
    mem->backing_gpu = params->backing_gpu;
    mem->size = params->size;
    mem->chunk_size = params->page_size;

    if (mem->chunk_size == UVM_PAGE_SIZE_DEFAULT) {
        mem->chunk_size = pick_chunk_size(mem);
    }

    mem->physical_allocation_size = UVM_ALIGN_UP(mem->size, mem->chunk_size);
    mem->chunks_count = mem->physical_allocation_size / mem->chunk_size;

    if (mem->is_user_allocation) {
        UVM_ASSERT(mem->physical_allocation_size == mem->size);
        UVM_ASSERT(IS_ALIGNED((NvU64)mem->user.addr, mem->chunk_size));
    }

    status = uvm_mem_alloc_chunks(mem);
    if (status != NV_OK) {
        UVM_ERR_PRINT("uvm_mem_alloc_chunks (chunk count %zu, page size %u) failed: %s, %s\n",
                mem->chunks_count, mem->chunk_size,
                nvstatusToString(status), uvm_mem_physical_source(mem));
        goto error;
    }

    if (!mem->is_user_allocation) {
        status = uvm_range_allocator_alloc(&g_free_ranges, mem->physical_allocation_size, mem->chunk_size, &mem->kernel.range_alloc);
        if (status != NV_OK) {
            UVM_ERR_PRINT("Failed to allocate a free range for size %llu alignment %u\n",
                    mem->physical_allocation_size, mem->chunk_size);
            goto error;
        }
    }

    *mem_out = mem;

    return NV_OK;

error:
    uvm_mem_free(mem);
    return status;
}

static NvU64 reserved_gpu_va(uvm_mem_t *mem, uvm_gpu_t *gpu)
{
    UVM_ASSERT(!mem->is_user_allocation);
    UVM_ASSERT(mem->kernel.range_alloc.aligned_start + mem->physical_allocation_size < gpu->uvm_mem_va_size);

    return gpu->uvm_mem_va_base + mem->kernel.range_alloc.aligned_start;
}

static struct page *uvm_mem_cpu_page(uvm_mem_t *mem, NvU64 offset)
{
    struct page *base_page = mem->sysmem.pages[offset / mem->chunk_size];

    UVM_ASSERT_MSG(PAGE_ALIGNED(offset), "offset 0x%llx\n", offset);

    offset = offset % mem->chunk_size;
    return pfn_to_page(page_to_pfn(base_page) + offset / PAGE_SIZE);
}

static NV_STATUS uvm_mem_map_cpu_sysmem_kernel(uvm_mem_t *mem)
{
    struct page **pages = mem->sysmem.pages;
    size_t num_pages = mem->physical_allocation_size / PAGE_SIZE;

    UVM_ASSERT(mem->backing_gpu == NULL);
    UVM_ASSERT(!mem->is_user_allocation);

    // If chunk size is different than PAGE_SIZE then create a temporary array
    // of all the pages to map so that vmap() can be used.
    if (mem->chunk_size != PAGE_SIZE) {
        size_t i;
        pages = uvm_kvmalloc(sizeof(*pages) * num_pages);
        if (!pages)
            return NV_ERR_NO_MEMORY;
        for (i = 0; i < num_pages; ++i)
            pages[i] = uvm_mem_cpu_page(mem, i * PAGE_SIZE);
    }

    mem->kernel.cpu_addr = vmap(pages, num_pages, VM_MAP, PAGE_KERNEL);

    if (mem->chunk_size != PAGE_SIZE)
        uvm_kvfree(pages);

    if (!mem->kernel.cpu_addr)
        return NV_ERR_NO_MEMORY;

    return NV_OK;
}

static void uvm_mem_unmap_cpu_sysmem_kernel(uvm_mem_t *mem)
{
    UVM_ASSERT(uvm_mem_is_sysmem(mem));
    UVM_ASSERT(!mem->is_user_allocation);
    UVM_ASSERT(mem->kernel.cpu_addr != NULL);

    vunmap(mem->kernel.cpu_addr);
    mem->kernel.cpu_addr = NULL;
}

static NV_STATUS uvm_mem_map_cpu_sysmem_user(uvm_mem_t *mem, struct vm_area_struct *vma)
{
    NvU64 offset;

    UVM_ASSERT(uvm_mem_is_sysmem(mem));
    UVM_ASSERT(mem->is_user_allocation);
    uvm_assert_mmap_sem_locked(&vma->vm_mm->mmap_sem);

    for (offset = 0; offset < mem->physical_allocation_size; offset += PAGE_SIZE) {
        int ret = vm_insert_page(vma, (unsigned long)mem->user.addr + offset, uvm_mem_cpu_page(mem, offset));
        if (ret) {
            UVM_ASSERT_MSG(ret == -ENOMEM, "ret: %d\n", ret);
            return errno_to_nv_status(ret);
        }
    }

    return NV_OK;
}

static void uvm_mem_unmap_cpu_sysmem_user(uvm_mem_t *mem)
{
    UVM_ASSERT(uvm_mem_is_sysmem(mem));
    UVM_ASSERT(mem->is_user_allocation);

    unmap_mapping_range(&mem->user.va_space->mapping, (size_t)mem->user.addr, mem->physical_allocation_size, 1);
}

NV_STATUS uvm_mem_map_cpu(uvm_mem_t *mem, struct vm_area_struct *vma)
{
    NV_STATUS status;

    UVM_ASSERT(mem);

    if (uvm_processor_mask_test(&mem->mapped_on, UVM_CPU_ID)) {
        // Already mapped
        return NV_OK;
    }

    // Only mapping sysmem on the CPU is supported
    UVM_ASSERT(uvm_mem_is_sysmem(mem));

    if (mem->is_user_allocation) {
        UVM_ASSERT(vma);
        status = uvm_mem_map_cpu_sysmem_user(mem, vma);
    }
    else {
        status = uvm_mem_map_cpu_sysmem_kernel(mem);
    }
    if (status != NV_OK)
        return status;

    uvm_processor_mask_set(&mem->mapped_on, UVM_CPU_ID);
    return NV_OK;
}

void uvm_mem_unmap_cpu(uvm_mem_t *mem)
{
    UVM_ASSERT(mem);

    if (!uvm_processor_mask_test(&mem->mapped_on, UVM_CPU_ID)) {
        // Already unmapped
        return;
    }

    if (mem->is_user_allocation)
        uvm_mem_unmap_cpu_sysmem_user(mem);
    else
        uvm_mem_unmap_cpu_sysmem_kernel(mem);

    uvm_processor_mask_clear(&mem->mapped_on, UVM_CPU_ID);
}

static void unmap_gpu_sysmem_iommu(uvm_mem_t *mem, uvm_gpu_t *gpu)
{
    NvU64 *dma_addrs = mem->sysmem.dma_addrs[gpu->id - 1];
    NvU32 i;

    UVM_ASSERT(uvm_mem_is_sysmem(mem));
    UVM_ASSERT(dma_addrs);

    for (i = 0; i < mem->chunks_count; ++i) {
        if (dma_addrs[i] == 0) {
            // The DMA address can only be 0 when cleaning up after a failed
            // partial map_gpu_sysmem_iommu() operation.
            break;
        }
        uvm_gpu_unmap_cpu_pages(gpu, dma_addrs[i], mem->chunk_size);
        dma_addrs[i] = 0;
    }

    uvm_kvfree(dma_addrs);
    mem->sysmem.dma_addrs[gpu->id - 1] = NULL;
}

static NV_STATUS map_gpu_sysmem_iommu(uvm_mem_t *mem, uvm_gpu_t *gpu)
{
    NV_STATUS status;
    NvU64 *dma_addrs;
    size_t i;

    UVM_ASSERT(uvm_mem_is_sysmem(mem));

    dma_addrs = uvm_kvmalloc_zero(sizeof(*dma_addrs) * mem->chunks_count);
    if (!dma_addrs)
        return NV_ERR_NO_MEMORY;

    mem->sysmem.dma_addrs[gpu->id - 1] = dma_addrs;

    for (i = 0; i < mem->chunks_count; ++i) {
        status = uvm_gpu_map_cpu_pages(gpu, mem->sysmem.pages[i], mem->chunk_size, &dma_addrs[i]);
        if (status != NV_OK)
            goto error;
    }

    return NV_OK;

error:
    unmap_gpu_sysmem_iommu(mem, gpu);
    return status;
}

static uvm_gpu_phys_address_t uvm_mem_gpu_physical_vidmem(uvm_mem_t *mem, size_t offset)
{
    size_t chunk_index = uvm_div_pow2_64(offset, mem->chunk_size);
    size_t chunk_offset = offset & (mem->chunk_size - 1);

    UVM_ASSERT(uvm_mem_is_vidmem(mem));

    return uvm_gpu_phys_address(UVM_APERTURE_VID, mem->vidmem.chunks[chunk_index]->address + chunk_offset);
}

static uvm_gpu_phys_address_t uvm_mem_gpu_physical_sysmem(uvm_mem_t *mem, uvm_gpu_t *gpu, size_t offset)
{
    NvU64 *dma_addrs = mem->sysmem.dma_addrs[gpu->id - 1];
    NvU64 dma_addr = dma_addrs[offset / mem->chunk_size];

    UVM_ASSERT(uvm_mem_is_sysmem(mem));
    UVM_ASSERT(uvm_processor_mask_test(&mem->mapped_phys_on, gpu->id));

    return uvm_gpu_phys_address(UVM_APERTURE_SYS, dma_addr + offset % mem->chunk_size);
}

uvm_gpu_phys_address_t uvm_mem_gpu_physical(uvm_mem_t *mem, uvm_gpu_t *gpu, NvU64 offset, NvU64 size)
{
    UVM_ASSERT(size != 0);
    UVM_ASSERT_MSG(UVM_ALIGN_DOWN(offset, mem->chunk_size) == UVM_ALIGN_DOWN(offset + size - 1, mem->chunk_size),
            "offset %llu size %llu page_size %u\n", offset, size, mem->chunk_size);
    UVM_ASSERT_MSG(offset / mem->chunk_size < mem->chunks_count, "offset %llu\n", offset);

    if (uvm_mem_is_vidmem(mem))
        return uvm_mem_gpu_physical_vidmem(mem, offset);
    else
        return uvm_mem_gpu_physical_sysmem(mem, gpu, offset);
}

typedef struct uvm_mem_pte_maker_data_struct
{
    uvm_mem_t *mem;
    uvm_mem_gpu_mapping_attrs_t *attrs;
} uvm_mem_pte_maker_data_t;

static NvU64 uvm_mem_pte_maker(uvm_page_table_range_vec_t *range_vec, NvU64 offset, void *vp_data)
{
    uvm_mem_pte_maker_data_t *data = (uvm_mem_pte_maker_data_t *)vp_data;
    uvm_page_tree_t *tree = range_vec->tree;
    uvm_gpu_t *gpu = tree->gpu;
    uvm_gpu_phys_address_t phys = uvm_mem_gpu_physical(data->mem, gpu, offset, range_vec->page_size);
    return tree->hal->make_pte(phys.aperture, phys.address, data->attrs->protection, data->attrs->is_volatile, range_vec->page_size);
}

static void unmap_gpu(uvm_mem_t *mem, uvm_gpu_t *gpu)
{
    NV_STATUS status;
    uvm_page_table_range_vec_t *range_vec = mem->range_vecs[gpu->id - 1];
    uvm_membar_t tlb_membar = UVM_MEMBAR_SYS;

    if (uvm_mem_is_local_vidmem(mem, gpu))
        tlb_membar = UVM_MEMBAR_GPU;

    status = uvm_page_table_range_vec_clear_ptes(range_vec, tlb_membar);
    if (status != NV_OK)
        UVM_ERR_PRINT("Clearing PTEs failed: %s, GPU %s\n", nvstatusToString(status), gpu->name);

    uvm_page_table_range_vec_destroy(range_vec);
    mem->range_vecs[gpu->id - 1] = NULL;
}

static NV_STATUS map_gpu(uvm_mem_t *mem, uvm_gpu_t *gpu, NvU64 gpu_va, uvm_page_tree_t *tree, uvm_mem_gpu_mapping_attrs_t *attrs)
{
    NV_STATUS status;
    uvm_page_table_range_vec_t **range_vec = &mem->range_vecs[gpu->id - 1];
    NvU32 page_size;
    uvm_mem_pte_maker_data_t pte_maker_data = {
            .mem = mem,
            .attrs = attrs
        };

    if (!uvm_gpu_can_address(gpu, gpu_va + mem->size - 1))
        return NV_ERR_OUT_OF_RANGE;

    page_size = pick_gpu_page_size(mem, gpu, tree);
    UVM_ASSERT_MSG(uvm_mmu_page_size_supported(tree, page_size), "page_size 0x%x\n", page_size);

    status = uvm_page_table_range_vec_create(tree, gpu_va, mem->physical_allocation_size, page_size, range_vec);
    if (status != NV_OK) {
        UVM_ERR_PRINT("Failed to init page mapping at [0x%llx, 0x%llx): %s, GPU %s\n",
                gpu_va, gpu_va + mem->physical_allocation_size, nvstatusToString(status), gpu->name);
        return status;
    }

    status = uvm_page_table_range_vec_write_ptes(*range_vec, UVM_MEMBAR_NONE, uvm_mem_pte_maker, &pte_maker_data);
    if (status != NV_OK) {
        UVM_ERR_PRINT("Failed to write PTEs for mapping at [0x%llx, 0x%llx): %s, GPU %s\n",
                gpu_va, gpu_va + mem->physical_allocation_size, nvstatusToString(status), gpu->name);
        goto error;
    }

    return NV_OK;

error:
    unmap_gpu(mem, gpu);
    return status;
}

NV_STATUS uvm_mem_map_gpu_kernel(uvm_mem_t *mem, uvm_gpu_t *gpu)
{
    NV_STATUS status;
    NvU64 gpu_va;
    uvm_mem_gpu_mapping_attrs_t attrs = {
            .protection = UVM_PROT_READ_WRITE_ATOMIC,
            .is_volatile = !uvm_mem_is_vidmem(mem)
        };

    UVM_ASSERT(!mem->is_user_allocation);

    if (uvm_processor_mask_test(&mem->mapped_on, gpu->id))
        return NV_OK;

    status = uvm_mem_map_gpu_phys(mem, gpu);
    if (status != NV_OK)
        return status;

    gpu_va = reserved_gpu_va(mem, gpu);
    status = map_gpu(mem, gpu, gpu_va, &gpu->address_space_tree, &attrs);
    if (status != NV_OK)
        return status;

    uvm_processor_mask_set(&mem->mapped_on, gpu->id);

    return NV_OK;
}

NV_STATUS uvm_mem_map_gpu_user(uvm_mem_t *mem, uvm_gpu_t *gpu, uvm_mem_gpu_mapping_attrs_t *attrs)
{
    NV_STATUS status;
    uvm_gpu_va_space_t *gpu_va_space;

    UVM_ASSERT(mem->is_user_allocation);

    if (uvm_processor_mask_test(&mem->mapped_on, gpu->id))
        return NV_OK;

    status = uvm_mem_map_gpu_phys(mem, gpu);
    if (status != NV_OK)
        return status;

    uvm_assert_rwsem_locked(&mem->user.va_space->lock);
    gpu_va_space = uvm_gpu_va_space_get(mem->user.va_space, gpu);
    status = map_gpu(mem, gpu, (NvU64)mem->user.addr, &gpu_va_space->page_tables, attrs);
    if (status != NV_OK)
        return status;

    uvm_processor_mask_set(&mem->mapped_on, gpu->id);

    return NV_OK;
}

void uvm_mem_unmap_gpu(uvm_mem_t *mem, uvm_gpu_t *gpu)
{
    UVM_ASSERT(mem);
    UVM_ASSERT(gpu);

    if (!uvm_processor_mask_test(&mem->mapped_on, gpu->id)) {
        // Already unmapped
        return;
    }

    unmap_gpu(mem, gpu);
    uvm_processor_mask_clear(&mem->mapped_on, gpu->id);
}

NV_STATUS uvm_mem_map_gpu_phys(uvm_mem_t *mem, uvm_gpu_t *gpu)
{
    NV_STATUS status;

    if (!uvm_mem_is_sysmem(mem))
        return NV_OK;

    if (uvm_processor_mask_test(&mem->mapped_phys_on, gpu->id)) {
        // Already mapped
        return NV_OK;
    }

    status = map_gpu_sysmem_iommu(mem, gpu);
    if (status != NV_OK)
        return status;

    uvm_processor_mask_set(&mem->mapped_phys_on, gpu->id);

    return NV_OK;
}

void uvm_mem_unmap_gpu_phys(uvm_mem_t *mem, uvm_gpu_t *gpu)
{
    UVM_ASSERT(mem);
    UVM_ASSERT(gpu);

    if (!uvm_mem_is_sysmem(mem))
        return;

    uvm_mem_unmap_gpu(mem, gpu);

    if (!uvm_processor_mask_test(&mem->mapped_phys_on, gpu->id)) {
        // Already unmapped
        return;
    }

    unmap_gpu_sysmem_iommu(mem, gpu);
    uvm_processor_mask_clear(&mem->mapped_phys_on, gpu->id);
}

void uvm_mem_free(uvm_mem_t *mem)
{
    uvm_gpu_t *gpu;

    if (mem == NULL)
        return;

    if (uvm_processor_mask_test(&mem->mapped_on, UVM_CPU_ID))
        uvm_mem_unmap_cpu(mem);

    for_each_gpu_in_mask(gpu, &mem->mapped_on)
        uvm_mem_unmap_gpu(mem, gpu);

    for_each_gpu_in_mask(gpu, &mem->mapped_phys_on)
        uvm_mem_unmap_gpu_phys(mem, gpu);

    if (!mem->is_user_allocation && mem->kernel.range_alloc.node)
        uvm_range_allocator_free(&g_free_ranges, &mem->kernel.range_alloc);

    uvm_mem_free_chunks(mem);

    uvm_kvfree(mem);
}

void *uvm_mem_get_cpu_addr_kernel(uvm_mem_t *mem)
{
    UVM_ASSERT(!mem->is_user_allocation);
    UVM_ASSERT(uvm_processor_mask_test(&mem->mapped_on, UVM_CPU_ID));

    return mem->kernel.cpu_addr;
}

NvU64 uvm_mem_get_gpu_va_kernel(uvm_mem_t *mem, uvm_gpu_t *gpu)
{
    UVM_ASSERT(!mem->is_user_allocation);
    UVM_ASSERT_MSG(uvm_processor_mask_test(&mem->mapped_on, gpu->id), "GPU %s\n", gpu->name);

    return reserved_gpu_va(mem, gpu);
}

uvm_gpu_address_t uvm_mem_gpu_address_virtual_kernel(uvm_mem_t *mem, uvm_gpu_t *gpu)
{
    return uvm_gpu_address_virtual(uvm_mem_get_gpu_va_kernel(mem, gpu));
}

uvm_gpu_address_t uvm_mem_gpu_address_physical(uvm_mem_t *mem, uvm_gpu_t *gpu, NvU64 offset, NvU64 size)
{
    return uvm_gpu_address_from_phys(uvm_mem_gpu_physical(mem, gpu, offset, size));
}
