/*
 * Copyright (c) 2015, NVIDIA CORPORATION. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "nvidia-drm-conftest.h" /* NV_DRM_ATOMIC_MODESET_AVAILABLE */

#if defined(NV_DRM_AVAILABLE)

#include "nvidia-drm-priv.h"
#include "nvidia-drm-ioctl.h"
#include "nvidia-drm-prime-fence.h"
#include "nvidia-drm-gem.h"

#include "nv-mm.h"

static inline int __nv_drm_gem_handle_create(struct drm_file *file_priv,
                                             struct nvidia_drm_gem_object *nv_gem,
                                             uint32_t *handle) {
    int ret = drm_gem_handle_create(file_priv, &nv_gem->base, handle);

    /* drop reference from allocate - handle holds it now */

    drm_gem_object_unreference_unlocked(&nv_gem->base);

    return ret;
}

static struct nvidia_drm_gem_object *nvidia_drm_gem_new
(
    struct drm_device *dev,
    enum nv_drm_gem_object_type type,
    const union nvidia_drm_gem_object_union *nv_gem_union,
    size_t size
)
{
    struct nvidia_drm_device *nv_dev = to_nv_drm_device(dev);

    struct nvidia_drm_gem_object *nv_gem = NULL;

    /* Allocate memory for the gem object */

    nv_gem = nvidia_drm_calloc(1, sizeof(*nv_gem));

    if (nv_gem == NULL)
    {
        NV_DRM_DEV_LOG_ERR(nv_dev, "Failed to allocate gem object");
        return ERR_PTR(-ENOMEM);
    }

    nv_gem->type = type;
    nv_gem->u = *nv_gem_union;

    /* Initialize the gem object */

    drm_gem_private_object_init(dev, &nv_gem->base, size);

#if defined(NV_DRM_DRIVER_HAS_GEM_PRIME_RES_OBJ)
    reservation_object_init(&nv_gem->fenceContext.resv);
#endif

    return nv_gem;
}

void nvidia_drm_gem_free(struct drm_gem_object *gem)
{
    struct drm_device *dev = gem->dev;

#if defined(NV_DRM_DRIVER_HAS_GEM_PRIME_RES_OBJ) || \
    defined(NV_DRM_ATOMIC_MODESET_AVAILABLE)
    struct nvidia_drm_device *nv_dev = to_nv_drm_device(dev);
#endif

    struct nvidia_drm_gem_object *nv_gem = to_nv_gem_object(gem);

    WARN_ON(!mutex_is_locked(&dev->struct_mutex));

    /* Cleanup core gem object */

    drm_gem_object_release(&nv_gem->base);

#if defined(NV_DRM_DRIVER_HAS_GEM_PRIME_RES_OBJ)
    /* Make sure fencing gets torn down if client died before it could do it */
    nvidia_drm_gem_prime_fence_teardown(nv_dev, nv_gem);

    reservation_object_fini(&nv_gem->fenceContext.resv);
#endif

    switch (nv_gem->type)
    {
#if defined(NV_DRM_ATOMIC_MODESET_AVAILABLE)
        case NV_DRM_GEM_OBJECT_TYPE_DUMB_BUFFER:
            if (nv_gem->u.nvkms_memory.
                        pWriteCombinedIORemapAddress != NULL) {
                iounmap(nv_gem->u.nvkms_memory.
                        pWriteCombinedIORemapAddress);
            }

            nvKms->unmapMemory(nv_dev->pDevice,
                               nv_gem->u.nvkms_memory.pMemory,
                               NVKMS_KAPI_MAPPING_TYPE_USER,
                               nv_gem->u.nvkms_memory.pPhysicalAddress);

            /* Intentionally fall through to free pMemory handle */

        case NV_DRM_GEM_OBJECT_TYPE_MEMORY_NVKMS_IMPORTED:

            /* Free NvKmsKapiMemory handle associated with this gem object */

            nvKms->freeMemory(nv_dev->pDevice, nv_gem->u.nvkms_memory.pMemory);
            break;
#endif
        case NV_DRM_GEM_OBJECT_TYPE_PRIME:
            nvidia_drm_unlock_user_pages(
                nv_gem->u.userspace_memory.pages_count,
                nv_gem->u.userspace_memory.pages);
            break;
    }

    /* Free gem */

    nvidia_drm_free(nv_gem);
}

int nvidia_drm_gem_import_userspace_memory(struct drm_device *dev,
                                           void *data,
                                           struct drm_file *file_priv)
{
    struct nvidia_drm_device *nv_dev = to_nv_drm_device(dev);

    struct drm_nvidia_gem_import_userspace_memory_params *params = data;
    struct nvidia_drm_gem_object *nv_gem;
    union nvidia_drm_gem_object_union nv_gem_union = { };

    struct page **pages = NULL;
    unsigned long pages_count = 0;

    int ret = 0;

    if ((params->size % PAGE_SIZE) != 0)
    {
        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Userspace memory 0x%llx size should be in a multiple of page "
            "size to create a gem object",
            params->address);
        return -EINVAL;
    }

    pages_count = params->size / PAGE_SIZE;

    ret = nvidia_drm_lock_user_pages(params->address, pages_count, &pages);

    if (ret != 0)
    {
        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to lock user pages for address 0x%llx: %d",
            params->address, ret);
        return ret;
    }

    nv_gem_union.userspace_memory.pages = pages;
    nv_gem_union.userspace_memory.pages_count = pages_count;

    nv_gem = nvidia_drm_gem_new(dev,
                                NV_DRM_GEM_OBJECT_TYPE_PRIME,
                                &nv_gem_union,
                                params->size);
    if (IS_ERR(nv_gem))
    {
        ret = PTR_ERR(nv_gem);

        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to create gem object for userspace memory 0x%llx",
            params->address);
        goto failed;
    }

    return __nv_drm_gem_handle_create(file_priv, nv_gem, &params->handle);

failed:

    nvidia_drm_unlock_user_pages(pages_count, pages);

    return ret;
}

struct dma_buf *nvidia_drm_gem_prime_export
(
    struct drm_device *dev,
    struct drm_gem_object *gem, int flags
)
{
    struct nvidia_drm_device *nv_dev = to_nv_drm_device(dev);

    struct nvidia_drm_gem_object *nv_gem = to_nv_gem_object(gem);

    if (nv_gem->type != NV_DRM_GEM_OBJECT_TYPE_PRIME)
    {
        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Gem object 0x%p is not suitable to export", gem);
        return ERR_PTR(-EINVAL);
    }

    return drm_gem_prime_export(dev, gem, flags);
}

struct sg_table *nvidia_drm_gem_prime_get_sg_table(struct drm_gem_object *gem)
{
    struct nvidia_drm_gem_object *nv_gem = to_nv_gem_object(gem);

    if (nv_gem->type != NV_DRM_GEM_OBJECT_TYPE_PRIME)
    {
        return ERR_PTR(-EINVAL);
    }

    return drm_prime_pages_to_sg(nv_gem->u.userspace_memory.pages,
                                 nv_gem->u.userspace_memory.pages_count);
}

void *nvidia_drm_gem_prime_vmap(struct drm_gem_object *gem)
{
    struct nvidia_drm_gem_object *nv_gem = to_nv_gem_object(gem);

    if (nv_gem->type != NV_DRM_GEM_OBJECT_TYPE_PRIME)
    {
        return ERR_PTR(-EINVAL);
    }

    return nvidia_drm_vmap(nv_gem->u.userspace_memory.pages,
                           nv_gem->u.userspace_memory.pages_count);
}

void nvidia_drm_gem_prime_vunmap(struct drm_gem_object *gem, void *address)
{
    struct nvidia_drm_gem_object *nv_gem = to_nv_gem_object(gem);

    if (nv_gem->type != NV_DRM_GEM_OBJECT_TYPE_PRIME)
    {
        return;
    }

    nvidia_drm_vunmap(address);
}

#if defined(NV_DRM_DRIVER_HAS_GEM_PRIME_RES_OBJ)
struct reservation_object* nvidia_drm_gem_prime_res_obj
(
    struct drm_gem_object *obj
)
{
    struct nvidia_drm_gem_object *nv_gem = to_nv_gem_object(obj);

    return &nv_gem->fenceContext.resv;
}
#endif

#if defined(NV_DRM_ATOMIC_MODESET_AVAILABLE)

int nvidia_drm_dumb_create
(
    struct drm_file *file_priv,
    struct drm_device *dev, struct drm_mode_create_dumb *args
)
{
    struct nvidia_drm_device *nv_dev = to_nv_drm_device(dev);
    struct nvidia_drm_gem_object *nv_gem;
    union nvidia_drm_gem_object_union nv_gem_union = { };
    int ret = 0;

    args->pitch = roundup(args->width * ((args->bpp + 7) >> 3),
                          nv_dev->pitchAlignment);

    args->size = args->height * args->pitch;

    /* Core DRM requires gem object size to be aligned with PAGE_SIZE */

    args->size = roundup(args->size, PAGE_SIZE);

    nv_gem_union.nvkms_memory.pMemory =
        nvKms->allocateMemory(nv_dev->pDevice, args->size);

    if (nv_gem_union.nvkms_memory.pMemory == NULL)
    {
        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to allocate NvKmsKapiMemory for dumb object of size %llu",
            args->size);
        return -ENOMEM;
    }

    if (!nvKms->mapMemory(nv_dev->pDevice,
                          nv_gem_union.nvkms_memory.pMemory,
                          NVKMS_KAPI_MAPPING_TYPE_USER,
                          &nv_gem_union.nvkms_memory.pPhysicalAddress))
    {
        ret = -ENOMEM;

        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to map NvKmsKapiMemory 0x%p",
            nv_gem_union.nvkms_memory.pMemory);
        goto nvkms_map_memory_failed;
    }

    nv_gem_union.nvkms_memory.pWriteCombinedIORemapAddress = ioremap_wc(
        (uintptr_t)nv_gem_union.nvkms_memory.pPhysicalAddress,
        args->size);

    nv_gem = nvidia_drm_gem_new(dev,
                                NV_DRM_GEM_OBJECT_TYPE_DUMB_BUFFER,
                                &nv_gem_union,
                                args->size);

    if (IS_ERR(nv_gem))
    {
        ret = PTR_ERR(nv_gem);

        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to create gem object for NvKmsKapiMemory 0x%p",
            nv_gem_union.nvkms_memory.pMemory);
        goto nvidia_drm_gem_new_failed;
    }

    return __nv_drm_gem_handle_create(file_priv, nv_gem, &args->handle);


nvidia_drm_gem_new_failed:

    if (nv_gem_union.nvkms_memory.pWriteCombinedIORemapAddress != NULL) {
        iounmap(nv_gem_union.nvkms_memory.pWriteCombinedIORemapAddress);
    }

    nvKms->unmapMemory(nv_dev->pDevice,
                       nv_gem_union.nvkms_memory.pMemory,
                       NVKMS_KAPI_MAPPING_TYPE_USER,
                       nv_gem_union.nvkms_memory.pPhysicalAddress);

nvkms_map_memory_failed:

    nvKms->freeMemory(nv_dev->pDevice, nv_gem_union.nvkms_memory.pMemory);

    return ret;
}

int nvidia_drm_gem_import_nvkms_memory
(
    struct drm_device *dev,
    void *data,
    struct drm_file *file_priv
)
{
    struct nvidia_drm_device *nv_dev = to_nv_drm_device(dev);
    struct drm_nvidia_gem_import_nvkms_memory_params *p = data;
    union nvidia_drm_gem_object_union nv_gem_union = { };
    struct nvidia_drm_gem_object *nv_gem;

    if (!nvidia_drm_modeset_enabled(dev))
    {
        return -EINVAL;
    }

    nv_gem_union.nvkms_memory.pMemory =
        nvKms->importMemory(nv_dev->pDevice,
                            p->mem_size,
                            p->nvkms_params_ptr,
                            p->nvkms_params_size);

    if (nv_gem_union.nvkms_memory.pMemory == NULL)
    {
        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to import NVKMS memory to GEM object");
        return -EINVAL;
    }

    nv_gem_union.nvkms_memory.pPhysicalAddress = NULL;
    nv_gem_union.nvkms_memory.pWriteCombinedIORemapAddress = NULL;

    nv_gem = nvidia_drm_gem_new(dev,
                                NV_DRM_GEM_OBJECT_TYPE_MEMORY_NVKMS_IMPORTED,
                                &nv_gem_union,
                                p->mem_size);
    if (IS_ERR(nv_gem))
    {
        nvKms->freeMemory(nv_dev->pDevice, nv_gem_union.nvkms_memory.pMemory);

        return PTR_ERR(nv_gem);
    }

    return __nv_drm_gem_handle_create(file_priv, nv_gem, &p->handle);
}

int nvidia_drm_dumb_map_offset(struct drm_file *file,
                               struct drm_device *dev, uint32_t handle,
                               uint64_t *offset)
{
    struct nvidia_drm_device *nv_dev = to_nv_drm_device(dev);

    struct drm_gem_object *gem = NULL;
    struct nvidia_drm_gem_object *nv_gem = NULL;

    int ret = -EINVAL;


    if ((gem = nvidia_drm_gem_object_lookup(dev, file, handle)) == NULL) {
        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to lookup gem object for mapping: 0x%08x",
            handle);
        goto done;
    }

    nv_gem = to_nv_gem_object(gem);

    if (nv_gem->type != NV_DRM_GEM_OBJECT_TYPE_DUMB_BUFFER) {
        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Invalid gem object type for mapping: 0x%08x",
            handle);
        goto done;
    }

    if ((ret = drm_gem_create_mmap_offset(gem)) < 0) {
        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "drm_gem_create_mmap_offset failed with error code %d",
            ret);
        goto done;
    }

    *offset = drm_vma_node_offset_addr(&gem->vma_node);

    ret = 0;

done:
    if (gem != NULL) {
        drm_gem_object_unreference_unlocked(gem);
    }

    return ret;
}

/* XXX Move these vma operations to os layer */

static void nvidia_drm_vma_open(struct vm_area_struct *vma)
{
    struct drm_gem_object *gem = vma->vm_private_data;

    drm_gem_object_reference(gem);
}

static int __nv_drm_vma_fault(struct vm_area_struct *vma,
                              struct vm_fault *vmf)
{
    unsigned long address = nv_page_fault_va(vmf);
    struct drm_gem_object *gem = vma->vm_private_data;
    struct nvidia_drm_gem_object *nv_gem =
                    to_nv_gem_object(gem);
    unsigned long page_offset, pfn;
    int ret = -EINVAL;

    pfn = (unsigned long)(uintptr_t)nv_gem->u.nvkms_memory.pPhysicalAddress;
    pfn >>= PAGE_SHIFT;

    page_offset = vmf->pgoff - drm_vma_node_start(&gem->vma_node);

    ret = vm_insert_pfn(vma, address, pfn + page_offset);

    switch (ret) {
        case 0:
        case -EBUSY:
            /*
             * EBUSY indicates that another thread already handled
             * the faulted range.
             */
            return VM_FAULT_NOPAGE;
        case -ENOMEM:
            return VM_FAULT_OOM;
        default:
            WARN_ONCE(1, "Unhandled error in %s: %d\n", __FUNCTION__, ret);
            break;
    }

    return VM_FAULT_SIGBUS;
}

/*
 * Note that nvidia_drm_vma_fault() can be called for different or same
 * ranges of the same drm_gem_object simultaneously.
 */

#if defined(NV_VM_OPS_FAULT_REMOVED_VMA_ARG)
static int nvidia_drm_vma_fault(struct vm_fault *vmf)
{
    return __nv_drm_vma_fault(vmf->vma, vmf);
}
#else
static int nvidia_drm_vma_fault(struct vm_area_struct *vma,
                                struct vm_fault *vmf)
{
    return __nv_drm_vma_fault(vma, vmf);
}
#endif

static void nvidia_drm_vma_release(struct vm_area_struct *vma)
{
    struct drm_gem_object *gem = vma->vm_private_data;

    drm_gem_object_unreference_unlocked(gem);
}

const struct vm_operations_struct nv_drm_gem_vma_ops = {
    .open  = nvidia_drm_vma_open,
    .fault = nvidia_drm_vma_fault,
    .close = nvidia_drm_vma_release,
};
#endif /* NV_DRM_ATOMIC_MODESET_AVAILABLE */

#endif /* NV_DRM_AVAILABLE */
