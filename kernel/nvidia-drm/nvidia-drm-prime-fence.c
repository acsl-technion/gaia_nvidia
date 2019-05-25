/*
 * Copyright (c) 2016, NVIDIA CORPORATION. All rights reserved.
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

#include "nvidia-drm-conftest.h"

#if defined(NV_DRM_AVAILABLE)

#include "nvidia-drm-priv.h"
#include "nvidia-drm-ioctl.h"
#include "nvidia-drm-gem.h"
#include "nvidia-drm-prime-fence.h"

#if defined(NV_DRM_DRIVER_HAS_GEM_PRIME_RES_OBJ)

#include "nvidia-dma-fence-helper.h"

struct nv_drm_prime_fence {
    nv_dma_fence_t base;
    spinlock_t lock;

    struct nvidia_drm_gem_object *nv_gem;
};

static inline
struct nv_drm_prime_fence *to_nv_drm_prime_fence(nv_dma_fence_t *fence) {
    return container_of(fence, struct nv_drm_prime_fence, base);
}

static inline bool
nv_fence_ready_to_signal(struct nv_drm_prime_fence *nv_fence)
{
    struct nvidia_drm_gem_object *nv_gem = nv_fence->nv_gem;
    uint32_t semVal;

    if (!nv_gem->fenceContext.mapped) {
        /* If semaphore surface isn't mapped, just allow fences to pass */
        return true;
    }

    /* Index into surface with 16 byte stride */
    semVal = *(nv_gem->fenceContext.pLinearAddress +
               (nv_gem->fenceContext.fenceSemIndex * 4));

    return (nv_fence->base.seqno <= semVal);
}

static const char *nvidia_drm_gem_prime_fence_op_get_driver_name
(
    nv_dma_fence_t *fence
)
{
    return "NVIDIA";
}

static const char *nvidia_drm_gem_prime_fence_op_get_timeline_name
(
    nv_dma_fence_t *fence
)
{
    return "nvidia.prime";
}

static bool nvidia_drm_gem_prime_fence_op_enable_signaling
(
    nv_dma_fence_t *fence
)
{
    // Take additional reference per the spec in Linux's dma-fence.h
    nv_dma_fence_get(fence);
    return true;
}

static void nvidia_drm_gem_prime_fence_op_release
(
    nv_dma_fence_t *fence
)
{
    struct nv_drm_prime_fence *nv_fence = to_nv_drm_prime_fence(fence);
    nvidia_drm_free(nv_fence);
}

static signed long nvidia_drm_gem_prime_fence_op_wait
(
    nv_dma_fence_t *fence,
    bool intr,
    signed long timeout
)
{
    /*
     * If the waiter requests to wait with no timeout, force a timeout to ensure
     * that it won't get stuck forever in the kernel if something were to go
     * wrong with signaling, such as a malicious userspace not releasing the
     * semaphore.
     *
     * 96 ms (roughly 6 frames @ 60 Hz) is arbitrarily chosen to be long enough
     * that it should never get hit during normal operation, but not so long
     * that the system becomes unresponsive.
     */
    return nv_dma_fence_default_wait(fence, intr,
                              (timeout == MAX_SCHEDULE_TIMEOUT) ?
                                  msecs_to_jiffies(96) : timeout);
}

static const nv_dma_fence_ops_t nvidia_drm_gem_prime_fence_ops = {
    .get_driver_name = nvidia_drm_gem_prime_fence_op_get_driver_name,
    .get_timeline_name = nvidia_drm_gem_prime_fence_op_get_timeline_name,
    .enable_signaling = nvidia_drm_gem_prime_fence_op_enable_signaling,
    .release = nvidia_drm_gem_prime_fence_op_release,
    .wait = nvidia_drm_gem_prime_fence_op_wait,
};

static void nvidia_drm_gem_prime_fence_destroy_semaphore
(
    struct nvidia_drm_device *nv_dev,
    struct nvidia_drm_gem_object *nv_gem
)
{
    WARN_ON(!mutex_is_locked(&nv_dev->dev->struct_mutex));

    if (nv_gem->fenceContext.mapped)
    {
        nvKms->unmapMemory(nv_dev->pDevice,
                           nv_gem->fenceContext.pSemSurface,
                           NVKMS_KAPI_MAPPING_TYPE_KERNEL,
                           (void *) nv_gem->fenceContext.pLinearAddress);

        nv_gem->fenceContext.pLinearAddress = NULL;
        nv_gem->fenceContext.mapped = false;
    }

    if (nv_gem->fenceContext.pSemSurface)
    {
        nvKms->freeMemory(nv_dev->pDevice, nv_gem->fenceContext.pSemSurface);
        nv_gem->fenceContext.pSemSurface = NULL;
    }

    nv_gem->fenceContext.fenceSemIndex = ~0;
}

static NvU32 nvidia_drm_gem_prime_fence_import_semaphore
(
    struct nvidia_drm_device *nv_dev,
    struct nvidia_drm_gem_object *nv_gem,
    NvU32 index,
    NvU64 size,
    NvU64 nvkms_params_ptr,
    NvU64 nvkms_params_size
)
{
    int ret = 0;

    WARN_ON(!mutex_is_locked(&nv_dev->dev->struct_mutex));

    /*
     * We should never import a fence semaphore more than once; the calling
     * function checks for that.
     */
    WARN_ON(nv_gem->fenceContext.pSemSurface != NULL);

    nv_gem->fenceContext.pSemSurface = nvKms->importMemory(nv_dev->pDevice,
                                                           size,
                                                           nvkms_params_ptr,
                                                           nvkms_params_size);
    if (!nv_gem->fenceContext.pSemSurface)
    {
        ret = -ENOMEM;

        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to import fence semaphore surface");

        goto fail;
    }

    if (!nvKms->mapMemory(nv_dev->pDevice,
                          nv_gem->fenceContext.pSemSurface,
                          NVKMS_KAPI_MAPPING_TYPE_KERNEL,
                          (void **) &nv_gem->fenceContext.pLinearAddress))
    {
        ret = -ENOMEM;

        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to map fence semaphore surface");

        goto fail;
    }
    nv_gem->fenceContext.mapped = true;

    nv_gem->fenceContext.fenceSemIndex = index;

    return ret;
fail:
    nvidia_drm_gem_prime_fence_destroy_semaphore(nv_dev, nv_gem);
    return ret;
}

static void nvidia_drm_gem_prime_fence_signal
(
    struct nvidia_drm_device *nv_dev,
    struct nvidia_drm_gem_object *nv_gem,
    bool force
)
{
    nv_dma_fence_t *fence =
        reservation_object_get_excl(&nv_gem->fenceContext.resv);
    struct nv_drm_prime_fence *nv_fence;

    WARN_ON(!mutex_is_locked(&nv_dev->dev->struct_mutex));

    if (!fence)
    {
        return;
    }

    nv_fence = to_nv_drm_prime_fence(fence);

    if (force || nv_fence_ready_to_signal(nv_fence))
    {
        bool was_signaled = nv_dma_fence_is_signaled(fence);

        nv_dma_fence_signal(fence);

        if (!was_signaled)
        {
            if (test_bit(NV_DMA_FENCE_FLAG_ENABLE_SIGNAL_BIT, &fence->flags))
            {
                // enable_signaling() takes additional reference per the spec
                nv_dma_fence_put(fence);
            }
        }
    }
}

struct nvidia_drm_gem_prime_fence_event_args {
    struct nvidia_drm_device *nv_dev;
    struct nvidia_drm_gem_object *nv_gem;
};

static void NVKMS_KAPI_CALL nvidia_drm_gem_prime_fence_event
(
    void *dataPtr,
    NvU32 dataU32
)
{
    struct nvidia_drm_gem_prime_fence_event_args *cbArgs = dataPtr;

    struct nvidia_drm_device *nv_dev = cbArgs->nv_dev;
    struct nvidia_drm_gem_object *nv_gem = cbArgs->nv_gem;

    mutex_lock(&nv_dev->dev->struct_mutex);

    nvidia_drm_gem_prime_fence_signal(nv_dev, nv_gem, false);

    mutex_unlock(&nv_dev->dev->struct_mutex);
}

static void nvidia_drm_gem_prime_destroy_fence_event
(
    struct nvidia_drm_device *nv_dev,
    struct nvidia_drm_gem_object *nv_gem
)
{
    WARN_ON(!mutex_is_locked(&nv_dev->dev->struct_mutex));

    nvidia_drm_gem_prime_fence_signal(nv_dev, nv_gem, true);

    if (nv_gem->fenceContext.cb)
    {
        nvKms->freeChannelEvent(nv_dev->pDevice, nv_gem->fenceContext.cb);
        nv_gem->fenceContext.cb = NULL;
    }

    if (nv_gem->fenceContext.cbArgs)
    {
        if (nv_gem->fenceContext.cbArgs->nv_gem)
        {
            drm_gem_object_unreference(&nv_gem->base);
        }

        nvidia_drm_free(nv_gem->fenceContext.cbArgs);
        nv_gem->fenceContext.cbArgs = NULL;
    }
}

static NvU32 nvidia_drm_gem_prime_create_fence_event
(
    struct nvidia_drm_device *nv_dev,
    struct nvidia_drm_gem_object *nv_gem,
    NvU64 nvkms_params_ptr,
    NvU64 nvkms_params_size
)
{
    int ret = 0;

    WARN_ON(!mutex_is_locked(&nv_dev->dev->struct_mutex));

    if (nv_gem->fenceContext.cb)
    {
        ret = -EINVAL;

        NV_DRM_DEV_LOG_ERR(nv_dev, "Double creation of fence event");

        return ret;
    }

    nv_gem->fenceContext.cbArgs =
        nvidia_drm_calloc(1, sizeof(*nv_gem->fenceContext.cbArgs));
    if (!nv_gem->fenceContext.cbArgs)
    {
        ret = -ENOMEM;

        NV_DRM_DEV_LOG_ERR(nv_dev,
                           "Failed to allocate fence signaling event args");

        goto fail;
    }

    drm_gem_object_reference(&nv_gem->base);

    nv_gem->fenceContext.cbArgs->nv_dev = nv_dev;
    nv_gem->fenceContext.cbArgs->nv_gem = nv_gem;

    nv_gem->fenceContext.cb =
        nvKms->allocateChannelEvent(nv_dev->pDevice,
                                    nvidia_drm_gem_prime_fence_event,
                                    nv_gem->fenceContext.cbArgs,
                                    nvkms_params_ptr, nvkms_params_size);
    if (!nv_gem->fenceContext.cb)
    {
        ret = -ENOMEM;

        NV_DRM_DEV_LOG_ERR(nv_dev,
                           "Failed to allocate fence signaling event");

        goto fail;
    }

    return ret;
fail:
    nvidia_drm_gem_prime_destroy_fence_event(nv_dev, nv_gem);
    return ret;
}

void nvidia_drm_gem_prime_fence_teardown
(
    struct nvidia_drm_device *nv_dev,
    struct nvidia_drm_gem_object *nv_gem
)
{
    nvidia_drm_gem_prime_fence_signal(nv_dev, nv_gem, true);
    nvidia_drm_gem_prime_fence_destroy_semaphore(nv_dev, nv_gem);
    nvidia_drm_gem_prime_destroy_fence_event(nv_dev, nv_gem);

    nv_gem->fenceContext.init = false;
}

int nvidia_drm_gem_prime_fence_supported
(
    struct drm_device *dev,
    void *data,
    struct drm_file *file_priv
)
{
    struct nvidia_drm_device *nv_dev = to_nv_drm_device(dev);
    return nv_dev->pDevice ? 0 : -EINVAL;
}

int nvidia_drm_gem_prime_fence_init
(
    struct drm_device *dev,
    void *data,
    struct drm_file *file_priv
)
{
    int ret = -EINVAL;
    struct nvidia_drm_device *nv_dev = to_nv_drm_device(dev);
    struct drm_nvidia_gem_prime_fence_init_params *p = data;

    struct drm_gem_object *gem;
    struct nvidia_drm_gem_object *nv_gem;

    mutex_lock(&dev->struct_mutex);

    gem = nvidia_drm_gem_object_lookup(nv_dev->dev, file_priv, p->handle);

    if (!gem)
    {
        ret = -EINVAL;

        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to lookup gem object for fencing init: 0x%08x",
            p->handle);

        goto unlock_struct_mutex;
    }

    nv_gem = to_nv_gem_object(gem);

    if (nv_gem->fenceContext.init)
    {
        ret = -EINVAL;

        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Attempt to init a gem object already "
            "initialized for fencing : 0x%08x",
            p->handle);

        goto unlock_gem_object;
    }

    /*
     * nv_dma_fence_context_alloc() cannot fail, so we do not need to check a return
     * value.
     */
    nv_gem->fenceContext.context = nv_dma_fence_context_alloc(1);

    ret = nvidia_drm_gem_prime_fence_import_semaphore(
              nv_dev, nv_gem, p->index,
              p->size,
              p->import_mem_nvkms_params_ptr,
              p->import_mem_nvkms_params_size);
    if (ret < 0)
    {
        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to import semaphore surface: 0x%08x",
            p->handle);

        goto unlock_gem_object;
    }

    ret = nvidia_drm_gem_prime_create_fence_event(
            nv_dev, nv_gem,
            p->event_nvkms_params_ptr,
            p->event_nvkms_params_size);
    if (ret < 0)
    {
        nvidia_drm_gem_prime_fence_destroy_semaphore(nv_dev, nv_gem);
        goto unlock_gem_object;
    }

    ret = 0;

    nv_gem->fenceContext.init = true;

unlock_gem_object:
    drm_gem_object_unreference(gem);
unlock_struct_mutex:
    mutex_unlock(&dev->struct_mutex);

    return ret;
}

int nvidia_drm_gem_prime_fence_fini
(
    struct drm_device *dev,
    void *data,
    struct drm_file *file_priv
)
{
    int ret = -EINVAL;
    struct nvidia_drm_device *nv_dev = to_nv_drm_device(dev);
    struct drm_nvidia_gem_prime_fence_fini_params *p = data;

    struct drm_gem_object *gem;
    struct nvidia_drm_gem_object *nv_gem;

    mutex_lock(&dev->struct_mutex);

    gem = nvidia_drm_gem_object_lookup(nv_dev->dev, file_priv, p->handle);

    if (!gem)
    {
        ret = -EINVAL;

        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to lookup gem object for fencing fini: 0x%08x",
            p->handle);

        goto unlock_struct_mutex;
    }

    nv_gem = to_nv_gem_object(gem);

    if (!nv_gem->fenceContext.init)
    {
        ret = -EINVAL;

        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Attempt to fini a gem object not initialized for fencing : 0x%08x",
            p->handle);

        goto unlock_gem_object;
    }

    nv_gem->fenceContext.context = 0;

    nvidia_drm_gem_prime_fence_teardown(nv_dev, nv_gem);

    ret = 0;

unlock_gem_object:
    drm_gem_object_unreference(gem);

unlock_struct_mutex:
    mutex_unlock(&dev->struct_mutex);

    return ret;
}

int nvidia_drm_gem_prime_fence_attach
(
    struct drm_device *dev,
    void *data,
    struct drm_file *file_priv
)
{
    int ret = -EINVAL;
    struct nvidia_drm_device *nv_dev = to_nv_drm_device(dev);
    struct drm_nvidia_gem_prime_fence_attach_params *p = data;

    struct drm_gem_object *gem;
    struct nvidia_drm_gem_object *nv_gem;

    struct nv_drm_prime_fence *nv_fence;

    mutex_lock(&dev->struct_mutex);

    gem = nvidia_drm_gem_object_lookup(nv_dev->dev, file_priv, p->handle);

    if (!gem)
    {
        ret = -EINVAL;

        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to lookup gem object for fence attach: 0x%08x",
            p->handle);

        goto unlock_struct_mutex;
    }

    nv_gem = to_nv_gem_object(gem);

    if (!nv_gem->fenceContext.init)
    {
        ret = -EINVAL;

        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Attempt to attach a fence to a gem "
            "object not initialized for fencing : 0x%08x",
            p->handle);

        goto unlock_struct_mutex;
    }

    nv_fence = nvidia_drm_calloc(1, sizeof(*nv_fence));
    if (!nv_fence)
    {
        ret = -ENOMEM;

        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to allocate fence: 0x%08x", p->handle);

        goto unlock_gem_object;
    }

    nv_fence->nv_gem = nv_gem;

    spin_lock_init(&nv_fence->lock);
    nv_dma_fence_init(&nv_fence->base, &nvidia_drm_gem_prime_fence_ops,
                      &nv_fence->lock, nv_gem->fenceContext.context,
                      p->sem_thresh);

    /* We could be replacing an existing exclusive fence; force signal it to
     * unblock anyone waiting on it and clean up software signaling. */
    nvidia_drm_gem_prime_fence_signal(nv_dev, nv_gem, true);

    reservation_object_add_excl_fence(&nv_gem->fenceContext.resv,
                                      &nv_fence->base);
    nv_dma_fence_put(&nv_fence->base); /* Reservation object has reference */

    ret = 0;

unlock_gem_object:
    drm_gem_object_unreference(gem);

unlock_struct_mutex:
    mutex_unlock(&dev->struct_mutex);

    return ret;
}

int nvidia_drm_gem_prime_fence_force_signal
(
    struct drm_device *dev,
    void *data,
    struct drm_file *file_priv
)
{
    int ret = -EINVAL;
    struct nvidia_drm_device *nv_dev = to_nv_drm_device(dev);
    struct drm_nvidia_gem_prime_fence_force_signal_params *p = data;

    struct drm_gem_object *gem;
    struct nvidia_drm_gem_object *nv_gem;

    mutex_lock(&dev->struct_mutex);

    gem = nvidia_drm_gem_object_lookup(nv_dev->dev, file_priv, p->handle);

    if (!gem)
    {
        ret = -EINVAL;

        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to lookup gem object for fence attach: 0x%08x",
            p->handle);

        goto unlock_struct_mutex;
    }

    nv_gem = to_nv_gem_object(gem);

    if (!nv_gem->fenceContext.init)
    {
        ret = -EINVAL;

        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Attempt to force signal a gem object "
            "not initialized for fencing : 0x%08x",
            p->handle);

        goto unlock_gem_object;
    }

    nvidia_drm_gem_prime_fence_signal(nv_dev, nv_gem, true);

    ret = 0;

unlock_gem_object:
    drm_gem_object_unreference(gem);

unlock_struct_mutex:
    mutex_unlock(&dev->struct_mutex);

    return ret;
}

#endif /* NV_DRM_DRIVER_HAS_GEM_PRIME_RES_OBJ */

#endif /* NV_DRM_AVAILABLE */
