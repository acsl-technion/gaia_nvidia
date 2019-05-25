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

#if defined(NV_DRM_ATOMIC_MODESET_AVAILABLE)

#include "nvidia-drm-priv.h"
#include "nvidia-drm-ioctl.h"
#include "nvidia-drm-fb.h"
#include "nvidia-drm-utils.h"
#include "nvidia-drm-gem.h"

#include <drm/drm_crtc_helper.h>

static void nvidia_framebuffer_destroy(struct drm_framebuffer *fb)
{
    struct nvidia_drm_device *nv_dev = to_nv_drm_device(fb->dev);

    struct nvidia_drm_framebuffer *nv_fb =
                        DRM_FRAMEBUFFER_TO_NV_FRAMEBUFFER(fb);


    /* Unreference gem object */

    drm_gem_object_unreference_unlocked(nv_fb->gem);

    /* Cleaup core framebuffer object */

    drm_framebuffer_cleanup(fb);

    /* Free NvKmsKapiSurface associated with this framebuffer object */

    nvKms->destroySurface(nv_dev->pDevice, nv_fb->pSurface);

    /* Free framebuffer */

    nvidia_drm_free(nv_fb);
}

static int nvidia_framebuffer_create_handle
(
    struct drm_framebuffer *fb,
    struct drm_file *file, unsigned int *handle
)
{
    struct nvidia_drm_framebuffer *nv_fb =
                    DRM_FRAMEBUFFER_TO_NV_FRAMEBUFFER(fb);

    return drm_gem_handle_create(file, nv_fb->gem, handle);
}

static struct drm_framebuffer_funcs nv_framebuffer_funcs = {
    .destroy       = nvidia_framebuffer_destroy,
    .create_handle = nvidia_framebuffer_create_handle,
};

struct drm_framebuffer *nvidia_drm_internal_framebuffer_create(
    struct drm_device *dev,
    struct drm_file *file,
    struct drm_mode_fb_cmd2 *cmd)
{
    struct nvidia_drm_device *nv_dev = to_nv_drm_device(dev);

    struct nvidia_drm_framebuffer *nv_fb;

    struct drm_gem_object *gem;
    struct nvidia_drm_gem_object *nv_gem;

    enum NvKmsSurfaceMemoryFormat format;

    int ret;

    NV_DRM_DEV_LOG_DEBUG(
        nv_dev,
        "Creating a framebuffer of dimensions %ux%u from gem handle 0x%08x",
        cmd->width, cmd->height,
        cmd->handles[0]);

    if (!drm_format_to_nvkms_format(cmd->pixel_format, &format))
    {
        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Unsupported drm pixel format 0x%08x", cmd->pixel_format);
        return ERR_PTR(-EINVAL);
    }

    /*
     * In case of planar formats, this ioctl allows up to 4 buffer objects with
     * offsets and pitches per plane.
     *
     * We don't support any planar format, pick up first buffer only.
     */

    gem = nvidia_drm_gem_object_lookup(dev, file, cmd->handles[0]);

    if (gem == NULL)
    {
        NV_DRM_DEV_LOG_ERR(nv_dev, "Failed to find gem object");
        return ERR_PTR(-ENOENT);
    }

    nv_gem = to_nv_gem_object(gem);

    if (nv_gem->type != NV_DRM_GEM_OBJECT_TYPE_DUMB_BUFFER &&
        nv_gem->type != NV_DRM_GEM_OBJECT_TYPE_MEMORY_NVKMS_IMPORTED) {
        ret = -EINVAL;

        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Invalid gem object 0x%08x for framebuffer creation",
            cmd->handles[0]);
        goto failed_fb_create;
    }

    /* Allocate memory for the framebuffer object */

    nv_fb = nvidia_drm_calloc(1, sizeof(*nv_fb));

    if (nv_fb == NULL)
    {
        ret = -ENOMEM;

        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to allocate memory for framebuffer obejct");
        goto failed_fb_create;
    }

    nv_fb->gem = gem;

    /* Fill out framebuffer metadata from the userspace fb creation request */

    drm_helper_mode_fill_fb_struct(
        #if defined(NV_DRM_HELPER_MODE_FILL_FB_STRUCT_HAS_DEV_ARG)
        dev,
        #endif
        &nv_fb->base,
        cmd);

    /* Initialize the base framebuffer object and add it to drm subsystem */

    ret = drm_framebuffer_init(dev, &nv_fb->base, &nv_framebuffer_funcs);

    if (ret != 0)
    {
        NV_DRM_DEV_LOG_ERR(nv_dev, "Failed to initialize framebuffer object");
        goto failed_fb_init;
    }

    /* Create NvKmsKapiSurface */

    nv_fb->pSurface = nvKms->createSurface(
        nv_dev->pDevice, nv_gem->u.nvkms_memory.pMemory,
        format, nv_fb->base.width, nv_fb->base.height, nv_fb->base.pitches[0]);

    if (nv_fb->pSurface == NULL) {
        ret = -EINVAL;

        NV_DRM_DEV_LOG_ERR(nv_dev, "Failed to create NvKmsKapiSurface");
        goto failed_nvkms_create_surface;
    }

    return &nv_fb->base;

failed_nvkms_create_surface:

    drm_framebuffer_cleanup(&nv_fb->base);

failed_fb_init:

    nvidia_drm_free(nv_fb);

failed_fb_create:

    drm_gem_object_unreference_unlocked(&nv_gem->base);

    return ERR_PTR(ret);
}

#endif
