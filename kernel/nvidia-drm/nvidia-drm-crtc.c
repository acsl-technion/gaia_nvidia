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
#include "nvidia-drm-crtc.h"

#include <drm/drm_crtc_helper.h>
#include <drm/drm_plane_helper.h>

#include <drm/drm_atomic.h>
#include <drm/drm_atomic_helper.h>

static const u32 nv_default_supported_plane_drm_formats[] = {
    DRM_FORMAT_ARGB1555,
    DRM_FORMAT_XRGB1555,
    DRM_FORMAT_RGB565,
    DRM_FORMAT_ARGB8888,
    DRM_FORMAT_XRGB8888,
    DRM_FORMAT_ABGR2101010,
    DRM_FORMAT_XBGR2101010,
};

static const u32 nv_supported_cursor_plane_drm_formats[] = {
    DRM_FORMAT_ARGB1555,
    DRM_FORMAT_ARGB8888,
};

static void nvidia_plane_destroy(struct drm_plane *plane)
{
    /* Cleanup core plane object */

    drm_plane_cleanup(plane);

    /* Free plane object*/

    nvidia_drm_free(plane);
}

static int nvidia_plane_atomic_check(struct drm_plane *plane,
                                     struct drm_plane_state *state)
{
    return 0;
}

static void nvidia_plane_atomic_update(struct drm_plane *plane,
                                       struct drm_plane_state *old_state)
{
}

static void nvidia_plane_atomic_disable(struct drm_plane *plane,
                                        struct drm_plane_state *old_state)
{
}

static const struct drm_plane_funcs nv_primary_plane_funcs = {
    .update_plane           = drm_atomic_helper_update_plane,
    .disable_plane          = drm_atomic_helper_disable_plane,
    .destroy                = nvidia_plane_destroy,
    .reset                  = drm_atomic_helper_plane_reset,
    .atomic_duplicate_state = drm_atomic_helper_plane_duplicate_state,
    .atomic_destroy_state   = drm_atomic_helper_plane_destroy_state,
};

static const struct drm_plane_helper_funcs nv_primary_plane_helper_funcs = {
    .atomic_check   = nvidia_plane_atomic_check,
    .atomic_update  = nvidia_plane_atomic_update,
    .atomic_disable = nvidia_plane_atomic_disable,
};

static const struct drm_plane_funcs nv_cursor_plane_funcs = {
    .update_plane           = drm_atomic_helper_update_plane,
    .disable_plane          = drm_atomic_helper_disable_plane,
    .destroy                = nvidia_plane_destroy,
    .reset                  = drm_atomic_helper_plane_reset,
    .atomic_duplicate_state = drm_atomic_helper_plane_duplicate_state,
    .atomic_destroy_state   = drm_atomic_helper_plane_destroy_state,
};

static const struct drm_plane_helper_funcs nv_cursor_plane_helper_funcs = {
    .atomic_check   = nvidia_plane_atomic_check,
    .atomic_update  = nvidia_plane_atomic_update,
    .atomic_disable = nvidia_plane_atomic_disable,
};

static void nvidia_crtc_destroy(struct drm_crtc *crtc)
{
    struct drm_device *dev = crtc->dev;
    struct nvidia_drm_device *nv_dev = to_nv_drm_device(dev);

    struct nvidia_drm_crtc *nv_crtc = DRM_CRTC_TO_NV_CRTC(crtc);

    NV_DRM_DEV_LOG_DEBUG(
        nv_dev,
        "Destroying CRTC created from head %u",
        nv_crtc->head);

    BUG_ON(!mutex_is_locked(&nv_dev->lock));

    nv_dev->nv_crtc[nv_crtc->head] = NULL;

    /* Clean up core crtc object */

    drm_crtc_cleanup(crtc);

    /* Free crtc object*/

    nvidia_drm_free(nv_crtc);
}

static struct drm_crtc_funcs nv_crtc_funcs = {
    .set_config             = drm_atomic_helper_set_config,
    .page_flip              = drm_atomic_helper_page_flip,
    .reset                  = drm_atomic_helper_crtc_reset,
    .destroy                = nvidia_crtc_destroy,
    .atomic_duplicate_state = drm_atomic_helper_crtc_duplicate_state,
    .atomic_destroy_state   = drm_atomic_helper_crtc_destroy_state,
};

static bool
nvidia_crtc_mode_fixup(struct drm_crtc *crtc,
                       const struct drm_display_mode *mode,
                       struct drm_display_mode *adjusted_mode)
{
    return true;
}

static void nvidia_crtc_prepare(struct drm_crtc *crtc)
{

}

static void nvidia_crtc_commit(struct drm_crtc *crtc)
{

}

static void nvidia_crtc_disable(struct drm_crtc *crtc)
{

}

static void nvidia_crtc_enable(struct drm_crtc *crtc)
{

}

static const struct drm_crtc_helper_funcs nv_crtc_helper_funcs = {
    .prepare    = nvidia_crtc_prepare,
    .commit     = nvidia_crtc_commit,
    .enable     = nvidia_crtc_enable,
    .disable    = nvidia_crtc_disable,
    .mode_fixup = nvidia_crtc_mode_fixup,
};

static struct drm_plane *nvidia_plane_create
(
    struct drm_device *dev,
    enum drm_plane_type plane_type,
    const u32 formats[],
    unsigned int formats_count,
    const struct drm_plane_funcs *funcs,
    const struct drm_plane_helper_funcs *helper_funcs,
    struct drm_crtc *crtc_uninitialized,
    unsigned long crtc_mask
)
{
    struct drm_plane *plane = NULL;
    struct drm_plane_state *plane_state = NULL;

    int ret;

    /* Allocate memory for plane object */

    plane = nvidia_drm_calloc(1, sizeof(*plane));

    if (plane == NULL)
    {
        ret = -ENOMEM;
        goto failed;
    }

    /* Allocate memory for plane state */

    plane_state = nvidia_drm_calloc(1, sizeof(*plane_state));

    if (plane_state == NULL)
    {
        ret = -ENOMEM;
        goto failed;
    }

    plane->state = plane_state;
    plane_state->plane = plane;

    plane_state->crtc = crtc_uninitialized;

    /* Initialize plane */

    ret = drm_universal_plane_init(
        dev,
        plane, crtc_mask, funcs,
        formats, formats_count,
        plane_type
#if defined(NV_DRM_INIT_FUNCTIONS_HAVE_NAME_ARG)
        , NULL
#endif
        );

    if (ret != 0)
    {
        goto failed;
    }

    drm_plane_helper_add(plane, helper_funcs);

    return plane;

failed:

    nvidia_drm_free(plane_state);

    nvidia_drm_free(plane);

    return ERR_PTR(ret);
}

/*
 * Add drm crtc for given head and supported enum NvKmsSurfaceMemoryFormats.
 */
struct drm_crtc *nvidia_drm_add_crtc(struct drm_device *dev, NvU32 head)
{
    struct nvidia_drm_device *nv_dev = to_nv_drm_device(dev);

    struct drm_crtc *crtc = NULL;
    struct drm_crtc_state *crtc_state = NULL;

    struct drm_plane *primary_plane = NULL, *cursor_plane = NULL;

    struct nvidia_drm_crtc *nv_crtc = NULL;

    int ret;

    /* Look up for existing crtcs with same head */

    list_for_each_entry(crtc, &dev->mode_config.crtc_list, head)
    {
        struct nvidia_drm_crtc *nv_crtc = DRM_CRTC_TO_NV_CRTC(crtc);

        if (nv_crtc->head == head)
        {
            return &nv_crtc->base;
        }
    }

    NV_DRM_DEV_LOG_DEBUG(nv_dev, "Creating CRTC from head %u", head);

    /* Allocate memory for crtc object */

    nv_crtc = nvidia_drm_calloc(1, sizeof(*nv_crtc));

    if (nv_crtc == NULL)
    {
        NV_DRM_DEV_LOG_ERR(nv_dev, "Failed to allocate nvidia crtc object");
        return ERR_PTR(-ENOMEM);
    }

    /* Allocate memory for crtc state */

    crtc_state = nvidia_drm_calloc(1, sizeof(*crtc_state));

    if (crtc_state == NULL)
    {
        nvidia_drm_free(nv_crtc);

        NV_DRM_DEV_LOG_ERR(nv_dev, "Failed to allocate crtc state");
        return ERR_PTR(-ENOMEM);
    }

    nv_crtc->head = head;

    nv_crtc->base.state = crtc_state;
    crtc_state->crtc    = &nv_crtc->base;

    /* Create primary plane */

    primary_plane = nvidia_plane_create(
        dev,
        DRM_PLANE_TYPE_PRIMARY,
        nv_default_supported_plane_drm_formats,
        ARRAY_SIZE(nv_default_supported_plane_drm_formats),
        &nv_primary_plane_funcs,
        &nv_primary_plane_helper_funcs,
        &nv_crtc->base,
        BIT(nv_crtc->head));

    if (IS_ERR(primary_plane))
    {
        ret = PTR_ERR(primary_plane);

        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to create primary plane for head %u", head);
        goto failed_create_primary;
    }

    /* Create cursor plane */

    cursor_plane = nvidia_plane_create(
        dev,
        DRM_PLANE_TYPE_CURSOR,
        nv_supported_cursor_plane_drm_formats,
        ARRAY_SIZE(nv_supported_cursor_plane_drm_formats),
        &nv_cursor_plane_funcs,
        &nv_cursor_plane_helper_funcs,
        &nv_crtc->base,
        BIT(nv_crtc->head));

    if (IS_ERR(cursor_plane))
    {
        ret = PTR_ERR(cursor_plane);

        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to create cursor plane for head %u", head);
        goto failed_create_cursor;
    }

    /* Initialize crtc with primary and cursor planes */

    ret = drm_crtc_init_with_planes(dev,
                                    &nv_crtc->base,
                                    primary_plane, cursor_plane,
                                    &nv_crtc_funcs
#if defined(NV_DRM_INIT_FUNCTIONS_HAVE_NAME_ARG)
                                    , NULL
#endif
                                    );

    if (ret != 0)
    {
        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to init crtc for head %u with planes", head);
        goto failed_init_crtc;
    }

    /* Add crtc to drm sub-system */

    drm_crtc_helper_add(&nv_crtc->base, &nv_crtc_helper_funcs);

    BUG_ON(!mutex_is_locked(&nv_dev->lock));

    nv_dev->nv_crtc[head] = nv_crtc;

    return &nv_crtc->base;

failed_init_crtc:

    drm_plane_cleanup(cursor_plane);

    nvidia_drm_free(cursor_plane);

failed_create_cursor:

    drm_plane_cleanup(primary_plane);

    nvidia_drm_free(primary_plane);

failed_create_primary:

    nvidia_drm_free(crtc_state);

    nvidia_drm_free(nv_crtc);

    return ERR_PTR(ret);
}

#endif
