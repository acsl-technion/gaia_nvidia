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

/*
 * This file contains snapshots of DRM helper functions from the
 * Linux kernel which are used by nvidia-drm.ko if the target kernel
 * predates the helper function.  Having these functions consistently
 * present simplifies nvidia-drm.ko source.
 */

#include "nvidia-drm-helper.h"

#if defined(NV_DRM_ATOMIC_MODESET_AVAILABLE)

#include <drm/drmP.h>

/*
 * drm_atomic_set_mode_for_crtc() was added by kernel commit
 * 819364da20fd914aba2fd03e95ee0467286752f5 which was Signed-off-by:
 *      Daniel Stone <daniels@collabora.com>
 *      Daniel Vetter <daniel.vetter@ffwll.ch>
 *
 * drm_atomic_set_mode_for_crtc() was copied from
 *      linux/drivers/gpu/drm/drm_atomic.c @
 *      819364da20fd914aba2fd03e95ee0467286752f5
 * which has the following copyright and license information:
 *
 * Copyright (C) 2014 Red Hat
 * Copyright (C) 2014 Intel Corp.
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
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors:
 * Rob Clark <robdclark@gmail.com>
 * Daniel Vetter <daniel.vetter@ffwll.ch>
 */
int nv_drm_atomic_set_mode_for_crtc(struct drm_crtc_state *state,
                                    struct drm_display_mode *mode)
{
#if defined(NV_DRM_ATOMIC_SET_MODE_FOR_CRTC)
    return drm_atomic_set_mode_for_crtc(state, mode);
#else
    /* Early return for no change. */
    if (mode && memcmp(&state->mode, mode, sizeof(*mode)) == 0)
        return 0;

    if (mode) {
        drm_mode_copy(&state->mode, mode);
        state->enable = true;
        DRM_DEBUG_ATOMIC("Set [MODE:%s] for CRTC state %p\n",
                         mode->name, state);
    } else {
        memset(&state->mode, 0, sizeof(state->mode));
        state->enable = false;
        DRM_DEBUG_ATOMIC("Set [NOMODE] for CRTC state %p\n",
                         state);
    }

    return 0;
#endif
}

/*
 * drm_atomic_clean_old_fb() was added by commit
 * 0f45c26fc302c02b0576db37d4849baa53a2bb41, which was Signed-off-by:
 *      Maarten Lankhorst <maarten.lankhorst@linux.intel.com>
 *      Jani Nikula <jani.nikula@intel.com>
 *
 * drm_atomic_clean_old_fb()() was copied from
 *      linux/drivers/gpu/drm/drm_atomic.c @
 *      0f45c26fc302c02b0576db37d4849baa53a2bb41
 * which has the following copyright and license information:
 *
 * Copyright (C) 2014 Red Hat
 * Copyright (C) 2014 Intel Corp.
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
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors:
 * Rob Clark <robdclark@gmail.com>
 * Daniel Vetter <daniel.vetter@ffwll.ch>
 */
void nv_drm_atomic_clean_old_fb(struct drm_device *dev,
                                unsigned plane_mask,
                                int ret)
{
#if defined(NV_DRM_ATOMIC_CLEAN_OLD_FB)
    return drm_atomic_clean_old_fb(dev, plane_mask, ret);
#else
    struct drm_plane *plane;

    /* if succeeded, fixup legacy plane crtc/fb ptrs before dropping
     * locks (ie. while it is still safe to deref plane->state).  We
     * need to do this here because the driver entry points cannot
     * distinguish between legacy and atomic ioctls.
     */
    drm_for_each_plane_mask(plane, dev, plane_mask) {
        if (ret == 0) {
            struct drm_framebuffer *new_fb = plane->state->fb;
            if (new_fb)
                drm_framebuffer_reference(new_fb);
            plane->fb = new_fb;
            plane->crtc = plane->state->crtc;

            if (plane->old_fb)
                drm_framebuffer_unreference(plane->old_fb);
       }
       plane->old_fb = NULL;
   }
#endif
}

#endif /* NV_DRM_ATOMIC_MODESET_AVAILABLE */
