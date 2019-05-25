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

#ifndef __NVIDIA_DRM_HELPER_H__
#define __NVIDIA_DRM_HELPER_H__

#include "nvidia-drm-conftest.h"

#if defined(NV_DRM_AVAILABLE)

#include <drm/drmP.h>

/*
 * drm_dev_unref() has been added and drm_dev_free() removed by commit -
 *
 *      2014-01-29: 099d1c290e2ebc3b798961a6c177c3aef5f0b789
 */
static inline void nv_drm_dev_free(struct drm_device *dev)
{
#if defined(NV_DRM_DEV_UNREF_PRESENT)
    drm_dev_unref(dev);
#else
    drm_dev_free(dev);
#endif
}

#if defined(NV_DRM_ATOMIC_MODESET_AVAILABLE)

#include <drm/drm_atomic.h>

int nv_drm_atomic_set_mode_for_crtc(struct drm_crtc_state *state,
                                    struct drm_display_mode *mode);

void nv_drm_atomic_clean_old_fb(struct drm_device *dev,
                                unsigned plane_mask,
                                int ret);

#endif /* defined(NV_DRM_ATOMIC_MODESET_AVAILABLE) */

#endif /* defined(NV_DRM_AVAILABLE) */

#endif /* __NVIDIA_DRM_HELPER_H__ */
