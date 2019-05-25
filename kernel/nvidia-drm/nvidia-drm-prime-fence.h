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

#ifndef __NVIDIA_DRM_PRIME_FENCE_H__
#define __NVIDIA_DRM_PRIME_FENCE_H__

#include "nvidia-drm-conftest.h"

#if defined(NV_DRM_AVAILABLE)

#include "nvidia-drm-priv.h"
#include "nvidia-drm-gem.h"

#include "nv-misc.h"

#include <drm/drmP.h>

#if defined(NV_DRM_DRIVER_HAS_GEM_PRIME_RES_OBJ)

void nvidia_drm_gem_prime_fence_teardown
(
    struct nvidia_drm_device *nv_dev,
    struct nvidia_drm_gem_object *nv_gem
);

int nvidia_drm_gem_prime_fence_supported
(
    struct drm_device *dev,
    void *data,
    struct drm_file *file_priv
);

int nvidia_drm_gem_prime_fence_init
(
    struct drm_device *dev,
    void *data,
    struct drm_file *file_priv
);

int nvidia_drm_gem_prime_fence_attach
(
    struct drm_device *dev,
    void *data,
    struct drm_file *file_priv
);

int nvidia_drm_gem_prime_fence_force_signal
(
    struct drm_device *dev,
    void *data,
    struct drm_file *file_priv
);

int nvidia_drm_gem_prime_fence_fini
(
    struct drm_device *dev,
    void *data,
    struct drm_file *file_priv
);

#endif /* NV_DRM_DRIVER_HAS_GEM_PRIME_RES_OBJ */

#endif /* NV_DRM_AVAILABLE */

#endif /* __NVIDIA_DRM_PRIME_FENCE_H__ */
