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

#ifndef __NVIDIA_DRM_MODESET_H__
#define __NVIDIA_DRM_MODESET_H__

#include "nvidia-drm-conftest.h"

#if defined(NV_DRM_ATOMIC_MODESET_AVAILABLE)

#include <drm/drmP.h>

#if defined(NV_DRM_MODE_CONFIG_FUNCS_HAS_ATOMIC_STATE_ALLOC)
struct drm_atomic_state *nvidia_drm_atomic_state_alloc(struct drm_device *dev);
void nvidia_drm_atomic_state_clear(struct drm_atomic_state *state);
void nvidia_drm_atomic_state_free(struct drm_atomic_state *state);
#endif

#if defined(NV_DRM_ATOMIC_MODESET_NONBLOCKING_COMMIT_AVAILABLE)
void nvidia_drm_atomic_helper_commit_tail(struct drm_atomic_state *state);
#endif

int nvidia_drm_atomic_check(struct drm_device *dev,
                            struct drm_atomic_state *state);

int nvidia_drm_atomic_commit(struct drm_device *dev,
                             struct drm_atomic_state *state, bool async);


void nvidia_drm_handle_flip_occurred(struct nvidia_drm_device *nv_dev,
                                     NvU32 head,
                                     NvKmsKapiPlaneType plane);

int nvidia_drm_shut_down_all_crtcs(struct drm_device *dev);

#endif /* NV_DRM_ATOMIC_MODESET_AVAILABLE */

#endif /* __NVIDIA_DRM_MODESET_H__ */
