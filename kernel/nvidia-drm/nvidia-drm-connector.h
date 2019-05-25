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

#ifndef __NVIDIA_DRM_CONNECTOR_H__
#define __NVIDIA_DRM_CONNECTOR_H__

#include "nvidia-drm-conftest.h"

#if defined(NV_DRM_ATOMIC_MODESET_AVAILABLE)

#include <drm/drmP.h>

#include "nvtypes.h"
#include "nvkms-api-types.h"

struct nvidia_drm_connector
{
    NvU32 physicalIndex;

    NvBool internal;
    NvKmsConnectorType type;

    char dpAddress[NVKMS_DP_ADDRESS_STRING_LENGTH];

    struct nvidia_drm_encoder *nv_detected_encoder;
    struct nvidia_drm_edid *edid;

    bool changed;
    enum drm_connector_status connection_status;

    struct drm_connector base;
};

#define DRM_CONNECTOR_TO_NV_CONNECTOR(__connector) \
    container_of(__connector, struct nvidia_drm_connector, base)

struct drm_connector*
nvidia_drm_get_connector(struct drm_device *dev,
                         NvU32 physicalIndex, NvKmsConnectorType type,
                         NvBool internal,
                         char dpAddress[NVKMS_DP_ADDRESS_STRING_LENGTH]);

#endif /* NV_DRM_ATOMIC_MODESET_AVAILABLE */

#endif /* __NVIDIA_DRM_CONNECTOR_H__ */
