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

#ifndef __NVIDIA_DRM_UTILS_H__
#define __NVIDIA_DRM_UTILS_H__

#include "nvidia-drm-conftest.h"

#if defined(NV_DRM_ATOMIC_MODESET_AVAILABLE)

#include <drm/drmP.h>
#include "nvkms-kapi.h"

struct NvKmsKapiDisplayInfo *nvkms_get_display_info
(
    struct NvKmsKapiDevice *pDevice,
    NvKmsKapiDisplay hDisplay, NvU8 *edidBuffer, NvU16 edidSize
);

struct NvKmsKapiConnectorInfo *nvkms_get_connector_info
(
    struct NvKmsKapiDevice *pDevice,
    NvKmsKapiConnector hConnector
);

int nvkms_connector_signal_to_drm_encoder_signal
(
    NvKmsConnectorSignalFormat format
);

int nvkms_connector_type_to_drm_connector_type
(
    NvKmsConnectorType type, NvBool internal
);

void nvkms_display_mode_to_drm_mode
(
    const struct NvKmsKapiDisplayMode *displayMode,
    struct drm_display_mode *mode
);

bool drm_format_to_nvkms_format(u32 format,
                                enum NvKmsSurfaceMemoryFormat *nvkms_format);

void drm_mode_to_nvkms_display_mode
(
    const struct drm_display_mode *src, struct NvKmsKapiDisplayMode *dst
);

bool drm_plane_type_to_nvkms_plane_type
(
    enum drm_plane_type src, NvKmsKapiPlaneType *type
);

struct nvidia_drm_edid
{
    NvU8  buffer[NVKMS_KAPI_EDID_BUFFER_SIZE];
    NvU16 size;

    NvU32 ref_count;
};

static inline struct nvidia_drm_edid *nvidia_drm_edid_alloc(void)
{
    struct nvidia_drm_edid *edid = nvidia_drm_calloc(1, sizeof(*edid));

    edid->ref_count = 1;

    return edid;
}

static inline void nvidia_drm_edid_ref(struct nvidia_drm_edid *edid)
{
    edid->ref_count++;
}

static inline void nvidia_drm_edid_unref(struct nvidia_drm_edid *edid)
{
    if (--edid->ref_count == 0)
    {
        nvidia_drm_free(edid);
    }
}

#endif /* NV_DRM_ATOMIC_MODESET_AVAILABLE */

#endif /* __NVIDIA_DRM_UTILS_H__ */
