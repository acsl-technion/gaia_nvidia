/*
 * Copyright (c) 2015-2016, NVIDIA CORPORATION.  All rights reserved.
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
 */

#ifndef _UAPI_NVIDIA_DRM_IOCTL_H_
#define _UAPI_NVIDIA_DRM_IOCTL_H_

#include <drm/drm.h>

#define DRM_NVIDIA_GEM_IMPORT_NVKMS_MEMORY          0x00
#define DRM_NVIDIA_GEM_IMPORT_USERSPACE_MEMORY      0x01
#define DRM_NVIDIA_GET_DEV_INFO                     0x02
#define DRM_NVIDIA_GEM_PRIME_FENCE_SUPPORTED        0x03
#define DRM_NVIDIA_GEM_PRIME_FENCE_INIT             0x04
#define DRM_NVIDIA_GEM_PRIME_FENCE_ATTACH           0x05
#define DRM_NVIDIA_GEM_PRIME_FENCE_FORCE_SIGNAL     0x06
#define DRM_NVIDIA_GEM_PRIME_FENCE_FINI             0x07
#define DRM_NVIDIA_GET_CLIENT_CAPABILITY            0x08

#define DRM_IOCTL_NVIDIA_GEM_IMPORT_NVKMS_MEMORY                           \
    DRM_IOWR((DRM_COMMAND_BASE + DRM_NVIDIA_GEM_IMPORT_NVKMS_MEMORY),      \
             struct drm_nvidia_gem_import_nvkms_memory_params)

#define DRM_IOCTL_NVIDIA_GEM_IMPORT_USERSPACE_MEMORY                       \
    DRM_IOWR((DRM_COMMAND_BASE + DRM_NVIDIA_GEM_IMPORT_USERSPACE_MEMORY),  \
             struct drm_nvidia_gem_import_userspace_memory_params)

#define DRM_IOCTL_NVIDIA_GET_DEV_INFO                                      \
    DRM_IOWR((DRM_COMMAND_BASE + DRM_NVIDIA_GET_DEV_INFO),                 \
             struct drm_nvidia_get_dev_info_params)

/*
 * XXX Solaris compiler has issues with DRM_IO. None of this is supported on
 * Solaris anyway, so just skip it.
 *
 * 'warning: suggest parentheses around arithmetic in operand of |'
 */
#if defined(NV_LINUX)
#define DRM_IOCTL_NVIDIA_GEM_PRIME_FENCE_SUPPORTED                         \
    DRM_IO(DRM_COMMAND_BASE + DRM_NVIDIA_GEM_PRIME_FENCE_SUPPORTED)
#else
#define DRM_IOCTL_NVIDIA_GEM_PRIME_FENCE_SUPPORTED 0
#endif

#define DRM_IOCTL_NVIDIA_GEM_PRIME_FENCE_INIT                              \
    DRM_IOW((DRM_COMMAND_BASE + DRM_NVIDIA_GEM_PRIME_FENCE_INIT),          \
            struct drm_nvidia_gem_prime_fence_init_params)

#define DRM_IOCTL_NVIDIA_GEM_PRIME_FENCE_ATTACH                            \
    DRM_IOW((DRM_COMMAND_BASE + DRM_NVIDIA_GEM_PRIME_FENCE_ATTACH),        \
            struct drm_nvidia_gem_prime_fence_attach_params)

#define DRM_IOCTL_NVIDIA_GEM_PRIME_FENCE_FORCE_SIGNAL                      \
    DRM_IOW((DRM_COMMAND_BASE + DRM_NVIDIA_GEM_PRIME_FENCE_FORCE_SIGNAL),  \
            struct drm_nvidia_gem_prime_fence_force_signal_params)

#define DRM_IOCTL_NVIDIA_GEM_PRIME_FENCE_FINI                              \
    DRM_IOW((DRM_COMMAND_BASE + DRM_NVIDIA_GEM_PRIME_FENCE_FINI),          \
            struct drm_nvidia_gem_prime_fence_fini_params)

#define DRM_IOCTL_NVIDIA_GET_CLIENT_CAPABILITY                             \
    DRM_IOWR((DRM_COMMAND_BASE + DRM_NVIDIA_GET_CLIENT_CAPABILITY),        \
             struct drm_nvidia_get_client_capability_params)

struct drm_nvidia_gem_import_nvkms_memory_params {
    uint64_t mem_size;           /* IN */

    uint64_t nvkms_params_ptr;   /* IN */
    uint64_t nvkms_params_size;  /* IN */

    uint32_t handle;             /* OUT */

    uint32_t __pad;
};

struct drm_nvidia_gem_import_userspace_memory_params {
    uint64_t size;               /* IN Size of memory in bytes */
    uint64_t address;            /* IN Virtual address of userspace memory */
    uint32_t handle;             /* OUT Handle to gem object */
};

struct drm_nvidia_get_dev_info_params {
    uint32_t gpu_id;             /* OUT */
    uint32_t primary_index;      /* OUT; the "card%d" value */
};

struct drm_nvidia_gem_prime_fence_init_params {
    uint32_t handle;            /* IN GEM handle to initialize */

    uint32_t index;             /* IN Index of semaphore to use for fencing */
    uint64_t size;              /* IN Size of semaphore surface in bytes */

    /* Params for importing userspace semaphore surface */
    uint64_t import_mem_nvkms_params_ptr;  /* IN */
    uint64_t import_mem_nvkms_params_size; /* IN */

    /* Params for creating software signaling event */
    uint64_t event_nvkms_params_ptr;  /* IN */
    uint64_t event_nvkms_params_size; /* IN */
};

struct drm_nvidia_gem_prime_fence_attach_params {
    uint32_t handle;        /* IN GEM handle to attach fence to */
    uint32_t sem_thresh;    /* IN Semaphore value to reach before signal */
};

struct drm_nvidia_gem_prime_fence_force_signal_params {
    uint32_t handle;        /* IN GEM handle to force signal */
};

struct drm_nvidia_gem_prime_fence_fini_params {
    uint32_t handle;    /* IN GEM handle to finalize */
};

struct drm_nvidia_get_client_capability_params {
    uint64_t capability;    /* IN Client capability enum */
    uint64_t value;         /* OUT Client capability value */
};

#endif /* _UAPI_NVIDIA_DRM_IOCTL_H_ */
