/*
 * Copyright (c) 2015-2016, NVIDIA CORPORATION. All rights reserved.
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

#include "nvidia-drm-conftest.h" /* NV_DRM_AVAILABLE and NV_DRM_DRM_GEM_H_PRESENT */

#include "nvidia-drm-priv.h"
#include "nvidia-drm-drv.h"
#include "nvidia-drm-fb.h"
#include "nvidia-drm-modeset.h"
#include "nvidia-drm-encoder.h"
#include "nvidia-drm-gem.h"
#include "nvidia-drm-crtc.h"
#include "nvidia-drm-prime-fence.h"
#include "nvidia-drm-helper.h"

#if defined(NV_DRM_AVAILABLE)

#include "nvidia-drm-ioctl.h"

#include <drm/drmP.h>

#include <drm/drm_crtc_helper.h>

#if defined(NV_DRM_DRM_GEM_H_PRESENT)
#include <drm/drm_gem.h>
#endif

#if defined(NV_DRM_DRM_AUTH_H_PRESENT)
#include <drm/drm_auth.h>
#endif

static struct nvidia_drm_device *dev_list = NULL;

#if defined(NV_DRM_ATOMIC_MODESET_AVAILABLE)

static void nvidia_drm_output_poll_changed(struct drm_device *dev)
{
    struct drm_connector *connector = NULL;

    mutex_lock(&dev->mode_config.mutex);

    list_for_each_entry(connector, &dev->mode_config.connector_list, head)
    {
        connector->funcs->fill_modes(
            connector,
            dev->mode_config.max_width, dev->mode_config.max_height);
    }

    mutex_unlock(&dev->mode_config.mutex);
}

static struct drm_framebuffer *nvidia_drm_framebuffer_create(
    struct drm_device *dev,
    struct drm_file *file,
    #if defined(NV_DRM_HELPER_MODE_FILL_FB_STRUCT_HAS_CONST_MODE_CMD_ARG)
    const struct drm_mode_fb_cmd2 *cmd
    #else
    struct drm_mode_fb_cmd2 *cmd
    #endif
)
{
    struct drm_mode_fb_cmd2 local_cmd;
    struct drm_framebuffer *fb;

    local_cmd = *cmd;

    fb = nvidia_drm_internal_framebuffer_create(
            dev,
            file,
            &local_cmd);

    #if !defined(NV_DRM_HELPER_MODE_FILL_FB_STRUCT_HAS_CONST_MODE_CMD_ARG)
    *cmd = local_cmd;
    #endif

    return fb;
}

static const struct drm_mode_config_funcs nv_mode_config_funcs = {
    .fb_create = nvidia_drm_framebuffer_create,

#if defined(NV_DRM_MODE_CONFIG_FUNCS_HAS_ATOMIC_STATE_ALLOC)
    .atomic_state_alloc = nvidia_drm_atomic_state_alloc,
    .atomic_state_clear = nvidia_drm_atomic_state_clear,
    .atomic_state_free  = nvidia_drm_atomic_state_free,
#endif
    .atomic_check  = nvidia_drm_atomic_check,
    .atomic_commit = nvidia_drm_atomic_commit,

    .output_poll_changed = nvidia_drm_output_poll_changed,
};

static void nvidia_drm_event_callback(const struct NvKmsKapiEvent *event)
{
    struct nvidia_drm_device *nv_dev = event->privateData;

    mutex_lock(&nv_dev->lock);

    if (!atomic_read(&nv_dev->enable_event_handling)) {
        goto done;
    }

    switch (event->type) {
        case NVKMS_EVENT_TYPE_DPY_CHANGED:
            nvidia_drm_handle_display_change(
                nv_dev,
                event->u.displayChanged.display);
            break;

        case NVKMS_EVENT_TYPE_DYNAMIC_DPY_CONNECTED:
            nvidia_drm_handle_dynamic_display_connected(
                nv_dev,
                event->u.dynamicDisplayConnected.display);
            break;
        case NVKMS_EVENT_TYPE_FLIP_OCCURRED:
            nvidia_drm_handle_flip_occurred(
                nv_dev,
                event->u.flipOccurred.head,
                event->u.flipOccurred.plane);
            break;
        default:
            break;
    }

done:

    mutex_unlock(&nv_dev->lock);
}

/*
 * Helper function to initialize drm_device::mode_config from
 * NvKmsKapiDevice's resource information.
 */
static void nvidia_drm_init_mode_config
(
    struct nvidia_drm_device *nv_dev,
    const struct NvKmsKapiDeviceResourcesInfo *pResInfo
)
{
#if defined(NV_DRM_ATOMIC_MODESET_NONBLOCKING_COMMIT_AVAILABLE)
    static struct drm_mode_config_helper_funcs nv_mode_config_helper = {
        .atomic_commit_tail = nvidia_drm_atomic_helper_commit_tail,
    };
#endif
    struct drm_device *dev = nv_dev->dev;

    drm_mode_config_init(dev);
    drm_mode_create_dvi_i_properties(dev);

    dev->mode_config.funcs = &nv_mode_config_funcs;

    dev->mode_config.min_width  = pResInfo->caps.minWidthInPixels;
    dev->mode_config.min_height = pResInfo->caps.minHeightInPixels;

    dev->mode_config.max_width  = pResInfo->caps.maxWidthInPixels;
    dev->mode_config.max_height = pResInfo->caps.maxHeightInPixels;

    dev->mode_config.cursor_width  = pResInfo->caps.maxCursorSizeInPixels;
    dev->mode_config.cursor_height = pResInfo->caps.maxCursorSizeInPixels;

    /*
     * NVIDIA GPUs have no preferred depth. Arbitrarily report 24, to be
     * consistent with other DRM drivers.
     */

    dev->mode_config.preferred_depth = 24;
    dev->mode_config.prefer_shadow = 1;

    /* Currently unused. Update when needed. */

    dev->mode_config.fb_base = 0;

    dev->mode_config.async_page_flip = true;

#if defined(NV_DRM_ATOMIC_MODESET_NONBLOCKING_COMMIT_AVAILABLE)
    dev->mode_config.helper_private = &nv_mode_config_helper;
#endif

    /* Initialize output polling support */

    drm_kms_helper_poll_init(dev);

    /* Disable output polling, because we don't support it yet */

    drm_kms_helper_poll_disable(dev);
}

/*
 * Helper function to enumerate crtcs from NvKmsKapiDevice's
 * resource information.
 */
static void nvidia_drm_enumerate_crtcs
(
    struct nvidia_drm_device *nv_dev,
    const struct NvKmsKapiDeviceResourcesInfo *pResInfo
)
{
    struct drm_device *dev = nv_dev->dev;
    unsigned int i;

    for (i = 0; i < pResInfo->numHeads; i++)
    {
        struct drm_crtc *crtc = NULL;

        crtc = nvidia_drm_add_crtc(dev, i);

        if (IS_ERR(crtc))
        {
            NV_DRM_DEV_LOG_ERR(
                nv_dev,
                "Failed to add DRM CRTC for head %u, error = %ld",
                i, PTR_ERR(crtc));
        }
    }
}

/*
 * Helper function to enumerate encoders/connectors from NvKmsKapiDevice.
 */
static void nvidia_drm_enumerate_encoders_and_connectors
(
    struct nvidia_drm_device *nv_dev
)
{
    struct drm_device *dev = nv_dev->dev;
    NvU32 nDisplays = 0;

    if (!nvKms->getDisplays(nv_dev->pDevice, &nDisplays, NULL))
    {
        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to enumurate NvKmsKapiDisplay count");
    }

    if (nDisplays != 0)
    {
        NvKmsKapiDisplay *hDisplays =
            nvidia_drm_calloc(nDisplays, sizeof(*hDisplays));

        if (hDisplays != NULL)
        {
            if (!nvKms->getDisplays(nv_dev->pDevice, &nDisplays, hDisplays))
            {
                NV_DRM_DEV_LOG_ERR(
                    nv_dev,
                    "Failed to enumurate NvKmsKapiDisplay handles");
            }
            else
            {
                NvU32 i;

                for (i = 0; i < nDisplays; i++)
                {
                    struct drm_encoder *encoder =
                        nvidia_drm_add_encoder(dev, hDisplays[i]);

                    if (IS_ERR(encoder))
                    {
                        NV_DRM_DEV_LOG_ERR(
                            nv_dev,
                            "Failed to add connector for NvKmsKapiDisplay 0x%08x",
                            hDisplays[i]);
                    }
                }
            }

            nvidia_drm_free(hDisplays);
        }
        else
        {
            NV_DRM_DEV_LOG_ERR(
                nv_dev,
                "Failed to allocate memory for NvKmsKapiDisplay array");
        }
    }
}

#endif /* NV_DRM_ATOMIC_MODESET_AVAILABLE */

static int nvidia_drm_load(struct drm_device *dev, unsigned long flags)
{
#if defined(NV_DRM_ATOMIC_MODESET_AVAILABLE)
    struct NvKmsKapiDevice *pDevice;

    struct NvKmsKapiAllocateDeviceParams allocateDeviceParams;
    struct NvKmsKapiDeviceResourcesInfo resInfo;
#endif

    struct nvidia_drm_device *nv_dev = to_nv_drm_device(dev);

    NV_DRM_DEV_LOG_INFO(nv_dev, "Loading driver");

#if defined(NV_DRM_ATOMIC_MODESET_AVAILABLE)

    if (!nvidia_drm_modeset_enabled(dev))
    {
        return 0;
    }

    /* Allocate NvKmsKapiDevice from GPU ID */

    memset(&allocateDeviceParams, 0, sizeof(allocateDeviceParams));

    allocateDeviceParams.gpuId = nv_dev->gpu_info.gpu_id;

    allocateDeviceParams.privateData = nv_dev;
    allocateDeviceParams.eventCallback = nvidia_drm_event_callback;

    pDevice = nvKms->allocateDevice(&allocateDeviceParams);

    if (pDevice == NULL) {
        NV_DRM_DEV_LOG_ERR(nv_dev, "Failed to allocate NvKmsKapiDevice");
        return -ENODEV;
    }

    /* Query information of resources available on device */

    if (!nvKms->getDeviceResourcesInfo(pDevice, &resInfo)) {

        nvKms->freeDevice(pDevice);

        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to query NvKmsKapiDevice resources info");
        return -ENODEV;
    }

    mutex_lock(&nv_dev->lock);

    /* Set NvKmsKapiDevice */

    nv_dev->pDevice = pDevice;

    nv_dev->pitchAlignment = resInfo.caps.pitchAlignment;

    /* Initialize drm_device::mode_config */

    nvidia_drm_init_mode_config(nv_dev, &resInfo);

    if (!nvKms->declareEventInterest(
            nv_dev->pDevice,
            ((1 << NVKMS_EVENT_TYPE_DPY_CHANGED) |
             (1 << NVKMS_EVENT_TYPE_DYNAMIC_DPY_CONNECTED) |
             (1 << NVKMS_EVENT_TYPE_FLIP_OCCURRED))))
    {
        NV_DRM_DEV_LOG_ERR(nv_dev, "Failed to register event mask");
    }

    /* Add crtcs */

    nvidia_drm_enumerate_crtcs(nv_dev, &resInfo);

    /* Add connectors and encoders */

    nvidia_drm_enumerate_encoders_and_connectors(nv_dev);

    drm_vblank_init(dev, dev->mode_config.num_crtc);

    /*
     * Trigger hot-plug processing, to update connection status of
     * all HPD supported connectors.
     */

    drm_helper_hpd_irq_event(dev);

    /* Enable event handling */

    atomic_set(&nv_dev->enable_event_handling, true);

#if !defined(NV_DRM_ATOMIC_MODESET_NONBLOCKING_COMMIT_AVAILABLE)
    init_waitqueue_head(&nv_dev->pending_commit_queue);
    init_waitqueue_head(&nv_dev->pending_flip_queue);
#endif

    mutex_unlock(&nv_dev->lock);

#endif /* NV_DRM_ATOMIC_MODESET_AVAILABLE */

    return 0;
}

static void __nv_drm_unload(struct drm_device *dev)
{
#if defined(NV_DRM_ATOMIC_MODESET_AVAILABLE)
    struct NvKmsKapiDevice *pDevice = NULL;
#endif

    struct nvidia_drm_device *nv_dev = to_nv_drm_device(dev);

    NV_DRM_DEV_LOG_INFO(nv_dev, "Unloading driver");

#if defined(NV_DRM_ATOMIC_MODESET_AVAILABLE)

    if (!nvidia_drm_modeset_enabled(dev))
    {
        return;
    }

    mutex_lock(&nv_dev->lock);

    /* Disable event handling */

    atomic_set(&nv_dev->enable_event_handling, false);

    /* Clean up output polling */

    drm_kms_helper_poll_fini(dev);

    /* Clean up mode configuration */

    drm_mode_config_cleanup(dev);

    if (!nvKms->declareEventInterest(nv_dev->pDevice, 0x0))
    {
        NV_DRM_DEV_LOG_ERR(nv_dev, "Failed to stop event listening");
    }

    /* Unset NvKmsKapiDevice */

    pDevice = nv_dev->pDevice;
    nv_dev->pDevice = NULL;

    mutex_unlock(&nv_dev->lock);

    nvKms->freeDevice(pDevice);

#endif /* NV_DRM_ATOMIC_MODESET_AVAILABLE */
}

#if defined(NV_DRM_DRIVER_UNLOAD_HAS_INT_RETURN_TYPE)
static int nvidia_drm_unload(struct drm_device *dev)
{
    __nv_drm_unload(dev);

    return 0;
}
#else
static void nvidia_drm_unload(struct drm_device *dev)
{
    __nv_drm_unload(dev);
}
#endif

#if defined(NV_DRM_ATOMIC_MODESET_AVAILABLE)

static int nvidia_drm_master_set(struct drm_device *dev,
                                 struct drm_file *file_priv, bool from_open)
{
    struct nvidia_drm_device *nv_dev = to_nv_drm_device(dev);

    if (!nvKms->grabOwnership(nv_dev->pDevice))
    {
        NV_DRM_DEV_LOG_DEBUG(
            nv_dev,
            "Failed to grab NVKMS ownership");
        return -EINVAL;
    }

    return 0;
}

#if defined(NV_DRM_MASTER_DROP_HAS_FROM_RELEASE_ARG)
static
void nvidia_drm_master_drop(struct drm_device *dev,
                            struct drm_file *file_priv, bool from_release)
#else
static
void nvidia_drm_master_drop(struct drm_device *dev, struct drm_file *file_priv)
#endif
{
    struct nvidia_drm_device *nv_dev = to_nv_drm_device(dev);
    int ret;

    ret = nvidia_drm_shut_down_all_crtcs(dev);
    if (ret != 0) {
        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "nvidia_drm_shut_down_all_crtcs() failed with error code %d.",
            ret);
    }

    nvKms->releaseOwnership(nv_dev->pDevice);
}
#endif /* NV_DRM_ATOMIC_MODESET_AVAILABLE */

static int nvidia_drm_pci_set_busid(struct drm_device *dev,
                                    struct drm_master *master)
{
    struct nvidia_drm_device *nv_dev = to_nv_drm_device(dev);

    master->unique = nvidia_drm_asprintf("pci:%04x:%02x:%02x.%d",
                                          nv_dev->gpu_info.pci_info.domain,
                                          nv_dev->gpu_info.pci_info.bus,
                                          nv_dev->gpu_info.pci_info.slot,
                                          nv_dev->gpu_info.pci_info.function);

    if (master->unique == NULL)
    {
        return -ENOMEM;
    }

    master->unique_len = strlen(master->unique);

    return 0;
}

static int nvidia_drm_get_dev_info(struct drm_device *dev,
                                   void *data,
                                   struct drm_file *file_priv)
{
    struct nvidia_drm_device *nv_dev = to_nv_drm_device(dev);
    struct drm_nvidia_get_dev_info_params *params = data;

    if (dev->primary == NULL)
    {
        return -ENOENT;
    }

    params->gpu_id = nv_dev->gpu_info.gpu_id;
    params->primary_index = dev->primary->index;

    return 0;
}

static int nvidia_drm_get_client_capability(struct drm_device *dev,
                                            void *data,
                                            struct drm_file *file_priv)
{
    struct drm_nvidia_get_client_capability_params *params = data;

    switch (params->capability)
    {
#if defined(DRM_CLIENT_CAP_STEREO_3D)
        case DRM_CLIENT_CAP_STEREO_3D:
            params->value = file_priv->stereo_allowed;
            break;
#endif
#if defined(DRM_CLIENT_CAP_UNIVERSAL_PLANES)
        case DRM_CLIENT_CAP_UNIVERSAL_PLANES:
            params->value = file_priv->universal_planes;
            break;
#endif
#if defined(DRM_CLIENT_CAP_ATOMIC)
        case DRM_CLIENT_CAP_ATOMIC:
            params->value = file_priv->atomic;
            break;
#endif
        default:
            return -EINVAL;
    }

    return 0;
}

#if defined(NV_DRM_BUS_PRESENT)

#if defined(NV_DRM_BUS_HAS_GET_IRQ)
static int nv_drm_bus_get_irq(struct drm_device *dev)
{
    return 0;
}
#endif

#if defined(NV_DRM_BUS_HAS_GET_NAME)
static const char *nv_drm_bus_get_name(struct drm_device *dev)
{
    return "nvidia-drm";
}
#endif

static struct drm_bus nv_drm_bus = {
#if defined(NV_DRM_BUS_HAS_BUS_TYPE)
    .bus_type     = DRIVER_BUS_PCI,
#endif
#if defined(NV_DRM_BUS_HAS_GET_IRQ)
    .get_irq      = nv_drm_bus_get_irq,
#endif
#if defined(NV_DRM_BUS_HAS_GET_NAME)
    .get_name     = nv_drm_bus_get_name,
#endif
    .set_busid    = nvidia_drm_pci_set_busid,
};

#endif /* NV_DRM_BUS_PRESENT */

static const struct file_operations nv_drm_fops = {
    .owner          = THIS_MODULE,

    .open           = drm_open,
    .release        = drm_release,
    .unlocked_ioctl = drm_ioctl,

#if defined(NV_DRM_ATOMIC_MODESET_AVAILABLE)
    .mmap           = drm_gem_mmap,
#endif

    .poll           = drm_poll,
    .read           = drm_read,

    .llseek         = noop_llseek,
};

static const struct drm_ioctl_desc nv_drm_ioctls[] = {
#if defined(NV_DRM_ATOMIC_MODESET_AVAILABLE)
    DRM_IOCTL_DEF_DRV(NVIDIA_GEM_IMPORT_NVKMS_MEMORY,
                      nvidia_drm_gem_import_nvkms_memory,
                      DRM_CONTROL_ALLOW|DRM_UNLOCKED),
#endif /* NV_DRM_ATOMIC_MODESET_AVAILABLE */

    DRM_IOCTL_DEF_DRV(NVIDIA_GEM_IMPORT_USERSPACE_MEMORY,
                      nvidia_drm_gem_import_userspace_memory,
                      DRM_CONTROL_ALLOW|DRM_RENDER_ALLOW|DRM_UNLOCKED),
    DRM_IOCTL_DEF_DRV(NVIDIA_GET_DEV_INFO,
                      nvidia_drm_get_dev_info,
                      DRM_CONTROL_ALLOW|DRM_RENDER_ALLOW|DRM_UNLOCKED),

#if defined(NV_DRM_DRIVER_HAS_GEM_PRIME_RES_OBJ)
    DRM_IOCTL_DEF_DRV(NVIDIA_GEM_PRIME_FENCE_SUPPORTED,
                      nvidia_drm_gem_prime_fence_supported,
                      DRM_CONTROL_ALLOW|DRM_RENDER_ALLOW|DRM_UNLOCKED),
    DRM_IOCTL_DEF_DRV(NVIDIA_GEM_PRIME_FENCE_INIT,
                      nvidia_drm_gem_prime_fence_init,
                      DRM_CONTROL_ALLOW|DRM_RENDER_ALLOW|DRM_UNLOCKED),
    DRM_IOCTL_DEF_DRV(NVIDIA_GEM_PRIME_FENCE_ATTACH,
                      nvidia_drm_gem_prime_fence_attach,
                      DRM_CONTROL_ALLOW|DRM_RENDER_ALLOW|DRM_UNLOCKED),
    DRM_IOCTL_DEF_DRV(NVIDIA_GEM_PRIME_FENCE_FORCE_SIGNAL,
                      nvidia_drm_gem_prime_fence_force_signal,
                      DRM_CONTROL_ALLOW|DRM_RENDER_ALLOW|DRM_UNLOCKED),
    DRM_IOCTL_DEF_DRV(NVIDIA_GEM_PRIME_FENCE_FINI,
                      nvidia_drm_gem_prime_fence_fini,
                      DRM_CONTROL_ALLOW|DRM_RENDER_ALLOW|DRM_UNLOCKED),
#endif

    DRM_IOCTL_DEF_DRV(NVIDIA_GET_CLIENT_CAPABILITY,
                      nvidia_drm_get_client_capability,
                      0),
};

static struct drm_driver nv_drm_driver = {

    .driver_features        = DRIVER_GEM | DRIVER_PRIME | DRIVER_RENDER,

    .gem_free_object        = nvidia_drm_gem_free,

    .ioctls                 = nv_drm_ioctls,
    .num_ioctls             = ARRAY_SIZE(nv_drm_ioctls),

    .prime_handle_to_fd     = drm_gem_prime_handle_to_fd,
    .gem_prime_export       = nvidia_drm_gem_prime_export,
    .gem_prime_get_sg_table = nvidia_drm_gem_prime_get_sg_table,
    .gem_prime_vmap         = nvidia_drm_gem_prime_vmap,
    .gem_prime_vunmap       = nvidia_drm_gem_prime_vunmap,

#if defined(NV_DRM_DRIVER_HAS_GEM_PRIME_RES_OBJ)
    .gem_prime_res_obj      = nvidia_drm_gem_prime_res_obj,
#endif

#if defined(NV_DRM_DRIVER_HAS_SET_BUSID)
    .set_busid              = nvidia_drm_pci_set_busid,
#endif

    .load                   = nvidia_drm_load,
    .unload                 = nvidia_drm_unload,

    .fops                   = &nv_drm_fops,

#if defined(NV_DRM_BUS_PRESENT)
    .bus                    = &nv_drm_bus,
#endif

    .name                   = "nvidia-drm",

    .desc                   = "NVIDIA DRM driver",
    .date                   = "20160202",

#if defined(NV_DRM_DRIVER_HAS_LEGACY_DEV_LIST)
    .legacy_dev_list        = LIST_HEAD_INIT(nv_drm_driver.legacy_dev_list),
#else
    .device_list            = LIST_HEAD_INIT(nv_drm_driver.device_list),
#endif
};


/*
 * Update the global nv_drm_driver for the intended features.
 *
 * It defaults to PRIME-only, but is upgraded to atomic modeset if the
 * kernel supports atomic modeset and the 'modeset' kernel module
 * parameter is true.
 */
static void nvidia_update_drm_driver_features(void)
{
#if defined(NV_DRM_ATOMIC_MODESET_AVAILABLE)

    if (!nvidia_drm_modeset_module_param) {
        return;
    }

    nv_drm_driver.driver_features |= DRIVER_MODESET | DRIVER_ATOMIC;

    nv_drm_driver.master_set       = nvidia_drm_master_set;
    nv_drm_driver.master_drop      = nvidia_drm_master_drop;

    nv_drm_driver.dumb_create      = nvidia_drm_dumb_create;
    nv_drm_driver.dumb_map_offset  = nvidia_drm_dumb_map_offset;
    nv_drm_driver.dumb_destroy     = drm_gem_dumb_destroy;

    nv_drm_driver.gem_vm_ops       = &nv_drm_gem_vma_ops;
#endif /* NV_DRM_ATOMIC_MODESET_AVAILABLE */
}



/*
 * Helper function for allocate/register DRM device for given NVIDIA GPU ID.
 */
static void nvidia_register_drm_device(const nv_gpu_info_t *gpu_info)
{
    struct nvidia_drm_device *nv_dev = NULL;
    struct drm_device *dev = NULL;
    struct pci_dev *pdev = gpu_info->os_dev_ptr;

    NV_DRM_LOG_DEBUG(
        "Registering device for NVIDIA GPU ID 0x08%x",
        gpu_info->gpu_id);

    /* Allocate NVIDIA-DRM device */

    nv_dev = nvidia_drm_calloc(1, sizeof(*nv_dev));

    if (nv_dev == NULL)
    {
        NV_DRM_LOG_ERR(
            "Failed to allocate memmory for NVIDIA-DRM device object");
        return;
    }

    nv_dev->gpu_info = *gpu_info;

#if defined(NV_DRM_ATOMIC_MODESET_AVAILABLE)
    mutex_init(&nv_dev->lock);
#endif

    /* Allocate DRM device */

    dev = drm_dev_alloc(&nv_drm_driver, &pdev->dev);

    if (dev == NULL)
    {
        NV_DRM_DEV_LOG_ERR(nv_dev, "Failed to allocate device");
        goto failed_drm_alloc;
    }

    dev->dev_private = nv_dev;
    nv_dev->dev = dev;
    dev->pdev = pdev;

    /* Register DRM device to DRM sub-system */

    if (drm_dev_register(dev, 0) != 0)
    {
        NV_DRM_DEV_LOG_ERR(nv_dev, "Failed to register device");
        goto failed_drm_register;
    }

    /* Add NVIDIA-DRM device into list */

    nv_dev->next = dev_list;
    dev_list = nv_dev;

    return; /* Success */

failed_drm_register:

    nv_drm_dev_free(dev);

failed_drm_alloc:

    nvidia_drm_free(nv_dev);
}

/*
 * Enumerate NVIDIA GPUs and allocate/register DRM device for each of them.
 */
int nvidia_drm_probe_devices(void)
{
    nv_gpu_info_t *gpu_info = NULL;
    NvU32 gpu_count = 0;
    NvU32 i;

    int ret = 0;

    nvidia_update_drm_driver_features();

    /* Enumerate NVIDIA GPUs */

    gpu_info = nvidia_drm_calloc(NV_MAX_GPUS, sizeof(*gpu_info));

    if (gpu_info == NULL) {
        ret = -ENOMEM;

        NV_DRM_LOG_ERR("Failed to allocate gpu ids arrays");
        goto done;
    }

    gpu_count = nvKms->enumerateGpus(gpu_info);

    if (gpu_count == 0)
    {
        NV_DRM_LOG_INFO("Not found NVIDIA GPUs");
        goto done;
    }

    WARN_ON(gpu_count > NV_MAX_GPUS);

    /* Register DRM device for each NVIDIA GPU */

    for (i = 0; i < gpu_count; i++)
    {
        nvidia_register_drm_device(&gpu_info[i]);
    }

done:

    nvidia_drm_free(gpu_info);

    return ret;
}

/*
 * Unregister all NVIDIA DRM devices.
 */
void nvidia_drm_remove_devices(void)
{
    while (dev_list != NULL)
    {
        struct nvidia_drm_device *next = dev_list->next;

        drm_dev_unregister(dev_list->dev);
        nv_drm_dev_free(dev_list->dev);

        nvidia_drm_free(dev_list);

        dev_list = next;
    }
}

#endif /* NV_DRM_AVAILABLE */
