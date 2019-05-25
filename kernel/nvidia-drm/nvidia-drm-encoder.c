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
#include "nvidia-drm-encoder.h"
#include "nvidia-drm-utils.h"
#include "nvidia-drm-connector.h"
#include "nvidia-drm-crtc.h"

#include <drm/drm_crtc_helper.h>

#include <drm/drm_atomic.h>
#include <drm/drm_atomic_helper.h>

static void nvidia_encoder_destroy(struct drm_encoder *encoder)
{
    struct drm_device *dev = encoder->dev;
    struct nvidia_drm_device *nv_dev = to_nv_drm_device(dev);

    struct nvidia_drm_encoder *nv_encoder = DRM_ENCODER_TO_NV_ENCODER(encoder);

    NV_DRM_DEV_LOG_DEBUG(
        nv_dev,
        "Destroying encoder created from NvKmsKapiDisplay 0x%08x",
        nv_encoder->hDisplay);

    /* Cleanup the core encoder object */

    drm_encoder_cleanup(encoder);

    /* Decrease reference count of edid */

    if (nv_encoder->edid != NULL)
    {
        nvidia_drm_edid_unref(nv_encoder->edid);
    }

    /* Free the encoder */

    nvidia_drm_free(nv_encoder);
}

static const struct drm_encoder_funcs nv_encoder_funcs = {
    .destroy = nvidia_encoder_destroy,
};

static bool nvidia_encoder_mode_fixup(struct drm_encoder *encoder,
                                      const struct drm_display_mode *mode,
                                      struct drm_display_mode *adjusted_mode)
{
    return true;
}

static void nvidia_encoder_prepare(struct drm_encoder *encoder)
{

}

static void nvidia_encoder_commit(struct drm_encoder *encoder)
{

}

static void nvidia_encoder_mode_set(struct drm_encoder *encoder,
                                    struct drm_display_mode *mode,
                                    struct drm_display_mode *adjusted_mode)
{

}

static const struct drm_encoder_helper_funcs nv_encoder_helper_funcs = {
    .mode_fixup = nvidia_encoder_mode_fixup,
    .prepare    = nvidia_encoder_prepare,
    .commit     = nvidia_encoder_commit,
    .mode_set   = nvidia_encoder_mode_set,
};

static uint32_t get_crtc_mask(struct drm_device *dev, uint32_t headMask)
{
    struct drm_crtc *crtc = NULL;
    uint32_t crtc_mask = 0x0;

    list_for_each_entry(crtc, &dev->mode_config.crtc_list, head)
    {
        struct nvidia_drm_crtc *nv_crtc = DRM_CRTC_TO_NV_CRTC(crtc);

        if (headMask & BIT(nv_crtc->head)) {
            crtc_mask |= drm_crtc_mask(crtc);
        }
    }

    return crtc_mask;
}

/*
 * Helper function to create new encoder for given NvKmsKapiDisplay
 * with given signal format.
 */
static struct drm_encoder*
nvidia_encoder_new(struct drm_device *dev,
                   NvKmsKapiDisplay hDisplay,
                   NvKmsConnectorSignalFormat format,
                   unsigned int crtc_mask)
{
    struct nvidia_drm_device *nv_dev = to_nv_drm_device(dev);

    struct nvidia_drm_encoder *nv_encoder = NULL;

    int ret = 0;

    /* Allocate an NVIDIA encoder object */

    nv_encoder = nvidia_drm_calloc(1, sizeof(*nv_encoder));

    if (nv_encoder == NULL)
    {
        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to allocate memory for NVIDIA-DRM encoder object");
        return ERR_PTR(-ENOMEM);
    }

    nv_encoder->hDisplay = hDisplay;

    /* Initialize the base encoder object and add it to the drm subsystem */

    ret = drm_encoder_init(dev,
                           &nv_encoder->base, &nv_encoder_funcs,
                           nvkms_connector_signal_to_drm_encoder_signal(format)
#if defined(NV_DRM_INIT_FUNCTIONS_HAVE_NAME_ARG)
                           , NULL
#endif
                           );

    if (ret != 0)
    {
        nvidia_drm_free(nv_encoder);

        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to initialize encoder created from NvKmsKapiDisplay 0x%08x",
            hDisplay);
        return ERR_PTR(ret);
    }

    nv_encoder->base.possible_crtcs = crtc_mask;

    drm_encoder_helper_add(&nv_encoder->base, &nv_encoder_helper_funcs);

    return &nv_encoder->base;
}

void nvidia_enocder_update_dynamic_information
(
    struct nvidia_drm_encoder *nv_encoder,
    const struct NvKmsKapiDisplayInfo *pDisplayInfo
)
{
    struct drm_encoder *encoder = &nv_encoder->base;

    struct drm_device *dev = encoder->dev;
    struct nvidia_drm_device *nv_dev = to_nv_drm_device(dev);

    BUG_ON(!mutex_is_locked(&dev->mode_config.mutex));

    BUG_ON(nv_encoder->hDisplay != pDisplayInfo->handle);

    if (nv_encoder->edid != NULL)
    {
        nvidia_drm_edid_unref(nv_encoder->edid);
    }

    nv_encoder->connected = pDisplayInfo->connected ? true : false;

    if (nv_encoder->connected && !pDisplayInfo->overrideEdid)
    {
        struct nvidia_drm_edid *edid = nvidia_drm_edid_alloc();

        if (edid != NULL)
        {
            memcpy(edid->buffer,
                   pDisplayInfo->edid.buffer,
                   pDisplayInfo->edid.bufferSize);

            edid->size = pDisplayInfo->edid.bufferSize;
        }
        else
        {
            NV_DRM_DEV_LOG_ERR(nv_dev, "Failed to allocate memory for edid");
        }

        nv_encoder->edid = edid;
    }
}

/*
 * Add encoder for given NvKmsKapiDisplay
 */
struct drm_encoder*
nvidia_drm_add_encoder(struct drm_device *dev, NvKmsKapiDisplay hDisplay)
{
    struct nvidia_drm_device *nv_dev = to_nv_drm_device(dev);

    struct NvKmsKapiDisplayInfo *displayInfo = NULL;
    struct NvKmsKapiConnectorInfo *connectorInfo = NULL;

    struct drm_encoder *encoder = NULL;
    struct nvidia_drm_encoder *nv_encoder = NULL;

    struct drm_connector *connector = NULL;

    int ret = 0;

    NV_DRM_DEV_LOG_DEBUG(
        nv_dev,
        "Creating encoder from NvKmsKapiDisplay 0x%08x", hDisplay);


    /* Query NvKmsKapiDisplayInfo and NvKmsKapiConnectorInfo */

    displayInfo = nvkms_get_display_info(nv_dev->pDevice, hDisplay, NULL, 0);

    if (IS_ERR(displayInfo))
    {
        ret = PTR_ERR(displayInfo);
        goto done;
    }

    connectorInfo = nvkms_get_connector_info(nv_dev->pDevice,
                                             displayInfo->connectorHandle);

    if (IS_ERR(connectorInfo))
    {
        ret = PTR_ERR(connectorInfo);
        goto done;
    }

    /* Create and add drm encoder */

    encoder = nvidia_encoder_new(dev,
                                 displayInfo->handle,
                                 connectorInfo->signalFormat,
                                 get_crtc_mask(dev, connectorInfo->headMask));

    if (IS_ERR(encoder)) {
        ret = PTR_ERR(encoder);
        goto done;
    }

    /* Get connector from repective physical index */

    connector =
        nvidia_drm_get_connector(dev,
                                 connectorInfo->physicalIndex,
                                 connectorInfo->type,
                                 displayInfo->internal, displayInfo->dpAddress);

    if (IS_ERR(connector)) {
        ret = PTR_ERR(connector);
        goto failed_connector_encoder_attach;
    }

    /* Attach encoder and connector */

    ret = drm_mode_connector_attach_encoder(connector, encoder);

    if (ret != 0)
    {
        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to attach encoder created from NvKmsKapiDisplay 0x%08x "
            "to connector",
            hDisplay);
        goto failed_connector_encoder_attach;
    }

    nv_encoder = DRM_ENCODER_TO_NV_ENCODER(encoder);

    mutex_lock(&dev->mode_config.mutex);

    nv_encoder->nv_connector = DRM_CONNECTOR_TO_NV_CONNECTOR(connector);

    nvidia_enocder_update_dynamic_information(nv_encoder, displayInfo);

    mutex_unlock(&dev->mode_config.mutex);

    goto done;

failed_connector_encoder_attach:

    drm_encoder_cleanup(encoder);

    nvidia_drm_free(encoder);

done:

    nvidia_drm_free(displayInfo);

    nvidia_drm_free(connectorInfo);

    return ret != 0 ? ERR_PTR(ret) : encoder;
}

static inline struct nvidia_drm_encoder *get_nv_encoder_from_nvkms_display
(
    struct drm_device *dev, NvKmsKapiDisplay hDisplay
)
{
    struct drm_encoder *encoder;

    list_for_each_entry(encoder, &dev->mode_config.encoder_list, head)
    {
        struct nvidia_drm_encoder *nv_encoder =
                    DRM_ENCODER_TO_NV_ENCODER(encoder);

        if (nv_encoder->hDisplay == hDisplay)
        {
            return nv_encoder;
        }
    }

    return NULL;
}

void nvidia_drm_handle_display_change
(
    struct nvidia_drm_device *nv_dev, NvKmsKapiDisplay hDisplay
)
{
    struct drm_device *dev = nv_dev->dev;

    struct nvidia_drm_encoder *nv_encoder = NULL;
    struct NvKmsKapiDisplayInfo *pDisplayInfo = NULL;

    bool changed = false;
    struct drm_connector *connector;
    enum drm_connector_status old_status;

    mutex_lock(&dev->mode_config.mutex);

    nv_encoder = get_nv_encoder_from_nvkms_display(dev, hDisplay);

    if (nv_encoder == NULL) {
        goto done;
    }

    connector = &nv_encoder->nv_connector->base;

    if (connector->override_edid)
    {
        pDisplayInfo =
            nvkms_get_display_info(nv_dev->pDevice,
                                   hDisplay,
                                   connector->edid_blob_ptr->data,
                                   connector->edid_blob_ptr->length);
    }
    else
    {
        pDisplayInfo =
            nvkms_get_display_info(nv_dev->pDevice, hDisplay, NULL, 0);
    }

    if (IS_ERR(pDisplayInfo))
    {
        goto done;
    }

    nvidia_enocder_update_dynamic_information(nv_encoder, pDisplayInfo);

    old_status = connector->status;

    connector->status = connector->funcs->detect(connector, false);

    if (old_status != connector->status) {
        changed = true;
    }

done:

    nvidia_drm_free(pDisplayInfo);

    mutex_unlock(&dev->mode_config.mutex);

    if (changed) {
        drm_kms_helper_hotplug_event(dev);
    }
}

void nvidia_drm_handle_dynamic_display_connected
(
    struct nvidia_drm_device *nv_dev, NvKmsKapiDisplay hDisplay
)
{
    struct drm_device *dev = nv_dev->dev;

    struct drm_encoder *encoder = NULL;
    struct nvidia_drm_encoder *nv_encoder = NULL;

    struct drm_connector *connector = NULL;

    /*
     * Look for an existing encoder with the same hDisplay and
     * use it if available.
     */

    nv_encoder = get_nv_encoder_from_nvkms_display(dev, hDisplay);

    if (nv_encoder != NULL) {
        NV_DRM_DEV_LOG_DEBUG(
            nv_dev,
            "Encoder with NvKmsKapiDisplay 0x%08x is already exist",
            hDisplay);
        return;
    }

    encoder = nvidia_drm_add_encoder(dev, hDisplay);

    if (IS_ERR(encoder)) {
        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to add encoder for NvKmsKapiDisplay 0x%08x",
            hDisplay);
        return;
    }

    /*
     * On some kernels, DRM has the notion of a "primary group" that
     * tracks the global mode setting state for the device.
     *
     * On kernels where DRM has a primary group, we need to reinitialize
     * after adding encoders and connectors.
     */
#if defined(NV_DRM_REINIT_PRIMARY_MODE_GROUP_PRESENT)
    drm_reinit_primary_mode_group(dev);
#endif

    nv_encoder = DRM_ENCODER_TO_NV_ENCODER(encoder);

    connector = &nv_encoder->nv_connector->base;

    mutex_lock(&dev->mode_config.mutex);

    connector->status = connector->funcs->detect(connector, false);

    mutex_unlock(&dev->mode_config.mutex);

    if (connector->status == connector_status_connected) {
        drm_kms_helper_hotplug_event(dev);
    }
}

#endif
