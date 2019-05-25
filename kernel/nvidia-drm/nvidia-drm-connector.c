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
#include "nvidia-drm-connector.h"
#include "nvidia-drm-utils.h"
#include "nvidia-drm-encoder.h"

#include <drm/drm_crtc_helper.h>

#include <drm/drm_atomic.h>
#include <drm/drm_atomic_helper.h>

static void nvidia_connector_destroy(struct drm_connector *connector)
{
    struct drm_device *dev = connector->dev;
    struct nvidia_drm_device *nv_dev = to_nv_drm_device(dev);

    struct nvidia_drm_connector *nv_connector =
                DRM_CONNECTOR_TO_NV_CONNECTOR(connector);

    NV_DRM_DEV_LOG_DEBUG(
        nv_dev,
        "Destroying connector created from physical index %u",
        nv_connector->physicalIndex);

    /* Unregister connector */

    drm_connector_unregister(connector);

    /* Cleanup core connector object */

    drm_connector_cleanup(connector);

    /* Decrease reference count of edid */

    if (nv_connector->edid != NULL)
    {
        nvidia_drm_edid_unref(nv_connector->edid);
    }


    /* Free connector */

    nvidia_drm_free(nv_connector);
}

static enum drm_connector_status
nvidia_connector_detect(struct drm_connector *connector, bool force)
{
    struct drm_device *dev = connector->dev;

    struct nvidia_drm_device *nv_dev = to_nv_drm_device(dev);

    struct nvidia_drm_connector *nv_connector =
                    DRM_CONNECTOR_TO_NV_CONNECTOR(connector);

    enum drm_connector_status status = connector_status_disconnected;

    struct drm_encoder *detected_encoder = NULL;
    struct nvidia_drm_encoder *nv_detected_encoder = NULL;

    unsigned int i;

    BUG_ON(!mutex_is_locked(&dev->mode_config.mutex));

    if (nv_connector->edid != NULL)
    {
        drm_mode_connector_update_edid_property(connector, NULL);

        nvidia_drm_edid_unref(nv_connector->edid);
        nv_connector->edid = NULL;
    }

    for (i = 0; i < DRM_CONNECTOR_MAX_ENCODER; i++)
    {
        struct drm_encoder *encoder;
        struct nvidia_drm_encoder *nv_encoder;

        int id = connector->encoder_ids[i];

        if (id == 0)
        {
            break;
        }

        encoder = drm_encoder_find(dev, id);

        if (encoder == NULL)
        {
            BUG_ON(encoder != NULL);
            continue;
        }

        nv_encoder = DRM_ENCODER_TO_NV_ENCODER(encoder);

        if (nv_encoder->connected)
        {
            /* we only expect one connected encoder */

            BUG_ON(detected_encoder != NULL);

            detected_encoder = encoder;
        }
    }

    if (detected_encoder == NULL)
    {
        goto done;
    }

    nv_detected_encoder = DRM_ENCODER_TO_NV_ENCODER(detected_encoder);

    status = connector_status_connected;

    nv_connector->nv_detected_encoder = nv_detected_encoder;

    if (!connector->override_edid && nv_detected_encoder->edid != NULL)
    {
        nvidia_drm_edid_ref(nv_detected_encoder->edid);
        nv_connector->edid = nv_detected_encoder->edid;

        drm_mode_connector_update_edid_property(
            connector,
            (struct edid*) nv_connector->edid->buffer);
    }

    if (nv_connector->type == NVKMS_CONNECTOR_TYPE_DVI_I)
    {
        drm_object_property_set_value(
            &connector->base,
            dev->mode_config.dvi_i_subconnector_property,
            detected_encoder->encoder_type == DRM_MODE_ENCODER_DAC ?
                DRM_MODE_SUBCONNECTOR_DVID :
                DRM_MODE_SUBCONNECTOR_DVIA);
    }

done:

    nv_connector->connection_status = status;

    NV_DRM_DEV_LOG_DEBUG(
        nv_dev,
        "Detected Connector(%u) Status = %s",
        nv_connector->physicalIndex,
        (status == connector_status_connected) ? "connected" : "disconnected");

    return status;
}

static int nvidia_connector_fill_modes(struct drm_connector *connector,
                                       uint32_t max_width, uint32_t max_height)
{
    struct drm_device *dev = connector->dev;

    struct nvidia_drm_device *nv_dev = to_nv_drm_device(dev);

    struct nvidia_drm_connector *nv_connector =
                DRM_CONNECTOR_TO_NV_CONNECTOR(connector);

    struct nvidia_drm_encoder *nv_detected_encoder =
                               nv_connector->nv_detected_encoder;

    bool verbose_prune = true;

    NvU32 modeIndex = 0;
    int   count = 0;

    struct drm_display_mode *mode;

    /* Set all modes to the invalid state */

    list_for_each_entry(mode, &connector->modes, head)
    {
        /*
         * MODE_UNVERIFIED was renamed to MODE_STALE; avoid API churn
         * by using MODE_BAD instead.
         */
        mode->status = MODE_BAD;
    }

    if (connector->status == connector_status_disconnected ||
        nv_detected_encoder == NULL)
    {
        verbose_prune = false;
        goto prune;
    }

    modeIndex = 0;

    count = 0;

    while (1)
    {
        struct NvKmsKapiDisplayMode displayMode;
        NvBool valid = 0;
        int ret;

        struct drm_display_mode *mode = NULL;

        ret = nvKms->getDisplayMode(nv_dev->pDevice,
                                    nv_detected_encoder->hDisplay,
                                    modeIndex++, &displayMode, &valid);

        if (ret < 0)
        {
            NV_DRM_DEV_LOG_ERR(
                nv_dev,
                "Failed to get mode at modeIndex %d of NvKmsKapiDisplay 0x%08x",
                modeIndex, nv_detected_encoder->hDisplay);
            break;
        }

        /* Is end of mode-list */

        if (ret == 0)
        {
            break;
        }

        /* Ignore invalid modes */

        if (!valid)
        {
            continue;
        }

        mode = drm_mode_create(connector->dev);

        if (mode == NULL)
        {
            NV_DRM_DEV_LOG_ERR(
                nv_dev,
                "Failed to create mode for NvKmsKapiDisplay 0x%08x",
                nv_detected_encoder->hDisplay);
            continue;
        }

        nvkms_display_mode_to_drm_mode(&displayMode, mode);

        /* Add a mode to a connector's probed_mode list */

        drm_mode_probed_add(connector, mode);

        count++;
    }

    /* Moves the modes from the @connector probed_modes list */

    drm_mode_connector_list_update(connector
#if defined(NV_DRM_MODE_CONNECTOR_LIST_UPDATE_HAS_MERGE_TYPE_BITS_ARG)
                                   , true /* merge_type_bits */
#endif
                                   );

    /* Make sure modes adhere to size constraints */

    list_for_each_entry(mode, &connector->modes, head)
    {
        mode->status = drm_mode_validate_size(mode, max_width, max_height);
    }

prune:

    /* Remove invalid modes from mode list */

    drm_mode_prune_invalid(dev, &connector->modes, verbose_prune);

    if (list_empty(&connector->modes))
    {
        return 0;
    }

    drm_mode_sort(&connector->modes);

    return count;
}

static int nvidia_drm_atomic_helper_connector_dpms(
    struct drm_connector *connector,
    int mode)
{
    /* TODO */
    return -EPERM;
}

static struct drm_connector_funcs nv_connector_funcs = {
    .dpms                   = nvidia_drm_atomic_helper_connector_dpms,
    .destroy                = nvidia_connector_destroy,
    .reset                  = drm_atomic_helper_connector_reset,
    .detect                 = nvidia_connector_detect,
    .fill_modes             = nvidia_connector_fill_modes,
    .atomic_duplicate_state = drm_atomic_helper_connector_duplicate_state,
    .atomic_destroy_state   = drm_atomic_helper_connector_destroy_state,
};

static int nvidia_connector_get_modes(struct drm_connector *connector)
{
    return 0;
}

static int nvidia_connector_mode_valid(struct drm_connector    *connector,
                                       struct drm_display_mode *mode)
{
    return MODE_OK;
}

static struct drm_encoder*
nvidia_connector_best_encoder(struct drm_connector *connector)
{
    struct nvidia_drm_connector *nv_connector =
                DRM_CONNECTOR_TO_NV_CONNECTOR(connector);

    if (nv_connector->nv_detected_encoder != NULL)
    {
        return &nv_connector->nv_detected_encoder->base;
    }

    return NULL;
}

static const struct drm_connector_helper_funcs nv_connector_helper_funcs = {
    .get_modes    = nvidia_connector_get_modes,
    .mode_valid   = nvidia_connector_mode_valid,
    .best_encoder = nvidia_connector_best_encoder,
};

static struct drm_connector*
nvidia_connector_new(struct drm_device *dev,
                     NvU32 physicalIndex, NvKmsConnectorType type,
                     NvBool internal,
                     char dpAddress[NVKMS_DP_ADDRESS_STRING_LENGTH])
{
    struct nvidia_drm_device *nv_dev = to_nv_drm_device(dev);

    struct nvidia_drm_connector *nv_connector = NULL;
    struct drm_connector_state  *connector_state = NULL;

    int ret = 0;

    NV_DRM_DEV_LOG_DEBUG(
        nv_dev,
        "Creating connector from physical index %u",
        physicalIndex);

    /* Allocate memory for connector object */

    nv_connector = nvidia_drm_calloc(1, sizeof(*nv_connector));

    if (nv_connector == NULL)
    {
        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to allocate memory for connector object");
        return ERR_PTR(-ENOMEM);
    }

    nv_connector->physicalIndex = physicalIndex;

    nv_connector->type     = type;
    nv_connector->internal = internal;

    strcpy(nv_connector->dpAddress, dpAddress);

    nv_connector->connection_status = connector_status_unknown;

    nv_connector->changed = true;

    /* Allocate and set connector state */

    connector_state = nvidia_drm_calloc(1, sizeof(*connector_state));

    if (connector_state == NULL)
    {
        nvidia_drm_free(nv_connector);

        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to allocate memory for connector state");
        return ERR_PTR(-ENOMEM);
    }

    nv_connector->base.state   = connector_state;
    connector_state->connector = &nv_connector->base;

    /* Initialize connector */

    ret = drm_connector_init(
        dev,
        &nv_connector->base, &nv_connector_funcs,
        nvkms_connector_type_to_drm_connector_type(type, internal));

    if (ret != 0)
    {
        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to initialize connector created from physical index %u",
            nv_connector->physicalIndex);
        goto failed_connector_init;
    }

    drm_connector_helper_add(&nv_connector->base, &nv_connector_helper_funcs);

    nv_connector->base.polled = DRM_CONNECTOR_POLL_HPD;

    if (nv_connector->type == NVKMS_CONNECTOR_TYPE_VGA)
    {
        nv_connector->base.polled =
            DRM_CONNECTOR_POLL_CONNECT | DRM_CONNECTOR_POLL_DISCONNECT;
    }

    /* Register connector with DRM subsystem */

    ret = drm_connector_register(&nv_connector->base);

    if (ret != 0)
    {
        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to register connector created from physical index %u",
            nv_connector->physicalIndex);
        goto failed_connector_register;
    }

    return &nv_connector->base;

failed_connector_register:

    drm_connector_cleanup(&nv_connector->base);

failed_connector_init:

    nvidia_drm_free(connector_state);

    nvidia_drm_free(nv_connector);

    return ERR_PTR(ret);
}

/*
 * Get connector with given physical index one exists. Otherwise, create and
 * return a new connector.
 */
struct drm_connector*
nvidia_drm_get_connector(struct drm_device *dev,
                         NvU32 physicalIndex, NvKmsConnectorType type,
                         NvBool internal,
                         char dpAddress[NVKMS_DP_ADDRESS_STRING_LENGTH])
{
    struct drm_connector *connector = NULL;

    /* Lookup for existing connector with same physical index */

    list_for_each_entry(connector, &dev->mode_config.connector_list, head)
    {
        struct nvidia_drm_connector *nv_connector =
                        DRM_CONNECTOR_TO_NV_CONNECTOR(connector);

        if (nv_connector->physicalIndex == physicalIndex)
        {
            BUG_ON(nv_connector->type != type ||
                   nv_connector->internal != internal);

            if (strcmp(nv_connector->dpAddress, dpAddress) == 0)
            {
                return connector;
            }
        }
    }

    return nvidia_connector_new(dev, physicalIndex, type, internal, dpAddress);
}

#endif
