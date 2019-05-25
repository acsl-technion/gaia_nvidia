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
#include "nvidia-drm-modeset.h"
#include "nvidia-drm-crtc.h"
#include "nvidia-drm-utils.h"
#include "nvidia-drm-fb.h"
#include "nvidia-drm-connector.h"
#include "nvidia-drm-encoder.h"
#include "nvidia-drm-os-interface.h"
#include "nvidia-drm-helper.h"

#include <drm/drm_atomic.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_crtc.h>

static inline void nv_drm_atomic_state_free(struct drm_atomic_state *state) {
#if defined(NV_DRM_ATOMIC_STATE_FREE)
    drm_atomic_state_free(state);
#else
    drm_atomic_state_put(state);
#endif
}

#if defined(NV_DRM_MODE_CONFIG_FUNCS_HAS_ATOMIC_STATE_ALLOC)
struct nvidia_drm_atomic_state {
    struct NvKmsKapiRequestedModeSetConfig config;
    struct drm_atomic_state base;
};

static inline struct nvidia_drm_atomic_state *to_nv_atomic_state(
    struct drm_atomic_state *state)
{
    return container_of(state, struct nvidia_drm_atomic_state, base);
}

struct drm_atomic_state *nvidia_drm_atomic_state_alloc(struct drm_device *dev)
{
    struct nvidia_drm_atomic_state *nv_state =
            nvidia_drm_calloc(1, sizeof(*nv_state));

    if (nv_state == NULL || drm_atomic_state_init(dev, &nv_state->base) < 0) {
        nvidia_drm_free(nv_state);
        return NULL;
    }

    return &nv_state->base;
}

void nvidia_drm_atomic_state_clear(struct drm_atomic_state *state)
{
    drm_atomic_state_default_clear(state);
}

void nvidia_drm_atomic_state_free(struct drm_atomic_state *state)
{
    struct nvidia_drm_atomic_state *nv_state =
                    to_nv_atomic_state(state);
    drm_atomic_state_default_release(state);
    nvidia_drm_free(nv_state);
}
#endif

/*
 * In kernel versions before the addition of
 * drm_crtc_state::connectors_changed, connector changes were
 * reflected in drm_crtc_state::mode_changed.
 */
static inline bool
nvidia_drm_crtc_state_connectors_changed(struct drm_crtc_state *crtc_state)
{
#if defined(NV_DRM_CRTC_STATE_HAS_CONNECTORS_CHANGED)
    return crtc_state->connectors_changed;
#else
    return crtc_state->mode_changed;
#endif
}

inline static bool
nvidia_drm_atomic_crtc_needs_modeset(struct drm_crtc_state *crtc_state)
{
    return nvidia_drm_crtc_state_connectors_changed(crtc_state) ||
           crtc_state->planes_changed ||
           crtc_state->mode_changed;
}

static int head_modeset_config_attach_connector(
    const struct drm_connector *connector,
    struct NvKmsKapiHeadModeSetConfig *head_modeset_config)
{
    struct nvidia_drm_connector *nv_connector =
            DRM_CONNECTOR_TO_NV_CONNECTOR(connector);
    struct nvidia_drm_encoder *nv_encoder = nv_connector->nv_detected_encoder;

    if (nv_encoder == NULL) {
        struct nvidia_drm_device *nv_dev = to_nv_drm_device(connector->dev);

        NV_DRM_DEV_LOG_DEBUG(
            nv_dev,
            "Connector(%u) has no connected encoder",
            nv_connector->physicalIndex);
        return -EINVAL;
    }

    head_modeset_config->displays[head_modeset_config->numDisplays++] =
        nv_encoder->hDisplay;

    return 0;
}

static int setup_plane_config(struct drm_plane_state *plane_state,
                              struct NvKmsKapiPlaneConfig *plane_config)
{
    struct nvidia_drm_framebuffer *nv_fb = NULL;

    if (plane_state->fb == NULL) {
        return 0;
    }

    nv_fb = DRM_FRAMEBUFFER_TO_NV_FRAMEBUFFER(plane_state->fb);

    if (nv_fb == NULL || nv_fb->pSurface == NULL) {
        struct nvidia_drm_device *nv_dev =
            to_nv_drm_device(plane_state->plane->dev);

        NV_DRM_DEV_LOG_DEBUG(
            nv_dev,
            "Invalid framebuffer object 0x%p",
            nv_fb);
        return -EINVAL;
    }

    plane_config->surface = nv_fb->pSurface;

    /* Source values are 16.16 fixed point */

    plane_config->srcX = plane_state->src_x >> 16;
    plane_config->srcY = plane_state->src_y >> 16;
    plane_config->srcWidth  = plane_state->src_w >> 16;
    plane_config->srcHeight = plane_state->src_h >> 16;

    plane_config->dstX = plane_state->crtc_x;
    plane_config->dstY = plane_state->crtc_y;
    plane_config->dstWidth  = plane_state->crtc_w;
    plane_config->dstHeight = plane_state->crtc_h;

    return 0;
}

static int setup_requested_head_modeset_config(
    struct drm_crtc *crtc,
    struct NvKmsKapiHeadRequestedConfig *head_requested_config)
{
    struct NvKmsKapiHeadModeSetConfig *head_modeset_config =
        &head_requested_config->modeSetConfig;
    struct drm_device *dev = crtc->dev;
    struct drm_connector *connector;
    struct drm_plane *plane;
    int ret = 0;

    list_for_each_entry(connector, &dev->mode_config.connector_list, head) {
        struct drm_connector_state *connector_state = connector->state;

        if (connector_state->crtc != crtc) {
            continue;
        }

        if ((ret = head_modeset_config_attach_connector(
                                        connector,
                                        head_modeset_config)) < 0) {
            goto done;
        }
    }

    if (head_modeset_config->numDisplays == 0) {
        goto done;
    }

    drm_mode_to_nvkms_display_mode(&crtc->state->mode,
                                   &head_modeset_config->mode);

    list_for_each_entry(plane, &dev->mode_config.plane_list, head) {
        struct drm_plane_state *plane_state = plane->state;
        NvKmsKapiPlaneType type;

        if (!drm_plane_type_to_nvkms_plane_type(plane->type, &type)) {
            struct nvidia_drm_device *nv_dev = to_nv_drm_device(dev);

            NV_DRM_DEV_LOG_DEBUG(
                nv_dev,
                "Unsupported drm plane type 0x%08x",
                plane->type);
            continue;
        }

        if (plane_state->crtc != crtc) {
            continue;
        }

        if ((ret = setup_plane_config(
              plane_state,
              &head_requested_config->planeRequestedConfig[type].config)) < 0) {
            goto done;
        }
    }

done:

    return ret;
}

static int drm_atomic_state_to_nvkms_requested_config(
    struct drm_atomic_state *state,
    struct NvKmsKapiRequestedModeSetConfig *requested_config)
{
    struct nvidia_drm_device *nv_dev = to_nv_drm_device(state->dev);

    struct drm_crtc *crtc;
    struct drm_crtc_state *crtc_state;

    struct drm_plane *plane;
    struct drm_plane_state *plane_state;

    int i, ret = 0;

    memset(requested_config, 0, sizeof(*requested_config));

    /*
     * Validate state object for modeset changes, this detect changes
     * happened in state.
     */

    ret = drm_atomic_helper_check(state->dev, state);

    if (ret != 0)
    {
        NV_DRM_DEV_LOG_DEBUG(
            nv_dev,
            "drm_atomic_helper_check_modeset() failed");
        return ret;
    }

    /* Loops over all crtcs and fill head configuration for changes */

    for_each_crtc_in_state(state, crtc, crtc_state, i)
    {
        struct nvidia_drm_crtc *nv_crtc;
        struct NvKmsKapiHeadRequestedConfig *head_requested_config;

        /* Is this crtc is enabled and has anything changed? */

        if (!nvidia_drm_atomic_crtc_needs_modeset(crtc_state))
        {
            continue;
        }

        nv_crtc = DRM_CRTC_TO_NV_CRTC(crtc);

        requested_config->headsMask |= 1 << nv_crtc->head;

        head_requested_config =
            &requested_config->headRequestedConfig[nv_crtc->head];

        /* Setup present configuration */

        if ((ret = setup_requested_head_modeset_config(
                                    crtc,
                                    head_requested_config)) < 0) {
            return ret;
        }

        /* Set mode-timing changes */

        if (crtc_state->mode_changed)
        {
            drm_mode_to_nvkms_display_mode(
                &crtc_state->mode,
                &head_requested_config->modeSetConfig.mode);

            head_requested_config->flags.modeChanged = NV_TRUE;
        }

        /* Set display changes */

        if (nvidia_drm_crtc_state_connectors_changed(crtc_state))
        {
            struct NvKmsKapiHeadModeSetConfig *head_modeset_config =
                &head_requested_config->modeSetConfig;

            struct drm_connector *connector;
            struct drm_connector_state *connector_state;

            int j;

            head_modeset_config->numDisplays = 0;

            memset(head_modeset_config->displays,
                   0,
                   sizeof(head_modeset_config->displays));

            head_requested_config->flags.displaysChanged = NV_TRUE;

            for_each_connector_in_state(state, connector, connector_state, j) {
                if (connector_state->crtc != crtc) {
                    continue;
                }

                if ((ret = head_modeset_config_attach_connector(
                                                connector,
                                                head_modeset_config)) < 0) {
                    return ret;
                }
            }

            crtc_state->active =
                (head_modeset_config->numDisplays != 0);
        }
    }

    /* Loops over all planes and fill plane configuration for changes */

    for_each_plane_in_state(state, plane, plane_state, i)
    {
        struct NvKmsKapiHeadRequestedConfig *head_requested_config;

        struct NvKmsKapiPlaneRequestedConfig *plane_requested_config;
        struct NvKmsKapiPlaneConfig *plane_config;

        struct NvKmsKapiPlaneConfig old_plane_config;
        NvKmsKapiPlaneType type;
        NvU32 head;

        bool disable = false;

        if (!drm_plane_type_to_nvkms_plane_type(plane->type, &type)) {
            NV_DRM_DEV_LOG_DEBUG(
                nv_dev,
                "Unsupported drm plane type 0x%08x",
                plane->type);
            continue;
        }

        if (plane_state->crtc == NULL)
        {
            /*
             * Happens when the plane is being disabled.  If the plane was
             * previously enabled, disable it.  Otherwise, ignore this
             * plane.
             */

            if (plane->state->crtc)
            {
                struct nvidia_drm_crtc *nv_crtc =
                    DRM_CRTC_TO_NV_CRTC(plane->state->crtc);

                head = nv_crtc->head;

                disable = true;
            }
            else
            {
                continue;
            }
        }
        else
        {
            struct nvidia_drm_crtc *nv_crtc =
                DRM_CRTC_TO_NV_CRTC(plane_state->crtc);

            head = nv_crtc->head;
        }

        BUG_ON((requested_config->headsMask & (1 << head)) == 0x0);

        head_requested_config = &requested_config->headRequestedConfig[head];

        plane_requested_config =
            &head_requested_config->planeRequestedConfig[type];

        plane_config = &plane_requested_config->config;

        /* Save old configuration */

        old_plane_config = *plane_config;

        /* Disable plane if there is no display attached to crtc */

        if (head_requested_config->modeSetConfig.numDisplays == 0 || disable) {
            plane_config->surface = NULL;
        }
        else if ((ret = setup_plane_config(plane_state, plane_config)) < 0) {
            return ret;
        }

        /*
         * If plane surface remains NULL then ignore all other changes
         * because there is nothing to show.
         */
        if (old_plane_config.surface == NULL &&
            old_plane_config.surface == plane_config->surface) {
            continue;
        }

        /*
         * Unconditionally mark the surface as changed, even if nothing
         * changed, so that we always get a flip event: a DRM client may
         * flip with the same surface and wait for a flip event.
         */
        plane_requested_config->flags.surfaceChanged = NV_TRUE;

        if (old_plane_config.surface == NULL &&
            old_plane_config.surface != plane_config->surface) {
            plane_requested_config->flags.srcXYChanged = NV_TRUE;
            plane_requested_config->flags.srcWHChanged = NV_TRUE;
            plane_requested_config->flags.dstXYChanged = NV_TRUE;
            plane_requested_config->flags.dstWHChanged = NV_TRUE;
            continue;
        }

        if (old_plane_config.srcX != plane_config->srcX ||
            old_plane_config.srcY != plane_config->srcY) {
            plane_requested_config->flags.srcXYChanged = NV_TRUE;
        }

        if (old_plane_config.srcWidth != plane_config->srcWidth ||
            old_plane_config.srcHeight != plane_config->srcHeight) {
            plane_requested_config->flags.srcWHChanged = NV_TRUE;
        }

        if (old_plane_config.dstX != plane_config->dstX ||
            old_plane_config.dstY != plane_config->dstY) {
            plane_requested_config->flags.dstXYChanged = NV_TRUE;
        }

        if (old_plane_config.dstWidth != plane_config->dstWidth ||
            old_plane_config.dstHeight != plane_config->dstHeight) {
            plane_requested_config->flags.dstWHChanged = NV_TRUE;
        }
    }

    return 0;
}

int nvidia_drm_atomic_check(struct drm_device *dev,
                            struct drm_atomic_state *state)
{
    struct nvidia_drm_device *nv_dev = to_nv_drm_device(dev);

    struct NvKmsKapiRequestedModeSetConfig *requested_config;

    int ret = 0;

#if defined(NV_DRM_MODE_CONFIG_FUNCS_HAS_ATOMIC_STATE_ALLOC)
    requested_config = &(to_nv_atomic_state(state)->config);
#else
    requested_config = nvidia_drm_calloc(1, sizeof(*requested_config));

    if (requested_config == NULL)
    {
        return -ENOMEM;
    }
#endif

    ret = drm_atomic_state_to_nvkms_requested_config(state, requested_config);

    if (ret != 0)
    {
        goto done;
    }

    if (!nvKms->applyModeSetConfig(nv_dev->pDevice,
                                   requested_config, NV_FALSE))
    {
        ret = -EINVAL;

        NV_DRM_DEV_LOG_DEBUG(
            nv_dev,
            "Failed to validate NvKmsKapiModeSetConfig");
    }

done:

#if !defined(NV_DRM_MODE_CONFIG_FUNCS_HAS_ATOMIC_STATE_ALLOC)
    nvidia_drm_free(requested_config);
#endif

    return ret;
}

#if defined(NV_DRM_ATOMIC_MODESET_NONBLOCKING_COMMIT_AVAILABLE)

void nvidia_drm_atomic_helper_commit_tail(struct drm_atomic_state *state)
{
    struct drm_device *dev = state->dev;
    struct nvidia_drm_device *nv_dev = to_nv_drm_device(dev);
    struct NvKmsKapiRequestedModeSetConfig *requested_config =
        &(to_nv_atomic_state(state)->config);

    int i;
    struct drm_crtc *crtc;
    struct drm_crtc_state *crtc_state;

    if (nvKms->systemInfo.bAllowWriteCombining) {
        /*
         * XXX This call is required only if dumb buffer is going
         * to be presented.
         */
         nvidia_drm_write_combine_flush();
    }

    if (!nvKms->applyModeSetConfig(nv_dev->pDevice,
                                   requested_config, NV_TRUE)) {
        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to commit NvKmsKapiModeSetConfig");
    }

    for_each_crtc_in_state(state, crtc, crtc_state, i) {
        struct nvidia_drm_crtc *nv_crtc = DRM_CRTC_TO_NV_CRTC(crtc);
        struct drm_crtc_commit *commit;

        spin_lock(&crtc->commit_lock);
        commit = list_first_entry_or_null(&crtc->commit_list,
                                          struct drm_crtc_commit, commit_entry);
        if (commit) {
            drm_crtc_commit_get(commit);
        }
        spin_unlock(&crtc->commit_lock);

        if (!commit) {
            continue;
        }

        if (wait_for_completion_timeout(&commit->flip_done, 3*HZ) == 0) {
            NV_DRM_DEV_LOG_ERR(
                nv_dev,
                "Flip event timeout on head %u", nv_crtc->head);
        }

        drm_crtc_commit_put(commit);
    }

    drm_atomic_helper_commit_hw_done(state);
}

#else

struct nvidia_drm_atomic_commit_task {
    struct drm_device *dev;
    struct drm_atomic_state *state;

#if !defined(NV_DRM_MODE_CONFIG_FUNCS_HAS_ATOMIC_STATE_ALLOC)
    struct NvKmsKapiRequestedModeSetConfig *requested_config;
#endif

    struct work_struct work;
};

static void nvidia_drm_atomic_commit_task_callback(struct work_struct *work)
{
    struct nvidia_drm_atomic_commit_task *nv_commit_task =
        container_of(work, struct nvidia_drm_atomic_commit_task, work);

    struct drm_device *dev = nv_commit_task->dev;
    struct drm_atomic_state *state = nv_commit_task->state;

    struct nvidia_drm_device *nv_dev = to_nv_drm_device(dev);

    struct NvKmsKapiRequestedModeSetConfig *requested_config =
    #if defined(NV_DRM_MODE_CONFIG_FUNCS_HAS_ATOMIC_STATE_ALLOC)
        &(to_nv_atomic_state(state)->config);
    #else
        nv_commit_task->requested_config;
    #endif

    int i;
    struct drm_crtc *crtc;
    struct drm_crtc_state *crtc_state;

    if (nvKms->systemInfo.bAllowWriteCombining) {
        /*
         * XXX This call is required only if dumb buffer is going
         * to be presented.
         */
         nvidia_drm_write_combine_flush();
    }

    if (!nvKms->applyModeSetConfig(nv_dev->pDevice,
                                   requested_config, NV_TRUE)) {
        NV_DRM_DEV_LOG_ERR(
            nv_dev,
            "Failed to commit NvKmsKapiModeSetConfig");
    }

    for_each_crtc_in_state(state, crtc, crtc_state, i) {
        struct nvidia_drm_crtc *nv_crtc = DRM_CRTC_TO_NV_CRTC(crtc);

        if (wait_event_timeout(
                nv_dev->pending_flip_queue,
                !atomic_read(&nv_crtc->has_pending_flip_event),
                3 * HZ /* 3 second */) == 0) {
            NV_DRM_DEV_LOG_ERR(
                nv_dev,
                "Flip event timeout on head %u", nv_crtc->head);
        }

        atomic_set(&nv_crtc->has_pending_commit, false);
        wake_up_all(&nv_dev->pending_commit_queue);
    }

    nv_drm_atomic_state_free(state);

#if !defined(NV_DRM_MODE_CONFIG_FUNCS_HAS_ATOMIC_STATE_ALLOC)
    nvidia_drm_free(requested_config);
#endif

    nvidia_drm_free(nv_commit_task);
}

static int nvidia_drm_atomic_commit_internal(
    struct drm_device *dev,
    struct drm_atomic_state *state,
    bool async)
{
    int ret = 0;

    int i;
    struct drm_crtc *crtc = NULL;
    struct drm_crtc_state *crtc_state = NULL;

    struct nvidia_drm_atomic_commit_task *nv_commit_task = NULL;

    struct NvKmsKapiRequestedModeSetConfig *requested_config = NULL;

    nv_commit_task = nvidia_drm_calloc(1, sizeof(*nv_commit_task));

    if (nv_commit_task == NULL) {
        ret = -ENOMEM;
        goto failed;
    }

#if defined(NV_DRM_MODE_CONFIG_FUNCS_HAS_ATOMIC_STATE_ALLOC)
    /*
     * Not required to convert convert drm_atomic_state to
     * NvKmsKapiRequestedModeSetConfig because it has been already
     * happened in nvidia_drm_atomic_check().
     *
     * Core DRM guarantees to call into nvidia_drm_atomic_check() before
     * calling into nvidia_drm_atomic_commit().
     */
    requested_config = &(to_nv_atomic_state(state)->config);
#else
    requested_config = nvidia_drm_calloc(1, sizeof(*requested_config));

    if (requested_config == NULL)
    {
        ret = -ENOMEM;
        goto failed;
    }

    ret = drm_atomic_state_to_nvkms_requested_config(state, requested_config);

    if (ret != 0)
    {
        NV_DRM_LOG_ERR("Failed to convert atomic state to NvKmsKapiModeSetConfig");
        goto failed;
    }
#endif

    /*
     * drm_mode_config_funcs::atomic_commit() mandates to return -EBUSY
     * for asynchronous commit if previous updates (commit tasks/flip event) are
     * pending. In case of synchronous commits it mandates to wait for previous
     * updates to complete.
     */
    if (!async) {
        /*
         * Serialize commits and flip events on crtc, in order to avoid race
         * condition between two/more nvKms->applyModeSetConfig() on single
         * crtc and generate flip events in correct order.
         */
        for_each_crtc_in_state(state, crtc, crtc_state, i) {
            struct nvidia_drm_device *nv_dev = to_nv_drm_device(dev);
            struct nvidia_drm_crtc *nv_crtc = DRM_CRTC_TO_NV_CRTC(crtc);

            if (wait_event_timeout(
                    nv_dev->pending_flip_queue,
                    !atomic_read(&nv_crtc->has_pending_flip_event),
                    3 * HZ /* 3 second */) == 0) {
                ret = -EBUSY;
                goto failed;
            }

            if (wait_event_timeout(
                    nv_dev->pending_commit_queue,
                    !atomic_read(&nv_crtc->has_pending_commit),
                    3 * HZ /* 3 second */) == 0) {
                ret = -EBUSY;
                goto failed;
            }
        }
    } else {
        for_each_crtc_in_state(state, crtc, crtc_state, i) {
            struct nvidia_drm_crtc *nv_crtc = DRM_CRTC_TO_NV_CRTC(crtc);

            if (atomic_read(&nv_crtc->has_pending_commit) ||
                atomic_read(&nv_crtc->has_pending_flip_event)) {
                ret = -EBUSY;
                goto failed;
            }
        }
    }

    /*
     * Mark all affected crtcs which will have pending commits and/or
     * flip events.
     */

    for_each_crtc_in_state(state, crtc, crtc_state, i) {
        struct nvidia_drm_crtc *nv_crtc = DRM_CRTC_TO_NV_CRTC(crtc);

        int j;
        struct drm_plane *plane;
        struct drm_plane_state *plane_state;

        atomic_set(&nv_crtc->has_pending_commit, true);

        if (!crtc->state->active && !crtc_state->active) {
            continue;
        }

        for_each_plane_in_state(state, plane, plane_state, j) {
            /*
             * Plane state is changing from active ---> disabled or
             * from disabled ---> active.
             */

            if (crtc == plane->state->crtc || crtc == plane_state->crtc) {
                switch (plane->type) {
                    case DRM_PLANE_TYPE_PRIMARY:
                        atomic_set(&nv_crtc->has_pending_flip_event, true);
                        break;
                    case DRM_PLANE_TYPE_OVERLAY:
                    case DRM_PLANE_TYPE_CURSOR:
                        /* TODO */
                        break;
                }
            }
        }
    }

    drm_atomic_helper_swap_state(dev, state);

    INIT_WORK(&nv_commit_task->work,
              nvidia_drm_atomic_commit_task_callback);

    nv_commit_task->dev = dev;
    nv_commit_task->state = state;
#if !defined(NV_DRM_MODE_CONFIG_FUNCS_HAS_ATOMIC_STATE_ALLOC)
    nv_commit_task->requested_config = requested_config;
#endif

    if (async)
    {
        schedule_work(&nv_commit_task->work);
    }
    else
    {
        nvidia_drm_atomic_commit_task_callback(&nv_commit_task->work);
    }

    return 0;

failed:

#if !defined(NV_DRM_MODE_CONFIG_FUNCS_HAS_ATOMIC_STATE_ALLOC)
    nvidia_drm_free(requested_config);
#endif

    nvidia_drm_free(nv_commit_task);

    return ret;
}

#endif /* NV_DRM_ATOMIC_MODESET_NONBLOCKING_COMMIT_AVAILABLE */

int nvidia_drm_atomic_commit(struct drm_device *dev,
                             struct drm_atomic_state *state, bool async)
{
#if defined(NV_DRM_ATOMIC_MODESET_NONBLOCKING_COMMIT_AVAILABLE)
    return drm_atomic_helper_commit(dev, state, async);
#else
    return nvidia_drm_atomic_commit_internal(dev, state, async);
#endif
}

void nvidia_drm_handle_flip_occurred(struct nvidia_drm_device *nv_dev,
                                     NvU32 head,
                                     NvKmsKapiPlaneType plane)
{
    BUG_ON(!mutex_is_locked(&nv_dev->lock));

    switch (plane)
    {
        case NVKMS_KAPI_PLANE_PRIMARY:
        {
            struct nvidia_drm_crtc *nv_crtc = nv_dev->nv_crtc[head];
            struct drm_crtc *crtc = &nv_crtc->base;

            struct drm_crtc_state *crtc_state = crtc->state;

            spin_lock(&nv_dev->dev->event_lock);
            if (crtc_state->event != NULL) {
                drm_crtc_send_vblank_event(crtc, crtc_state->event);
            }
            crtc_state->event = NULL;
            spin_unlock(&nv_dev->dev->event_lock);

#if !defined(NV_DRM_ATOMIC_MODESET_NONBLOCKING_COMMIT_AVAILABLE)
            WARN_ON(!atomic_read(&nv_crtc->has_pending_flip_event));
            atomic_set(&nv_crtc->has_pending_flip_event, false);
            wake_up_all(&nv_dev->pending_flip_queue);
#endif
            break;
        }

        case NVKMS_KAPI_PLANE_OVERLAY: /* TODO */
        case NVKMS_KAPI_PLANE_CURSOR:
        default:
            BUG_ON(1);
    }
}

int nvidia_drm_shut_down_all_crtcs(struct drm_device *dev)
{
    struct drm_atomic_state *state;

    struct drm_plane *plane;
    struct drm_connector *connector;
    struct drm_crtc *crtc;

    unsigned plane_mask;

    int ret = 0;

    state = drm_atomic_state_alloc(dev);

    if (state == NULL) {
        return -ENOMEM;
    }

    drm_modeset_lock_all(dev);

    state->acquire_ctx = dev->mode_config.acquire_ctx;

    plane_mask = 0;
    list_for_each_entry(plane, &dev->mode_config.plane_list, head) {
        struct drm_plane_state *plane_state =
            drm_atomic_get_plane_state(state, plane);

        if (IS_ERR(plane_state)) {
            ret = PTR_ERR(plane_state);
            goto done;
        }

        plane->old_fb = plane->fb;
        plane_mask |= 1 << drm_plane_index(plane);

        ret = drm_atomic_set_crtc_for_plane(plane_state, NULL);
        if (ret != 0) {
            goto done;
        }

        drm_atomic_set_fb_for_plane(plane_state, NULL);
    }

    list_for_each_entry(connector,
                        &dev->mode_config.connector_list, head) {
        struct drm_connector_state *connector_state =
            drm_atomic_get_connector_state(state, connector);

        if (IS_ERR(connector_state)) {
            ret = PTR_ERR(connector_state);
            goto done;
        }

        ret = drm_atomic_set_crtc_for_connector(connector_state, NULL);
        if (ret != 0) {
            goto done;
        }
    }

    list_for_each_entry(crtc, &dev->mode_config.crtc_list, head) {
        struct drm_crtc_state *crtc_state =
            drm_atomic_get_crtc_state(state, crtc);

        if (IS_ERR(crtc_state)) {
            ret = PTR_ERR(crtc_state);
            goto done;
        }

        ret = nv_drm_atomic_set_mode_for_crtc(crtc_state, NULL);
        if (ret != 0) {
            goto done;
        }
        crtc_state->active = false;
    }

    ret = drm_atomic_commit(state);

done:

    nv_drm_atomic_clean_old_fb(dev, plane_mask, ret);

    /*
     * If drm_atomic_commit() succeeds, it will free the state, and thus we
     * only need to free the state explicitly if we didn't successfully call
     * drm_atomic_commit().
     */
    if (ret != 0) {
        nv_drm_atomic_state_free(state);
    }

    drm_modeset_unlock_all(dev);

    return ret;
}

#endif
