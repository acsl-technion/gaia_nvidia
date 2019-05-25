/*******************************************************************************
    Copyright (c) 2016, 2016 NVIDIA Corporation

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to
    deal in the Software without restriction, including without limitation the
    rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
    sell copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

        The above copyright notice and this permission notice shall be
        included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.

*******************************************************************************/

#include "uvm8_hmm.h"

// You have to opt in, in order to use HMM. Once "HMM bringup" is complete,
// this should be reversed, so that HMM is enabled by default. See below
// (uvm_hmm_is_enabled) for further details on enabling HMM.
static int uvm_hmm = 0;
module_param(uvm_hmm, int, S_IRUGO);
MODULE_PARM_DESC(uvm_hmm, "Enable (1) or disable (0) HMM mode. Default: 0. "
                          "Ignored if CONFIG_HMM is not set, or if NEXT settings conflict with HMM.");

#if UVM_IS_CONFIG_HMM()

#include "uvm8_gpu.h"
#include "uvm8_va_space.h"

// You need all of these things, in order to actually run HMM:
//
//     1) An HMM kernel, with CONFIG_HMM set.
//
//     2) UVM Kernel module parameter set: uvm_hmm=1

//
//     3) ATS must not be enabled

//
bool uvm_hmm_is_enabled(void)
{
    bool enabled = (uvm_hmm != 0);

    enabled = enabled && uvm8_ats_mode == 0;


    return enabled;
}


// If ATS support is enabled, then HMM will be disabled, even if HMM was
// specifically requested via uvm_hmm kernel module parameter. Detect that case
// and print a warning to the unsuspecting developer.

void uvm_hmm_init(void)
{

    if ((uvm_hmm != 0) && (uvm8_ats_mode != 0)) {
        UVM_ERR_PRINT("uvm_hmm=%d (HMM was requested), ATS mode is also enabled, which is incompatible with HMM, "
                      "so HMM remains disabled\n", uvm_hmm);
    }

}

static uvm_gpu_t * mirror_to_gpu(struct hmm_mirror *mirror)
{
    struct hmm_device *hmm_dev = mirror->device;
    uvm_gpu_t *gpu = container_of(hmm_dev, uvm_gpu_t, uvm_hmm_device);
    return gpu;
}

static void uvm_hmm_mirror_release(struct hmm_mirror *mirror)
{
    if (!uvm_hmm_is_enabled())
        return;

    // TODO: implement
}

static void uvm_hmm_mirror_free(struct hmm_mirror *mirror)
{
    if (!uvm_hmm_is_enabled())
        return;

    // TODO: implement
}

static int uvm_hmm_mirror_update(struct hmm_mirror *mirror,
                                 struct hmm_event *event)
{
    if (!uvm_hmm_is_enabled())
        return 0;

    // TODO: implement
    return 0;
}

static int uvm_hmm_copy_from_device(struct hmm_mirror *mirror,
                                    const struct hmm_event *event,
                                    dma_addr_t *dst,
                                    unsigned long start,
                                    unsigned long end)
{
    if (!uvm_hmm_is_enabled())
        return 0;

    // TODO: implement
    return 0;
}

static int uvm_hmm_copy_to_device(struct hmm_mirror *mirror,
                                  const struct hmm_event *event,
                                  struct vm_area_struct *vma,
                                  dma_addr_t *dst,
                                  unsigned long start,
                                  unsigned long end)
{
    if (!uvm_hmm_is_enabled())
        return 0;

    // TODO: implement
    return 0;
}

static const struct hmm_device_ops uvm_hmm_device_ops = {
        .release                = &uvm_hmm_mirror_release,
        .free                   = &uvm_hmm_mirror_free,
        .update                 = &uvm_hmm_mirror_update,
        .copy_from_device       = &uvm_hmm_copy_from_device,
        .copy_to_device         = &uvm_hmm_copy_to_device,
};

NV_STATUS uvm_hmm_device_register(uvm_gpu_t *gpu)
{
    int ret;

    if (!uvm_hmm_is_enabled())
        return NV_OK;

    gpu->uvm_hmm_device.ops = &uvm_hmm_device_ops;
    gpu->uvm_hmm_device.dev = NULL;

    ret = hmm_device_register(&gpu->uvm_hmm_device);

    // TODO: remove this print statement before production
    UVM_DBG_PRINT("HMM device: %d, GPU %s\n", ret, gpu->name);

    return errno_to_nv_status(ret);
}

void uvm_hmm_device_unregister(uvm_gpu_t *gpu)
{
    int ret;

    if (!uvm_hmm_is_enabled())
        return;

    ret = hmm_device_unregister(&gpu->uvm_hmm_device);

    // TODO: remove this print statement before production
    UVM_DBG_PRINT("HMM device: %d, GPU %s\n", ret, gpu->name);
    UVM_ASSERT(ret == 0);
}

NV_STATUS uvm_hmm_mirror_register(uvm_gpu_va_space_t *gpu_va_space)
{
    int ret;
    uvm_gpu_t *gpu = gpu_va_space->gpu;

    if (!uvm_hmm_is_enabled())
        return NV_OK;

    gpu_va_space->uvm_hmm_mirror.device = &gpu->uvm_hmm_device;

    ret = hmm_mirror_register(&gpu_va_space->uvm_hmm_mirror);

    // TODO: remove this print statement before production
    UVM_DBG_PRINT("HMM mirror: result: %d, mirror: 0x%p, GPU %s\n",
                  ret, &gpu_va_space->uvm_hmm_mirror, gpu->name);

    return errno_to_nv_status(ret);
}

void uvm_hmm_mirror_unregister(uvm_gpu_va_space_t *gpu_va_space)
{
    uvm_gpu_t *gpu = gpu_va_space->gpu;
    if (!uvm_hmm_is_enabled())
        return;

    hmm_mirror_unregister(&gpu_va_space->uvm_hmm_mirror);

    // TODO: remove this print statement before production
    UVM_DBG_PRINT("HMM mirror: 0x%p, GPU %s\n",
                  &gpu_va_space->uvm_hmm_mirror, gpu->name);
}

#endif // UVM_IS_CONFIG_HMM()
