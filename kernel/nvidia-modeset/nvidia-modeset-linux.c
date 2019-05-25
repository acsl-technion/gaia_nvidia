/* _NVRM_COPYRIGHT_BEGIN_
 *
 * Copyright 2015 by NVIDIA Corporation.  All rights reserved.  All
 * information contained herein is proprietary and confidential to NVIDIA
 * Corporation.  Any use, reproduction, or disclosure without the written
 * permission of NVIDIA Corporation is prohibited.
 *
 * _NVRM_COPYRIGHT_END_
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/workqueue.h>
#include <linux/vmalloc.h>
#include <asm/div64.h> /* do_div() */
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/random.h>
#include <linux/file.h>
#include <linux/list.h>

#include "nvstatus.h"

#include "nv-register-module.h"
#include "nv-modeset-interface.h"
#include "nv-kref.h"

#include "nvidia-modeset-os-interface.h"
#include "nvkms.h"
#include "nvkms-ioctl.h"

#include "conftest.h"
#include "nv-procfs.h"

#if defined(NVCPU_X86_64) && defined(CONFIG_IA32_EMULATION) && \
  !defined(NV_FILE_OPERATIONS_HAS_COMPAT_IOCTL)
#  define NV_NEEDS_COMPAT_IOCTL_REGISTRATION 1
#else
#  define NV_NEEDS_COMPAT_IOCTL_REGISTRATION 0
#endif


#if NV_NEEDS_COMPAT_IOCTL_REGISTRATION
#include <linux/syscalls.h> /* sys_ioctl() */
#include <linux/ioctl32.h> /* register_ioctl32_conversion() */
#endif

#define NVKMS_MAJOR_DEVICE_NUMBER 195
#define NVKMS_MINOR_DEVICE_NUMBER 254

#define NVKMS_LOG_PREFIX "nvidia-modeset: "

/*
 * Convert from microseconds to jiffies.  The conversion is:
 * ((usec) * HZ / 1000000)
 *
 * Use do_div() to avoid gcc-generated references to __udivdi3().
 * Note that the do_div() macro divides the first argument in place.
 */
static inline unsigned long NVKMS_USECS_TO_JIFFIES(NvU64 usec)
{
    unsigned long result = usec * HZ;
    do_div(result, 1000000);
    return result;
}


/*************************************************************************
 * NVKMS uses a global lock, nvkms_lock.  The lock is taken in the
 * file operation callback functions when calling into core NVKMS.
 *************************************************************************/

static struct semaphore nvkms_lock;


/*************************************************************************
 * The nvkms_per_open structure tracks data that is specific to a
 * single open.
 *************************************************************************/

struct nvkms_kapi_event_work {
    struct NvKmsKapiDevice *device;
    struct work_struct kernel_work;
};

struct nvkms_per_open {
    void *data;

    enum NvKmsClientType type;

    union {
        struct {
            struct {
                atomic_t available;
                wait_queue_head_t wait_queue;
            } events;
        } user;

        struct {
            struct {
                struct nvkms_kapi_event_work work;
            } events;
        } kernel;
    } u;
};


/*************************************************************************
 * nvidia-modeset-os-interface.h functions.  It is assumed that these
 * are called while nvkms_lock is held.
 *************************************************************************/

/* Don't use kmalloc for allocations larger than 128k */
#define KMALLOC_LIMIT (128 * 1024)

void* NVKMS_API_CALL nvkms_alloc(size_t size, NvBool zero)
{
    void *p;

    if (size <= KMALLOC_LIMIT) {
        p = kmalloc(size, GFP_KERNEL);
    } else {
        p = vmalloc(size);
    }

    if (zero && (p != NULL)) {
        memset(p, 0, size);
    }

    return p;
}

void NVKMS_API_CALL nvkms_free(void *ptr, size_t size)
{
    if (size <= KMALLOC_LIMIT) {
        kfree(ptr);
    } else {
        vfree(ptr);
    }
}

void* NVKMS_API_CALL nvkms_memset(void *ptr, NvU8 c, size_t size)
{
    return memset(ptr, c, size);
}

void* NVKMS_API_CALL nvkms_memcpy(void *dest, const void *src, size_t n)
{
    return memcpy(dest, src, n);
}

void* NVKMS_API_CALL nvkms_memmove(void *dest, const void *src, size_t n)
{
    return memmove(dest, src, n);
}

int NVKMS_API_CALL nvkms_memcmp(const void *s1, const void *s2, size_t n)
{
    return memcmp(s1, s2, n);
}

size_t NVKMS_API_CALL nvkms_strlen(const char *s)
{
    return strlen(s);
}

int NVKMS_API_CALL nvkms_strcmp(const char *s1, const char *s2)
{
    return strcmp(s1, s2);
}

char* NVKMS_API_CALL nvkms_strncpy(char *dest, const char *src, size_t n)
{
    return strncpy(dest, src, n);
}

void NVKMS_API_CALL nvkms_usleep(NvU64 usec)
{
    if (usec < 1000) {
        /*
         * If the period to wait is less than one millisecond, sleep
         * using udelay(); note this is a busy wait.
         */
        udelay(usec);
    } else {
        /*
         * Otherwise, sleep with millisecond precision.  Clamp the
         * time to ~4 seconds (0xFFF/1000 => 4.09 seconds).
         *
         * Note that the do_div() macro divides the first argument in
         * place.
         */

        int msec;
        NvU64 tmp = usec + 500;
        do_div(tmp, 1000);
        msec = (int) (tmp & 0xFFF);

        /*
         * XXX NVKMS TODO: this may need to be msleep_interruptible(),
         * though the callers would need to be made to handle
         * returning early.
         */
        msleep(msec);
    }
}

NvU64 NVKMS_API_CALL nvkms_get_usec(void)
{
    struct timeval tv;

    do_gettimeofday(&tv);

    return (((NvU64)tv.tv_sec) * 1000000) + tv.tv_usec;
}

int NVKMS_API_CALL nvkms_copyin(void *kptr, NvU64 uaddr, size_t n)
{
    if (!nvKmsNvU64AddressIsSafe(uaddr)) {
        return -EINVAL;
    }

    if (copy_from_user(kptr, nvKmsNvU64ToPointer(uaddr), n) != 0) {
        return -EFAULT;
    }

    return 0;
}

int NVKMS_API_CALL nvkms_copyout(NvU64 uaddr, const void *kptr, size_t n)
{
    if (!nvKmsNvU64AddressIsSafe(uaddr)) {
        return -EINVAL;
    }

    if (copy_to_user(nvKmsNvU64ToPointer(uaddr), kptr, n) != 0) {
        return -EFAULT;
    }

    return 0;
}

void NVKMS_API_CALL nvkms_yield(void)
{
    schedule();
}

int NVKMS_API_CALL nvkms_snprintf(char *str, size_t size, const char *format, ...)
{
    int ret;
    va_list ap;

    va_start(ap, format);
    ret = vsnprintf(str, size, format, ap);
    va_end(ap);

    return ret;
}

int NVKMS_API_CALL nvkms_vsnprintf(char *str, size_t size, const char *format, va_list ap)
{
    return vsnprintf(str, size, format, ap);
}

void NVKMS_API_CALL nvkms_log(const int level, const char *gpuPrefix, const char *msg)
{
    const char *levelString;
    const char *levelPrefix;

    switch (level) {
    default:
    case NVKMS_LOG_LEVEL_INFO:
        levelPrefix = "";
        levelString = KERN_INFO;
        break;
    case NVKMS_LOG_LEVEL_WARN:
        levelPrefix = "WARNING: ";
        levelString = KERN_WARNING;
        break;
    case NVKMS_LOG_LEVEL_ERROR:
        levelPrefix = "ERROR: ";
        levelString = KERN_ERR;
        break;
    }

    printk("%s%s%s%s%s\n",
           levelString, NVKMS_LOG_PREFIX, levelPrefix, gpuPrefix, msg);
}

void NVKMS_API_CALL
nvkms_event_queue_changed(nvkms_per_open_handle_t *pOpenKernel,
                          NvBool eventsAvailable)
{
    struct nvkms_per_open *popen = pOpenKernel;

    switch (popen->type) {
        case NVKMS_CLIENT_USER_SPACE:
            /*
             * Write popen->events.available atomically, to avoid any races or
             * memory barrier issues interacting with nvkms_poll().
             */
            atomic_set(&popen->u.user.events.available, eventsAvailable);

            wake_up_interruptible(&popen->u.user.events.wait_queue);

            break;
        case NVKMS_CLIENT_KERNEL_SPACE:
            if (eventsAvailable) {
                schedule_work(&popen->u.kernel.events.work.kernel_work);
            }

            break;
    }
}

static void nvkms_suspend(NvU32 gpuId)
{
    down(&nvkms_lock);
    nvKmsSuspend(gpuId);
    up(&nvkms_lock);
}

static void nvkms_resume(NvU32 gpuId)
{
    down(&nvkms_lock);
    nvKmsResume(gpuId);
    up(&nvkms_lock);
}


/*************************************************************************
 * Interface with resman.
 *************************************************************************/

static nvidia_modeset_rm_ops_t __rm_ops = { 0 };
static nvidia_modeset_callbacks_t nvkms_rm_callbacks = {
    nvkms_suspend,
    nvkms_resume
};

static int nvkms_alloc_rm(void)
{
    NV_STATUS nvstatus;
    int ret;

    __rm_ops.version_string = NV_VERSION_STRING;

    nvstatus = nvidia_get_rm_ops(&__rm_ops);

    if (nvstatus != NV_OK) {
        printk(KERN_ERR NVKMS_LOG_PREFIX "Version mismatch: "
               "nvidia.ko(%s) nvidia-modeset.ko(%s)\n",
               __rm_ops.version_string, NV_VERSION_STRING);
        return -EINVAL;
    }

    ret = __rm_ops.set_callbacks(&nvkms_rm_callbacks);
    if (ret < 0) {
        printk(KERN_ERR NVKMS_LOG_PREFIX "Failed to register callbacks\n");
        return ret;
    }

    return 0;
}

static void nvkms_free_rm(void)
{
    __rm_ops.set_callbacks(NULL);
}

void NVKMS_API_CALL nvkms_call_rm(void *ops)
{
    nvidia_modeset_stack_ptr stack = NULL;

    if (__rm_ops.alloc_stack(&stack) != 0) {
        return;
    }

    __rm_ops.op(stack, ops);

    __rm_ops.free_stack(stack);
}

/*************************************************************************
 * ref_ptr implementation.
 *************************************************************************/

struct nvkms_ref_ptr {
    nv_kref_t refcnt;
    // Access to ptr is guarded by the nvkms_lock.
    void *ptr;
};

struct nvkms_ref_ptr* NVKMS_API_CALL nvkms_alloc_ref_ptr(void *ptr)
{
    struct nvkms_ref_ptr *ref_ptr = nvkms_alloc(sizeof(*ref_ptr), NV_FALSE);
    if (ref_ptr) {
        // The ref_ptr owner counts as a reference on the ref_ptr itself.
        nv_kref_init(&ref_ptr->refcnt);
        ref_ptr->ptr = ptr;
    }
    return ref_ptr;
}

void NVKMS_API_CALL nvkms_free_ref_ptr(struct nvkms_ref_ptr *ref_ptr)
{
    if (ref_ptr) {
        ref_ptr->ptr = NULL;
        // Release the owner's reference of the ref_ptr.
        nvkms_dec_ref(ref_ptr);
    }
}

void NVKMS_API_CALL nvkms_inc_ref(struct nvkms_ref_ptr *ref_ptr)
{
    nv_kref_get(&ref_ptr->refcnt);
}

static void ref_ptr_free(nv_kref_t *ref)
{
    struct nvkms_ref_ptr *ref_ptr = container_of(ref, struct nvkms_ref_ptr,
                                                 refcnt);
    nvkms_free(ref_ptr, sizeof(*ref_ptr));
}

void* NVKMS_API_CALL nvkms_dec_ref(struct nvkms_ref_ptr *ref_ptr)
{
    void *ptr = ref_ptr->ptr;
    nv_kref_put(&ref_ptr->refcnt, ref_ptr_free);
    return ptr;
}

/*************************************************************************
 * Timer support
 *
 * Core NVKMS needs to be able to schedule work to execute in the
 * future, within process context.
 *
 * To achieve this, use struct timer_list to schedule a timer
 * callback, nvkms_timer_callback().  This will execute in softirq
 * context, so from there schedule a workqueue item,
 * nvkms_workqueue_callback(), which will execute in process context.
 *
 * This could be slightly simpler with schedule_delayed_work(), but
 * timer_list + work_struct have been more ABI-stable across Linux
 * kernel versions, and it is more consistent with the FreeBSD and
 * SunOS NVKMS kernel interface implementations.
 *
 * Note that the work_struct ABI has evolved slightly:
 *
 * - In older kernel versions, the workqueue callback function
 * receives a void argument, specified as a third argument to
 * INIT_WORK().
 *
 * - In more recent kernels, the workqueue callback function receives
 * the work_struct pointer as its argument, and INIT_WORK() only takes
 * two arguments.
 *
 * For simplicity, always pass the work_struct to the workqueue
 * callback function.  I.e., when INIT_WORK() takes three arguments,
 * pass the work_struct as the 'data' argument.
 *************************************************************************/

#if (NV_INIT_WORK_ARGUMENT_COUNT == 2)
  #define NVKMS_INIT_WORK(_work_struct, _proc) \
    INIT_WORK(_work_struct, _proc)
  #define NVKMS_WORK_FUNC_ARG_T struct work_struct
#elif (NV_INIT_WORK_ARGUMENT_COUNT == 3)
  #define NVKMS_INIT_WORK(_work_struct, _proc) \
    INIT_WORK(_work_struct, _proc, _work_struct)
  #define NVKMS_WORK_FUNC_ARG_T void
#else
  #error "NV_INIT_WORK_ARGUMENT_COUNT value unrecognized!"
#endif

struct nvkms_timer_t {
    struct work_struct kernel_work;
    struct timer_list kernel_timer;
    NvBool cancel;
    NvBool complete;
    NvBool isRefPtr;
    NvBool kernel_timer_created;
    nvkms_timer_proc_t *proc;
    void *dataPtr;
    NvU32 dataU32;
    struct list_head timers_list;
};

/*
 * Global list with pending timers, any change requires acquiring lock
 */
static struct {
    spinlock_t lock;
    struct list_head list;
} nvkms_timers;

static void nvkms_workqueue_callback(NVKMS_WORK_FUNC_ARG_T *arg)
{
    struct nvkms_timer_t *timer =
        container_of(arg, struct nvkms_timer_t, kernel_work);
    void *dataPtr;

    /*
     * We can delete this timer from pending timers list - it's being
     * processed now.
     */
    spin_lock_bh(&nvkms_timers.lock);
    list_del(&timer->timers_list);
    spin_unlock_bh(&nvkms_timers.lock);

    /*
     * After workqueue_callback we want to be sure that timer_callback
     * for this timer also have finished. It's important during module
     * unload - this way we can safely unload this module by first deleting
     * pending timers and than waiting for workqueue callbacks.
     */
    if (timer->kernel_timer_created) {
        del_timer_sync(&timer->kernel_timer);
    }

    down(&nvkms_lock);

    if (timer->isRefPtr) {
        // If the object this timer refers to was destroyed, treat the timer as
        // canceled.
        dataPtr = nvkms_dec_ref(timer->dataPtr);
        if (!dataPtr) {
            timer->cancel = NV_TRUE;
        }
    } else {
        dataPtr = timer->dataPtr;
    }

    if (!timer->cancel) {
        timer->proc(dataPtr, timer->dataU32);
        timer->complete = NV_TRUE;
    }

    if (timer->isRefPtr) {
        // ref_ptr-based timers are allocated with kmalloc(GFP_ATOMIC).
        kfree(timer);
    } else if (timer->cancel) {
        nvkms_free(timer, sizeof(*timer));
    }

    up(&nvkms_lock);
}

static void nvkms_timer_callback(unsigned long arg)
{
    struct nvkms_timer_t *timer = (struct nvkms_timer_t *) arg;

    /* In softirq context, so schedule nvkms_workqueue_callback(). */
    schedule_work(&timer->kernel_work);
}

static void
nvkms_init_timer(struct nvkms_timer_t *timer, nvkms_timer_proc_t *proc,
                 void *dataPtr, NvU32 dataU32, NvBool isRefPtr, NvU64 usec)
{
    unsigned long flags = 0;

    memset(timer, 0, sizeof(*timer));
    timer->cancel = NV_FALSE;
    timer->complete = NV_FALSE;
    timer->isRefPtr = isRefPtr;

    timer->proc = proc;
    timer->dataPtr = dataPtr;
    timer->dataU32 = dataU32;

    NVKMS_INIT_WORK(&timer->kernel_work, nvkms_workqueue_callback);

    /*
     * After adding timer to timers_list we need to finish referencing it
     * (calling schedule_work() or mod_timer()) before releasing the lock.
     * Otherwise, if the code to free the timer were ever updated to
     * run in parallel with this, it could race against nvkms_init_timer()
     * and free the timer before its initialization is complete.
     */
    spin_lock_irqsave(&nvkms_timers.lock, flags);
    list_add(&timer->timers_list, &nvkms_timers.list);

    if (usec == 0) {
        timer->kernel_timer_created = NV_FALSE;
        schedule_work(&timer->kernel_work);
    } else {
        init_timer(&timer->kernel_timer);
        timer->kernel_timer_created = NV_TRUE;
        timer->kernel_timer.function = nvkms_timer_callback;
        timer->kernel_timer.data = (unsigned long) timer;
        mod_timer(&timer->kernel_timer, jiffies + NVKMS_USECS_TO_JIFFIES(usec));
    }
    spin_unlock_irqrestore(&nvkms_timers.lock, flags);
}

nvkms_timer_handle_t*
NVKMS_API_CALL nvkms_alloc_timer(nvkms_timer_proc_t *proc,
                                 void *dataPtr, NvU32 dataU32,
                                 NvU64 usec)
{
    // nvkms_alloc_timer cannot be called from an interrupt context.
    struct nvkms_timer_t *timer = nvkms_alloc(sizeof(*timer), NV_FALSE);
    if (timer) {
        nvkms_init_timer(timer, proc, dataPtr, dataU32, NV_FALSE, usec);
    }
    return timer;
}

NvBool NVKMS_API_CALL
nvkms_alloc_timer_with_ref_ptr(nvkms_timer_proc_t *proc,
                               struct nvkms_ref_ptr *ref_ptr,
                               NvU32 dataU32, NvU64 usec)
{
    // nvkms_alloc_timer_with_ref_ptr is called from an interrupt bottom half
    // handler, which runs in a tasklet (i.e. atomic) context.
    struct nvkms_timer_t *timer = kmalloc(sizeof(*timer), GFP_ATOMIC);
    if (timer) {
        // Reference the ref_ptr to make sure that it doesn't get freed before
        // the timer fires.
        nvkms_inc_ref(ref_ptr);
        nvkms_init_timer(timer, proc, ref_ptr, dataU32, NV_TRUE, usec);
    }

    return timer != NULL;
}

void NVKMS_API_CALL nvkms_free_timer(nvkms_timer_handle_t *handle)
{
    struct nvkms_timer_t *timer = handle;

    if (timer == NULL) {
        return;
    }

    if (timer->complete) {
        nvkms_free(timer, sizeof(*timer));
        return;
    }

    timer->cancel = NV_TRUE;
}

void NVKMS_API_CALL nvkms_get_random(void *ptr, size_t size)
{
    get_random_bytes(ptr, size);
}

void* NVKMS_API_CALL nvkms_get_per_open_data(int fd)
{
    struct file *filp = fget(fd);
    struct nvkms_per_open *popen = NULL;
    dev_t rdev = 0;
    void *data = NULL;

    if (filp == NULL) {
        return NULL;
    }

#if defined(NV_FILE_HAS_INODE)
    if (filp->f_inode == NULL) {
        goto done;
    }
    rdev = filp->f_inode->i_rdev;
#else
    if ((filp->f_dentry == NULL) ||
        (filp->f_dentry->d_inode == NULL)) {
        goto done;
    }
    rdev = filp->f_dentry->d_inode->i_rdev;
#endif

    if ((MAJOR(rdev) != NVKMS_MAJOR_DEVICE_NUMBER) ||
        (MINOR(rdev) != NVKMS_MINOR_DEVICE_NUMBER)) {
        goto done;
    }

    popen = filp->private_data;
    if (popen == NULL) {
        goto done;
    }

    data = popen->data;

done:
    /*
     * fget() incremented the struct file's reference count, which
     * needs to be balanced with a call to fput().  It is safe to
     * decrement the reference count before returning
     * filp->private_data because core NVKMS is currently holding the
     * nvkms_lock, which prevents the nvkms_close() => nvKmsClose()
     * call chain from freeing the file out from under the caller of
     * nvkms_get_per_open_data().
     */
    fput(filp);

    return data;
}

NvBool NVKMS_API_CALL nvkms_open_gpu(NvU32 gpuId)
{
    nvidia_modeset_stack_ptr stack = NULL;
    NvBool ret;

    if (__rm_ops.alloc_stack(&stack) != 0) {
        return NV_FALSE;
    }

    ret = __rm_ops.open_gpu(gpuId, stack) == 0;

    __rm_ops.free_stack(stack);

    return ret;
}

void NVKMS_API_CALL nvkms_close_gpu(NvU32 gpuId)
{
    nvidia_modeset_stack_ptr stack = NULL;

    if (__rm_ops.alloc_stack(&stack) != 0) {
        return;
    }

    __rm_ops.close_gpu(gpuId, stack);

    __rm_ops.free_stack(stack);
}

NvU32 NVKMS_API_CALL nvkms_enumerate_gpus(nv_gpu_info_t *gpu_info)
{
    return __rm_ops.enumerate_gpus(gpu_info);
}

NvBool NVKMS_API_CALL nvkms_allow_write_combining(void)
{
    return __rm_ops.system_info.allow_write_combining;
}

/*************************************************************************
 * Common to both user-space and kapi NVKMS interfaces
 *************************************************************************/

static void nvkms_kapi_event_work_queue_callback(NVKMS_WORK_FUNC_ARG_T *arg)
{
    struct nvkms_kapi_event_work *work =
        container_of(arg, struct nvkms_kapi_event_work, kernel_work);

    nvKmsKapiHandleEventQueueChange(work->device);
}

struct nvkms_per_open *nvkms_open_common(enum NvKmsClientType type,
                                         struct NvKmsKapiDevice *device,
                                         int *status)
{
    struct nvkms_per_open *popen = NULL;

    popen = nvkms_alloc(sizeof(*popen), NV_TRUE);

    if (popen == NULL) {
        *status = -ENOMEM;
        goto failed;
    }

    popen->type = type;

    *status = down_interruptible(&nvkms_lock);

    if (*status != 0) {
        goto failed;
    }

    popen->data = nvKmsOpen(popen);

    up(&nvkms_lock);

    if (popen->data == NULL) {
        *status = -EPERM;
        goto failed;
    }

    switch (popen->type) {
        case NVKMS_CLIENT_USER_SPACE:
            init_waitqueue_head(&popen->u.user.events.wait_queue);
            break;
        case NVKMS_CLIENT_KERNEL_SPACE:
            popen->u.kernel.events.work.device = device;

            NVKMS_INIT_WORK(&popen->u.kernel.events.work.kernel_work,
                            nvkms_kapi_event_work_queue_callback);
            break;
    }

    *status = 0;

    return popen;

failed:

    nvkms_free(popen, sizeof(*popen));

    return NULL;
}

void NVKMS_API_CALL nvkms_close_common(struct nvkms_per_open *popen)
{
    /*
     * Don't use down_interruptible(): we need to free resources
     * during close, so we have no choice but to wait to take the
     * mutex.
     */

    down(&nvkms_lock);

    nvKmsClose(popen->data);

    popen->data = NULL;

    up(&nvkms_lock);

    if (popen->type == NVKMS_CLIENT_KERNEL_SPACE) {
        /*
         * Flush any outstanding nvkms_kapi_event_work_queue_callback()
         * work items before freeing popen.
         *
         * Note that this must be done after the above nvKmsClose() call,
         * to guarantee that no more nvkms_kapi_event_work_queue_callback()
         * work items get scheduled.
         *
         * Also, note that though popen->data is freed above, any subsequent
         * nvkms_kapi_event_work_queue_callback()'s for this popen should be
         * safe: if any nvkms_kapi_event_work_queue_callback()-initiated work
         * attempts to call back into NVKMS, the popen->data==NULL check in
         * nvkms_ioctl_common() should reject the request.
         */

        flush_scheduled_work();
    }

    nvkms_free(popen, sizeof(*popen));
}

int NVKMS_API_CALL nvkms_ioctl_common
(
    struct nvkms_per_open *popen,
    NvU32 cmd, NvU64 address, const size_t size
)
{
    int status;
    NvBool ret;

    status = down_interruptible(&nvkms_lock);
    if (status != 0) {
        return status;
    }

    if (popen->data != NULL) {
        ret = nvKmsIoctl(popen->data, cmd, popen->type, address, size);
    } else {
        ret = NV_FALSE;
    }

    up(&nvkms_lock);

    return ret ? 0 : -EPERM;
}

/*************************************************************************
 * NVKMS interface for kernel space NVKMS clients like KAPI
 *************************************************************************/

struct nvkms_per_open* NVKMS_API_CALL nvkms_open_from_kapi
(
    struct NvKmsKapiDevice *device
)
{
    int status = 0;
    return nvkms_open_common(NVKMS_CLIENT_KERNEL_SPACE, device, &status);
}

void NVKMS_API_CALL nvkms_close_from_kapi(struct nvkms_per_open *popen)
{
    nvkms_close_common(popen);
}

NvBool NVKMS_API_CALL nvkms_ioctl_from_kapi
(
    struct nvkms_per_open *popen,
    NvU32 cmd, void *params_address, const size_t param_size
)
{
    return nvkms_ioctl_common(popen,
                              cmd,
                              (NvU64)(NvUPtr)params_address, param_size) == 0;
}

/*************************************************************************
 * APIs for locking.
 *************************************************************************/

struct nvkms_sema_t {
    struct semaphore os_sema;
};

nvkms_sema_handle_t* NVKMS_API_CALL nvkms_sema_alloc(void)
{
    nvkms_sema_handle_t *sema = nvkms_alloc(sizeof(*sema), NV_TRUE);

    if (sema != NULL) {
        sema_init(&sema->os_sema, 1);
    }

    return sema;
}

void NVKMS_API_CALL nvkms_sema_free(nvkms_sema_handle_t *sema)
{
    nvkms_free(sema, sizeof(*sema));
}

void NVKMS_API_CALL nvkms_sema_down(nvkms_sema_handle_t *sema)
{
    down(&sema->os_sema);
}

void NVKMS_API_CALL nvkms_sema_up(nvkms_sema_handle_t *sema)
{
    up(&sema->os_sema);
}

/*************************************************************************
 * Procfs files support code.
 *************************************************************************/

#if defined(CONFIG_PROC_FS)

#define NVKMS_PROCFS_FOLDER "driver/nvidia-modeset"

struct proc_dir_entry *nvkms_proc_dir;

static void NVKMS_API_CALL nv_procfs_out_string(void *data, const char *str)
{
    struct seq_file *s = data;

    seq_puts(s, str);
}

static int nv_procfs_read_nvkms_proc(struct seq_file *s, void *arg)
{
    char *buffer;
    nvkms_procfs_proc_t *func;

#define NVKMS_PROCFS_STRING_SIZE 8192

    func = s->private;
    if (func == NULL) {
        return 0;
    }

    buffer = nvkms_alloc(NVKMS_PROCFS_STRING_SIZE, NV_TRUE);

    if (buffer != NULL) {
        int status = down_interruptible(&nvkms_lock);

        if (status != 0) {
            nvkms_free(buffer, NVKMS_PROCFS_STRING_SIZE);
            return status;
        }

        func(s, buffer, NVKMS_PROCFS_STRING_SIZE, &nv_procfs_out_string);

        up(&nvkms_lock);

        nvkms_free(buffer, NVKMS_PROCFS_STRING_SIZE);
    }

    return 0;
}

NV_DEFINE_PROCFS_SINGLE_FILE(nvkms_proc);

static NvBool
nvkms_add_proc_file(const nvkms_procfs_file_t *file)
{
    struct proc_dir_entry *new_proc_dir;

    if (nvkms_proc_dir == NULL) {
        return NV_FALSE;
    }

    new_proc_dir = NV_CREATE_PROC_ENTRY(file->name,
                                        0,
                                        nvkms_proc_dir,
                                        &nv_procfs_nvkms_proc_fops,
                                        file->func);
    return (new_proc_dir != NULL);
}

#endif /* defined(CONFIG_PROC_FS) */

static void nvkms_proc_init(void)
{
#if defined(CONFIG_PROC_FS)
    const nvkms_procfs_file_t *file;

    nvkms_proc_dir = NULL;
    nvKmsGetProcFiles(&file);

    if (file == NULL || file->name == NULL) {
        return;
    }

    nvkms_proc_dir = NV_CREATE_PROC_DIR(NVKMS_PROCFS_FOLDER, NULL);
    if (nvkms_proc_dir == NULL) {
        return;
    }

    while (file->name != NULL) {
        if (!nvkms_add_proc_file(file)) {
            nvkms_log(NVKMS_LOG_LEVEL_WARN, NVKMS_LOG_PREFIX,
                      "Failed to create proc file");
            break;
        }
        file++;
    }
#endif
}

static void nvkms_proc_exit(void)
{
#if defined(CONFIG_PROC_FS)
    if (nvkms_proc_dir == NULL) {
        return;
    }

#if defined(NV_PROC_REMOVE_PRESENT)
    proc_remove(nvkms_proc_dir);
#else
    /*
     * On kernel versions without proc_remove(), we need to explicitly
     * remove each proc file beneath nvkms_proc_dir.
     * nvkms_proc_init() only creates files directly under
     * nvkms_proc_dir, so those are the only files we need to remove
     * here: warn if there is any deeper directory nesting.
     */
    {
        struct proc_dir_entry *entry = nvkms_proc_dir->subdir;

        while (entry != NULL) {
            struct proc_dir_entry *next = entry->next;
            WARN_ON(entry->subdir != NULL);
            remove_proc_entry(entry->name, entry->parent);
            entry = next;
        }
    }

    remove_proc_entry(nvkms_proc_dir->name, nvkms_proc_dir->parent);
#endif /* NV_PROC_REMOVE_PRESENT */
#endif /* CONFIG_PROC_FS */
}

/*************************************************************************
 * NVKMS KAPI functions
 ************************************************************************/

NvBool NVKMS_KAPI_CALL nvKmsKapiGetFunctionsTable
(
    struct NvKmsKapiFunctionsTable *funcsTable
)
{
    return nvKmsKapiGetFunctionsTableInternal(funcsTable);
}
EXPORT_SYMBOL(nvKmsKapiGetFunctionsTable);

/*************************************************************************
 * File operation callback functions.
 *************************************************************************/

static int nvkms_open(struct inode *inode, struct file *filp)
{
    int status = 0;

    filp->private_data =
        nvkms_open_common(NVKMS_CLIENT_USER_SPACE, NULL, &status);

    return status;
}

static int nvkms_close(struct inode *inode, struct file *filp)
{
    struct nvkms_per_open *popen = filp->private_data;

    if (popen == NULL) {
        return -EINVAL;
    }

    nvkms_close_common(popen);

    return 0;
}

static int nvkms_mmap(struct file *filp, struct vm_area_struct *vma)
{
    return -EPERM;
}

static int nvkms_ioctl(struct inode *inode, struct file *filp,
                           unsigned int cmd, unsigned long arg)
{
    size_t size;
    unsigned int nr;
    int status = 0;
    struct NvKmsIoctlParams params;
    struct nvkms_per_open *popen = filp->private_data;

    if ((popen == NULL) || (popen->data == NULL)) {
        return -EINVAL;
    }

    size = _IOC_SIZE(cmd);
    nr = _IOC_NR(cmd);

    /* The only supported ioctl is NVKMS_IOCTL_CMD. */

    if ((nr != NVKMS_IOCTL_CMD) || (size != sizeof(struct NvKmsIoctlParams))) {
        return -ENOTTY;
    }

    status = copy_from_user(&params, (void *) arg, size);
    if (status != 0) {
        return -EFAULT;
    }

    return nvkms_ioctl_common(popen,
                              params.cmd,
                              params.address,
                              params.size);
}

static void nvkms_register_compatible_ioctl(void)
{
#if NV_NEEDS_COMPAT_IOCTL_REGISTRATION
    register_ioctl32_conversion(NVKMS_IOCTL_IOWR, (void *)sys_ioctl);
#endif
}

static void nvkms_unregister_compatible_ioctl(void)
{
#if NV_NEEDS_COMPAT_IOCTL_REGISTRATION
    unregister_ioctl32_conversion(NVKMS_IOCTL_IOWR);
#endif
}

static unsigned int nvkms_poll(struct file *filp, poll_table *wait)
{
    unsigned int mask = 0;
    struct nvkms_per_open *popen = filp->private_data;

    if ((popen == NULL) || (popen->data == NULL)) {
        return mask;
    }

    BUG_ON(popen->type != NVKMS_CLIENT_USER_SPACE);

    if ((filp->f_flags & O_NONBLOCK) == 0) {
        poll_wait(filp, &popen->u.user.events.wait_queue, wait);
    }

    if (atomic_read(&popen->u.user.events.available)) {
        mask = POLLPRI | POLLIN;
    }

    return mask;
}


/*************************************************************************
 * Module loading support code.
 *************************************************************************/

static nvidia_module_t nvidia_modeset_module = {
    .owner       = THIS_MODULE,
    .module_name = "nvidia-modeset",
    .instance    = 1, /* minor number: 255-1=254 */
    .open        = nvkms_open,
    .close       = nvkms_close,
    .mmap        = nvkms_mmap,
    .ioctl       = nvkms_ioctl,
    .poll        = nvkms_poll,
};

static int __init nvkms_init(void)
{
    int ret;

    ret = nvkms_alloc_rm();

    if (ret != 0) {
        return ret;
    }

    sema_init(&nvkms_lock, 1);

    INIT_LIST_HEAD(&nvkms_timers.list);
    spin_lock_init(&nvkms_timers.lock);

    ret = nvidia_register_module(&nvidia_modeset_module);

    if (ret != 0) {
        return ret;
    }

    nvkms_register_compatible_ioctl();

    down(&nvkms_lock);
    nvKmsModuleLoad();
    up(&nvkms_lock);

    nvkms_proc_init();

    return 0;
}

static void __exit nvkms_exit(void)
{
    struct nvkms_timer_t *timer, *tmp_timer;

    nvkms_proc_exit();

    down(&nvkms_lock);
    nvKmsModuleUnload();
    up(&nvkms_lock);

    /*
     * At this point, any pending tasks should be marked canceled, but
     * we still need to drain them, so that nvkms_workqueue_callback()
     * doesn't get called after the module is unloaded.
     */
restart:
    spin_lock_bh(&nvkms_timers.lock);

    list_for_each_entry_safe(timer, tmp_timer, &nvkms_timers.list, timers_list) {
        if (timer->kernel_timer_created) {
            /*
             * We delete pending timers and check whether it was being executed
             * (returns 0) or we have deactivated it before execution (returns 1).
             * If it began execution, the workqueue callback will wait for timer
             * completion, and we wait for workqueue completion with flush_scheduled_work
             * below.
             */
            if (del_timer_sync(&timer->kernel_timer) == 1) {
                /*  We've deactivated timer so we need to clean after it */
                list_del(&timer->timers_list);
                
                /* We need to unlock spinlock because we are freeing memory which
                 * may sleep */
                spin_unlock_bh(&nvkms_timers.lock);

                if (timer->isRefPtr) {
                    nvkms_dec_ref(timer->dataPtr);
                    kfree(timer);
                } else {
                    nvkms_free(timer, sizeof(*timer));
                }

                /* List could change when we were freeing memory. */
                goto restart;
            }
        }
    }

    spin_unlock_bh(&nvkms_timers.lock);

    flush_scheduled_work();

    nvkms_unregister_compatible_ioctl();

    nvidia_unregister_module(&nvidia_modeset_module);
    nvkms_free_rm();
}

module_init(nvkms_init);
module_exit(nvkms_exit);

#if defined(MODULE_LICENSE)
  MODULE_LICENSE("NVIDIA");
#endif
#if defined(MODULE_INFO)
  MODULE_INFO(supported, "external");
#endif
#if defined(MODULE_VERSION)
  MODULE_VERSION(NV_VERSION_STRING);
#endif
