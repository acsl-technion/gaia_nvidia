/*******************************************************************************
    Copyright (c) 2015-2016 NVidia Corporation

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

#include "conftest.h"

#include <linux/module.h>
#include <linux/major.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/delay.h>            /* mdelay, udelay                   */
#include <linux/hardirq.h> 
#if defined(NV_LINUX_SEMAPHORE_H_PRESENT)
#include <linux/semaphore.h>
#else
#include <asm/semaphore.h>
#endif
#if defined(CONFIG_KDB)
/* Work around a bug in some KDB implementations that have underspecified
 * header dependencies */
#include <linux/console.h>
#include <linux/kdb.h>
#include <asm/kdb.h>
#endif
#include "nvlink_common.h"
#include "nvlink_linux.h"
#include "nvlink_proto.h"

#include "nvlink_export.h"

#define MAX_ERROR_STRING           512

#define NV_MAX_ISR_DELAY_US           20000
#define NV_MAX_ISR_DELAY_MS           (NV_MAX_ISR_DELAY_US / 1000)

#define NV_MSECS_PER_JIFFIE         (1000 / HZ)
#define NV_MSECS_TO_JIFFIES(msec)   ((msec) * HZ / 1000)
#define NV_USECS_PER_JIFFIE         (1000000 / HZ)
#define NV_USECS_TO_JIFFIES(usec)   ((usec) * HZ / 1000000)

static int nvlink_major_devnum;

static void dbg_breakpoint(void)
{
#if defined(DEBUG)
  #if defined(CONFIG_X86_REMOTE_DEBUG) || defined(CONFIG_KGDB) || defined(CONFIG_XMON)
    #if defined(NVCPU_X86) || defined(NVCPU_X86_64)
        __asm__ __volatile__ ("int $3");
    #elif defined(NVCPU_ARM)
        __asm__ __volatile__ (".word %c0" :: "i" (KGDB_COMPILED_BREAK));
    #elif defined(NVCPU_AARCH64)
        # warning "Need to implement dbg_breakpoint() for aarch64"
    #elif defined(NVCPU_PPC64LE)
        __asm__ __volatile__ ("trap");
    #endif // NVCPU_X86 || NVCPU_X86_64
  #elif defined(CONFIG_KDB)
      KDB_ENTER();
  #endif // CONFIG_X86_REMOTE_DEBUG || CONFIG_KGDB || CONFIG_XMON
#endif // DEBUG
}

static int nvlink_fops_open(struct inode *inode, struct file *filp)
{
    return 0;
}

static int nvlink_fops_release(struct inode *inode, struct file *filp)
{
    return 0;
}

static long nvlink_fops_unlocked_ioctl(struct file *filp,
                                       unsigned int cmd,
                                       unsigned long arg)
{
    return -ENOTSUPP;
}

static const struct file_operations nvlink_fops = {
    .owner           = THIS_MODULE,
    .open            = nvlink_fops_open,
    .release         = nvlink_fops_release,
#if defined(NV_FILE_OPERATIONS_HAS_UNLOCKED_IOCTL)
    .unlocked_ioctl  = nvlink_fops_unlocked_ioctl,
#endif
};

int __init nvlink_core_init(void)
{
    dev_t dev;
    int ret;

    ret = alloc_chrdev_region(&dev, 0, NVLINK_NUM_MINOR_DEVICES,
                              NVLINK_DEVICE_NAME);
    nvlink_major_devnum = MAJOR(dev);
    if (ret < 0)
    {
        nvlink_print(NVLINK_DBG_ERRORS,
            "alloc_chrdev_region failed: %d\n", ret);
        return ret;
    }

    //
    // TODO: Create char dev node and associate it with nvlink_fops
    //
 
    nvlink_print(NVLINK_DBG_INFO,
        "Nvlink Core is being initialized, major device number %d\n",
        nvlink_major_devnum);

    nvlink_lib_initialize();

    return ret;
}

void nvlink_core_exit(void)
{

    nvlink_lib_unload();

    if (nvlink_major_devnum != 0)
    {
        unregister_chrdev_region(MKDEV(nvlink_major_devnum, 0),
                                 NVLINK_NUM_MINOR_DEVICES);
    }

    nvlink_print(NVLINK_DBG_INFO,
        "Unregistered the Nvlink Core, major device number %d\n",
        nvlink_major_devnum);
}


void 
NVLINK_API_CALL
nvlink_print
(
    const char *file,
    int         line,
    const char *function,
    int         log_level,
    const char *fmt,
    ...
)
{
    va_list arglist;
    char    nv_string[MAX_ERROR_STRING];
    char   *sys_log_level;

    switch (log_level) {
    case NVLINK_DBG_LEVEL_INFO:
        sys_log_level = KERN_INFO;
        break;
    case NVLINK_DBG_LEVEL_SETUP:
        sys_log_level = KERN_DEBUG;
        break;
    case NVLINK_DBG_LEVEL_USERERRORS:
        sys_log_level = KERN_NOTICE;
        break;
    case NVLINK_DBG_LEVEL_WARNINGS:
        sys_log_level = KERN_WARNING;
        break;
    case NVLINK_DBG_LEVEL_ERRORS:
        sys_log_level = KERN_ERR;
        break;
    default:
        sys_log_level = KERN_INFO;
        break;
    }

    va_start(arglist, fmt);
    vsnprintf(nv_string, sizeof(nv_string), fmt, arglist);
    va_end(arglist);

    nv_string[sizeof(nv_string) - 1] = '\0';
    printk("%snvidia-nvlink: %s", sys_log_level, nv_string);
}

void * NVLINK_API_CALL nvlink_malloc(NvLength size)
{
   return kmalloc(size, GFP_KERNEL);
}

void NVLINK_API_CALL nvlink_free(void *ptr)
{
    return kfree(ptr);
}

char * NVLINK_API_CALL nvlink_strcpy(char *dest, const char *src)
{
    return strcpy(dest, src);
}

int NVLINK_API_CALL nvlink_strcmp(const char *dest, const char *src)
{
    return strcmp(dest, src);
}

NvLength NVLINK_API_CALL nvlink_strlen(const char *s)
{
    return strlen(s);
}

int NVLINK_API_CALL nvlink_snprintf(char *dest, NvLength size, const char *fmt, ...)
{
    va_list arglist;
    int chars_written;

    va_start(arglist, fmt);
    chars_written = vsnprintf(dest, size, fmt, arglist);
    va_end(arglist);

    return chars_written;
}

int NVLINK_API_CALL nvlink_memRd32(const volatile void * address)
{
    return (*(const volatile unsigned int*)(address));
}

void NVLINK_API_CALL nvlink_memWr32(volatile void *address, unsigned int data)
{
    (*(volatile unsigned int *)(address)) = data;
}

int NVLINK_API_CALL nvlink_memRd64(const volatile void * address)
{
    return (*(const volatile unsigned long long *)(address));
}

void NVLINK_API_CALL nvlink_memWr64(volatile void *address, unsigned long long data)
{
    (*(volatile unsigned long long *)(address)) = data;
}

void * NVLINK_API_CALL nvlink_memset(void *dest, int value, NvLength size)
{
     return memset(dest, value, size);
}

void * NVLINK_API_CALL nvlink_memcpy(void *dest, void *src, NvLength size)
{
    return memcpy(dest, src, size);
}

static NvBool nv_timer_less_than
(
    const struct timeval *a,
    const struct timeval *b
)
{
    return (a->tv_sec == b->tv_sec) ? (a->tv_usec < b->tv_usec) 
                                    : (a->tv_sec < b->tv_sec);
}

static void nv_timeradd
(
    const struct timeval    *a,
    const struct timeval    *b,
    struct timeval          *result
)
{
    result->tv_sec = a->tv_sec + b->tv_sec;
    result->tv_usec = a->tv_usec + b->tv_usec;
    while (result->tv_usec >= 1000000)
    {
        ++result->tv_sec;
        result->tv_usec -= 1000000;
    }
}

static void nv_timersub
(
    const struct timeval    *a,
    const struct timeval    *b,
    struct timeval          *result
)
{
    result->tv_sec = a->tv_sec - b->tv_sec;
    result->tv_usec = a->tv_usec - b->tv_usec;
    while (result->tv_usec < 0)
    {
        --(result->tv_sec);
        result->tv_usec += 1000000;
    }
}

/*
 * Sleep for specified milliseconds. Yields the CPU to scheduler.
 */
void NVLINK_API_CALL nvlink_sleep(unsigned int ms)
{
    unsigned long us;
    unsigned long jiffies;
    unsigned long mdelay_safe_msec;
    struct timeval tm_end, tm_aux;

    do_gettimeofday(&tm_aux);

    if (in_irq() && (ms > NV_MAX_ISR_DELAY_MS))
    {
        return;
    }

    if (irqs_disabled() || in_interrupt() || in_atomic())
    {
        mdelay(ms);
        return;
    }

    us = ms * 1000;
    tm_end.tv_usec = us;
    tm_end.tv_sec = 0;
    nv_timeradd(&tm_aux, &tm_end, &tm_end);

    /* do we have a full jiffie to wait? */
    jiffies = NV_USECS_TO_JIFFIES(us);

    if (jiffies)
    {
        //
        // If we have at least one full jiffy to wait, give up
        // up the CPU; since we may be rescheduled before
        // the requested timeout has expired, loop until less
        // than a jiffie of the desired delay remains.
        //
        current->state = TASK_INTERRUPTIBLE;
        do
        {
            schedule_timeout(jiffies);
            do_gettimeofday(&tm_aux);
            if (nv_timer_less_than(&tm_aux, &tm_end))
            {
                nv_timersub(&tm_end, &tm_aux, &tm_aux);
                us = tm_aux.tv_usec + tm_aux.tv_sec * 1000000;
            }
            else
            {
                us = 0;
            }
        } 
        while ((jiffies = NV_USECS_TO_JIFFIES(us)) != 0);
    }

    if (us > 1000)
    {
        mdelay_safe_msec = us / 1000;
        mdelay(mdelay_safe_msec);
        us %= 1000;
    }
    if (us)
    {
        udelay(us);
    }
}

void NVLINK_API_CALL nvlink_assert(int cond)
{
    if ((cond) == 0x0)
    {
        nvlink_print(NVLINK_DBG_ERRORS, "Assertion failed!\n");
        dbg_breakpoint();
    }
}

void * NVLINK_API_CALL nvlink_allocLock()
{
    struct semaphore *sema;

    sema = nvlink_malloc(sizeof(*sema));
    if (sema == NULL)
    {
        nvlink_print(NVLINK_DBG_ERRORS, "Failed to allocate sema!\n");
        return NULL;
    }
    sema_init(sema, 1);

    return sema;
}

void NVLINK_API_CALL nvlink_acquireLock(void *hLock)
{
    down(hLock);
}

void NVLINK_API_CALL nvlink_releaseLock(void *hLock)
{
    up(hLock);
}

void NVLINK_API_CALL nvlink_freeLock(void *hLock)
{
    if (NULL == hLock)
    {
        return;
    }

    NVLINK_FREE(hLock);
}

NvBool NVLINK_API_CALL nvlink_isLockOwner(void *hLock)
{
    return NV_TRUE;
}
