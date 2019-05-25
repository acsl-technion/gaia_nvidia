/*
* _NVRM_COPYRIGHT_BEGIN_
*
* Copyright 2015 by NVIDIA Corporation.  All rights reserved.  All
* information contained herein is proprietary and confidential to NVIDIA
* Corporation.  Any use, reproduction, or disclosure without the written
* permission of NVIDIA Corporation is prohibited.
*
* _NVRM_COPYRIGHT_END_
*/

#ifndef _clc076_h_
#define _clc076_h_

#ifdef __cplusplus
extern "C" {
#endif

#include "nvtypes.h"

#define GP100_UVM_SW                                                (0x0000c076)

#define NVC076_SET_OBJECT                                           (0x00000000)
#define NVC076_NO_OPERATION                                         (0x00000100)

/* Method data fields to support gpu fault cancel. These are pushed in order by UVM */

#define NVC076_FAULT_CANCEL_A                                       (0x00000104)
#define NVC076_FAULT_CANCEL_A_INST_APERTURE                         1:0
#define NVC076_FAULT_CANCEL_A_INST_APERTURE_VID_MEM                 0x00000000
#define NVC076_FAULT_CANCEL_A_INST_APERTURE_SYS_MEM_COHERENT        0x00000002
#define NVC076_FAULT_CANCEL_A_INST_APERTURE_SYS_MEM_NONCOHERENT     0x00000003

/* instance pointer is 4k aligned so those bits are reused to store the aperture */
#define NVC076_FAULT_CANCEL_A_INST_LOW                              31:12

#define NVC076_FAULT_CANCEL_B                                       (0x00000108)
#define NVC076_FAULT_CANCEL_B_INST_HI                               31:0

#define NVC076_FAULT_CANCEL_C                                       (0x0000010c)
#define NVC076_FAULT_CANCEL_C_CLIENT_ID                             5:0
#define NVC076_FAULT_CANCEL_C_GPC_ID                                10:6

#ifdef __cplusplus
};     /* extern "C" */
#endif

#endif /* _clc076_h_ */
