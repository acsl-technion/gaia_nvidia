/*******************************************************************************
    Copyright (c) 2016 NVIDIA Corporation

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

#include "uvm_linux.h"
#include "uvm8_hal.h"
#include "uvm8_push.h"
#include "uvm8_user_channel.h"
#include "clc36f.h"

void uvm_hal_volta_host_write_gpu_put(uvm_channel_t *channel, NvU32 gpu_put)
{
    UVM_WRITE_ONCE(*channel->channel_info.GPPut, gpu_put);

    wmb();

    UVM_WRITE_ONCE(*channel->channel_info.workSubmissionOffset, channel->channel_info.workSubmissionToken);
}

static NvU32 fault_access_type_to_cancel_access_type(uvm_fault_access_type_t access_type)
{
    switch (access_type)
    {
        case UVM_FAULT_ACCESS_TYPE_READ:
            return HWCONST(C36F, MEM_OP_C, TLB_INVALIDATE_ACCESS_TYPE, VIRT_ALL);
        case UVM_FAULT_ACCESS_TYPE_WRITE:
            return HWCONST(C36F, MEM_OP_C, TLB_INVALIDATE_ACCESS_TYPE, VIRT_WRITE_AND_ATOMIC);
        case UVM_FAULT_ACCESS_TYPE_ATOMIC_WEAK:
            return HWCONST(C36F, MEM_OP_C, TLB_INVALIDATE_ACCESS_TYPE, VIRT_ATOMIC_ALL);
        case UVM_FAULT_ACCESS_TYPE_ATOMIC_STRONG:
            return HWCONST(C36F, MEM_OP_C, TLB_INVALIDATE_ACCESS_TYPE, VIRT_ATOMIC_STRONG);
        default:
            UVM_ASSERT_MSG(false, "Invalid access type %d\n", access_type);
    }

    return 0;
}

void uvm_hal_volta_cancel_faults_va(uvm_push_t *push,
                                    uvm_gpu_phys_address_t pdb,
                                    uvm_fault_buffer_entry_t *fault_entry)
{
    NvU32 aperture_value;
    NvU32 pdb_lo;
    NvU32 pdb_hi;
    NvU32 addr_lo;
    NvU32 addr_hi;
    NvU32 access_type_value;
    NvU64 addr = fault_entry->fault_address;
    NvU32 mmu_engine_id = fault_entry->fault_source.mmu_engine_id;

    UVM_ASSERT_MSG(pdb.aperture == UVM_APERTURE_VID || pdb.aperture == UVM_APERTURE_SYS, "aperture: %u", pdb.aperture);

    if (pdb.aperture == UVM_APERTURE_VID)
        aperture_value = HWCONST(C36F, MEM_OP_C, TLB_INVALIDATE_PDB_APERTURE, VID_MEM);
    else
        aperture_value = HWCONST(C36F, MEM_OP_C, TLB_INVALIDATE_PDB_APERTURE, SYS_MEM_COHERENT);

    UVM_ASSERT_MSG(IS_ALIGNED(pdb.address, 1 << 12), "pdb 0x%llx not aligned to 4KB\n", pdb.address);
    pdb.address >>= 12;

    pdb_lo = pdb.address & HWMASK(C36F, MEM_OP_C, TLB_INVALIDATE_PDB_ADDR_LO);
    pdb_hi = pdb.address >> HWSIZE(C36F, MEM_OP_C, TLB_INVALIDATE_PDB_ADDR_LO);

    access_type_value = fault_access_type_to_cancel_access_type(fault_entry->fault_access_type);

    UVM_ASSERT_MSG(IS_ALIGNED(addr, 1 << 12), "addr 0x%llx not aligned to 4KB\n", addr);
    addr >>= 12;

    addr_lo = addr & HWMASK(C36F, MEM_OP_A, TLB_INVALIDATE_TARGET_ADDR_LO);
    addr_hi = addr >> HWSIZE(C36F, MEM_OP_A, TLB_INVALIDATE_TARGET_ADDR_LO);

    NV_PUSH_4U(C36F, MEM_OP_A, HWCONST(C36F, MEM_OP_A, TLB_INVALIDATE_SYSMEMBAR, DIS) |
                               HWVALUE(C36F, MEM_OP_A, TLB_INVALIDATE_TARGET_ADDR_LO, addr_lo) |
                               HWVALUE(C36F, MEM_OP_A, TLB_INVALIDATE_CANCEL_MMU_ENGINE_ID, mmu_engine_id),
                     MEM_OP_B, HWVALUE(C36F, MEM_OP_B, TLB_INVALIDATE_TARGET_ADDR_HI, addr_hi),
                     MEM_OP_C, HWCONST(C36F, MEM_OP_C, TLB_INVALIDATE_PDB, ONE) |
                               HWVALUE(C36F, MEM_OP_C, TLB_INVALIDATE_PDB_ADDR_LO, pdb_lo) |
                               HWCONST(C36F, MEM_OP_C, TLB_INVALIDATE_GPC, ENABLE) |
                               HWCONST(C36F, MEM_OP_C, TLB_INVALIDATE_REPLAY, CANCEL_VA_GLOBAL) |
                               HWCONST(C36F, MEM_OP_C, TLB_INVALIDATE_ACK_TYPE, NONE) |
                               access_type_value |
                               aperture_value,
                     MEM_OP_D, HWCONST(C36F, MEM_OP_D, OPERATION, MMU_TLB_INVALIDATE_TARGETED) |
                               HWVALUE(C36F, MEM_OP_D, TLB_INVALIDATE_PDB_ADDR_HI, pdb_hi));
}

void uvm_hal_volta_host_clear_faulted_channel(uvm_push_t *push,
                                              uvm_user_channel_t *user_channel,
                                              uvm_fault_buffer_entry_t *fault)
{
    NvU32 clear_type_value = 0;

    if (fault->fault_source.mmu_engine_type == UVM_MMU_ENGINE_TYPE_HOST) {
        clear_type_value = HWCONST(C36F, CLEAR_FAULTED, TYPE, PBDMA_FAULTED);
    }
    else if (fault->fault_source.mmu_engine_type == UVM_MMU_ENGINE_TYPE_CE) {
        clear_type_value = HWCONST(C36F, CLEAR_FAULTED, TYPE, ENG_FAULTED);
    }
    else {
        UVM_ASSERT_MSG(false, "Unsupported MMU engine type %s\n",
                       uvm_mmu_engine_type_string(fault->fault_source.mmu_engine_type));
    }

    NV_PUSH_1U(C36F, CLEAR_FAULTED, HWVALUE(C36F, CLEAR_FAULTED, CHID, user_channel->hw_channel_id) |
                                    clear_type_value);
}

void uvm_hal_volta_access_counter_clear_all(uvm_push_t *push)
{
    NV_PUSH_4U(C36F, MEM_OP_A, 0,
                     MEM_OP_B, 0,
                     MEM_OP_C, 0,
                     MEM_OP_D, HWCONST(C36F, MEM_OP_D, OPERATION, ACCESS_COUNTER_CLR) |
                               HWCONST(C36F, MEM_OP_D, ACCESS_COUNTER_CLR_TYPE, ALL));
}

static NvU32 get_access_counter_type_value(uvm_access_counter_type_t type)
{
    if (type == UVM_ACCESS_COUNTER_TYPE_MIMC)
        return NVC36F_MEM_OP_D_ACCESS_COUNTER_CLR_TYPE_MIMC;
    else if (type == UVM_ACCESS_COUNTER_TYPE_MOMC)
        return NVC36F_MEM_OP_D_ACCESS_COUNTER_CLR_TYPE_MOMC;
    else
        UVM_ASSERT_MSG(false, "Invalid access counter type %u\n", type);

    return 0;
}

static NvU32 get_access_counter_targeted_type_value(uvm_access_counter_type_t type)
{
    if (type == UVM_ACCESS_COUNTER_TYPE_MIMC)
        return NVC36F_MEM_OP_D_ACCESS_COUNTER_CLR_TARGETED_TYPE_MIMC;
    else if (type == UVM_ACCESS_COUNTER_TYPE_MOMC)
        return NVC36F_MEM_OP_D_ACCESS_COUNTER_CLR_TARGETED_TYPE_MOMC;
    else
        UVM_ASSERT_MSG(false, "Invalid access counter type %u\n", type);

    return 0;
}

void uvm_hal_volta_access_counter_clear_type(uvm_push_t *push, uvm_access_counter_type_t type)
{
    NvU32 type_value = get_access_counter_type_value(type);

    NV_PUSH_4U(C36F, MEM_OP_A, 0,
                     MEM_OP_B, 0,
                     MEM_OP_C, 0,
                     MEM_OP_D, HWCONST(C36F, MEM_OP_D, OPERATION, ACCESS_COUNTER_CLR) |
                               HWVALUE(C36F, MEM_OP_D, ACCESS_COUNTER_CLR_TYPE, type_value));
}

void uvm_hal_volta_access_counter_clear_targeted(uvm_push_t *push,
                                                 uvm_access_counter_buffer_entry_t *buffer_entry)
{
    NvU32 targeted_type_value = get_access_counter_targeted_type_value(buffer_entry->counter_type);

    NV_PUSH_4U(C36F, MEM_OP_A, 0,
                     MEM_OP_B, 0,
                     MEM_OP_C, HWVALUE(C36F, MEM_OP_C, ACCESS_COUNTER_CLR_TARGETED_NOTIFY_TAG, buffer_entry->tag),
                     MEM_OP_D, HWCONST(C36F, MEM_OP_D, OPERATION, ACCESS_COUNTER_CLR) |
                               HWCONST(C36F, MEM_OP_D, ACCESS_COUNTER_CLR_TYPE, TARGETED) |
                               HWVALUE(C36F, MEM_OP_D, ACCESS_COUNTER_CLR_TARGETED_TYPE, targeted_type_value) |
                               HWVALUE(C36F, MEM_OP_D, ACCESS_COUNTER_CLR_TARGETED_BANK, buffer_entry->bank));
}
