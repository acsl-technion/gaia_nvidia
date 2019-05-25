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

#ifndef __UVM8_VA_BLOCK_TYPES_H__
#define __UVM8_VA_BLOCK_TYPES_H__

#include "uvm_common.h"
#include "uvm8_pte_batch.h"
#include "uvm8_tlb_batch.h"

// UVM_VA_BLOCK_BITS is 21, meaning the maximum block size is 2MB. Rationale:
// - 2MB matches the largest Pascal GPU page size so it's a natural fit
// - 2MB won't span more than one PDE on any chip, so the VA blocks never need
//   to track more than a single GPU PDE.
// - 2MB is a decent tradeoff between memory overhead and serialization
//   contention.
//
#define UVM_VA_BLOCK_BITS               21

// Max size of a block in bytes
#define UVM_VA_BLOCK_SIZE               ((NvLength)1 << UVM_VA_BLOCK_BITS)

#define UVM_VA_BLOCK_ALIGN_DOWN(addr)   UVM_ALIGN_DOWN(addr, UVM_VA_BLOCK_SIZE)
#define UVM_VA_BLOCK_ALIGN_UP(addr)     UVM_ALIGN_UP(addr, UVM_VA_BLOCK_SIZE)

#define PAGES_PER_UVM_VA_BLOCK          (UVM_VA_BLOCK_SIZE / PAGE_SIZE)

#define UVM_MIN_BIG_PAGE_SIZE           UVM_PAGE_SIZE_64K
#define MAX_BIG_PAGES_PER_UVM_VA_BLOCK  (UVM_VA_BLOCK_SIZE / UVM_MIN_BIG_PAGE_SIZE)

// Encapsulates a [first, outer) region of pages within a va block
typedef struct
{
    // Page indices within the va block
    NvU32 first;
    NvU32 outer;
} uvm_va_block_region_t;

// Encapsulates a counter tree built on top of a page mask bitmap in
// which each leaf represents a page in the block. It contains
// leaf_count and level_count so that it can use some macros for
// perf trees
typedef struct
{
    DECLARE_BITMAP(pages, PAGES_PER_UVM_VA_BLOCK);

    NvU16 leaf_count;

    NvU8 level_count;
} uvm_va_block_bitmap_tree_t;

// Iterator for the bitmap tree. It contains level_idx and node_idx so
// that it can use some macros for perf trees
typedef struct
{
    s8 level_idx;

    NvU16 node_idx;
} uvm_va_block_bitmap_tree_iter_t;

// When updating GPU PTEs, this struct describes the new arrangement of PTE
// sizes. It is calculated before the operation is applied so we know which PTE
// sizes to allocate.
//
// This only decribes the new layout. The operation page mask describes the new
// permissions of each of these PTEs.
typedef struct
{
    // Whether the new PTE should remain 2m (if already 2m) or merged to 2m.
    // The meaning is the same as uvm_va_block_gpu_state_t::pte_is_2m. If this
    // is set, the other fields can be ignored.
    bool pte_is_2m;

    // Whether the operation requires writing 4k PTEs and thus needs them
    // allocated. Mutually exclusive to pte_is_2m, but not to big_ptes.
    bool needs_4k;

    // These are the PTEs which will be big after the operation is done. This
    // field will become the new value of uvm_va_block_gpu_state_t::big_ptes, so
    // it contains both those big PTEs which are being modified by the
    // operation, and any pre-existing big PTEs which remain unchanged. The
    // latter will not have the corresponding bit set in big_ptes_covered.
    DECLARE_BITMAP(big_ptes, MAX_BIG_PAGES_PER_UVM_VA_BLOCK);

    // These are the big PTE regions which the operation is touching. These may
    // or may not be big PTEs: use the big_ptes bitmap to determine that. For
    // example, a bit set here but not in big_ptes means that the PTE size for
    // that region should be 4k, and that some of those 4k PTEs will be written
    // by the operation.
    DECLARE_BITMAP(big_ptes_covered, MAX_BIG_PAGES_PER_UVM_VA_BLOCK);

    // These are the big PTE regions which will no longer have any valid
    // mappings after the operation. Only the bits which are set in
    // big_ptes_covered are valid.
    DECLARE_BITMAP(big_ptes_fully_unmapped, MAX_BIG_PAGES_PER_UVM_VA_BLOCK);
} uvm_va_block_new_pte_state_t;

// Event that triggered the call to uvm_va_block_make_resident/
// uvm_va_block_make_resident_read_duplicate
typedef enum
{
    UVM_MAKE_RESIDENT_CAUSE_FAULT,

    UVM_MAKE_RESIDENT_CAUSE_NON_REPLAYABLE_FAULT,

    UVM_MAKE_RESIDENT_CAUSE_PREFETCH,
    UVM_MAKE_RESIDENT_CAUSE_EVICTION,
    UVM_MAKE_RESIDENT_CAUSE_API_TOOLS,
    UVM_MAKE_RESIDENT_CAUSE_API_MIGRATE,
    UVM_MAKE_RESIDENT_CAUSE_API_SET_RANGE_GROUP,
    UVM_MAKE_RESIDENT_CAUSE_API_HINT,

    UVM_MAKE_RESIDENT_CAUSE_MAX
} uvm_make_resident_cause_t;

// Event that triggered the call to uvm_va_block_map/uvm_va_block_map_mask
typedef enum
{
    UVM_MAP_CAUSE_FAULT,
    UVM_MAP_CAUSE_LITE,
    UVM_MAP_CAUSE_THRASHING,
    UVM_MAP_CAUSE_API_HINT,

    UVM_MAP_CAUSE_MAX
} uvm_map_cause_t;

// In the worst case some VA block operations require more state than we should
// reasonably store on the stack. Instead, we dynamically allocate VA block
// contexts. These are used for almost all operations on VA blocks.
typedef struct
{
    // Available as scratch space for the caller. Not used by any of the VA
    // block APIs.
    DECLARE_BITMAP(caller_page_mask, PAGES_PER_UVM_VA_BLOCK);

    // Available as scratch space for the internal APIs. This is like a caller-
    // save register: it shouldn't be used across function calls which also take
    // this block_context.
    DECLARE_BITMAP(scratch_page_mask, PAGES_PER_UVM_VA_BLOCK);

    // State used by uvm_va_block_make_resident
    struct
    {
        // Masks used internally
        DECLARE_BITMAP(page_mask, PAGES_PER_UVM_VA_BLOCK);
        DECLARE_BITMAP(copy_resident_pages_between_mask, PAGES_PER_UVM_VA_BLOCK);
        DECLARE_BITMAP(pages_staged, PAGES_PER_UVM_VA_BLOCK);

        // Out mask filled in by uvm_va_block_make_resident to indicate which
        // pages actually changed residency.
        DECLARE_BITMAP(pages_changed_residency, PAGES_PER_UVM_VA_BLOCK);

        // Out mask of all processors involved in the migration either as
        // source, destination or the processor performing the copy.
        // Used to perform ECC checks after the migration is done.
        uvm_processor_mask_t all_involved_processors;

        // Final residency for the data. This is useful for callees to know if
        // a migration is part of a staging copy
        uvm_processor_id_t dest_id;

        // Event that triggered the call
        uvm_make_resident_cause_t cause;
    } make_resident;

    // State used by the mapping APIs (unmap, map, revoke). This could be used
    // at the same time as the state in make_resident.
    struct
    {
        // Master mask used by uvm_va_block_map and uvm_va_block_revoke_prot.
        // Bits are removed as the operation progresses.
        DECLARE_BITMAP(running_page_mask, PAGES_PER_UVM_VA_BLOCK);

        DECLARE_BITMAP(page_mask, PAGES_PER_UVM_VA_BLOCK);
        DECLARE_BITMAP(filtered_page_mask, PAGES_PER_UVM_VA_BLOCK);

        uvm_va_block_new_pte_state_t new_pte_state;

        uvm_pte_batch_t pte_batch;
        uvm_tlb_batch_t tlb_batch;

        // Event that triggered the call to the mapping function
        uvm_map_cause_t cause;
    } mapping;

    struct
    {
        // Used when adding mappings for pages that are already mapped
        struct
        {
            DECLARE_BITMAP(mapping_mask, PAGES_PER_UVM_VA_BLOCK);

            unsigned count;
        } by_prot[UVM_PROT_MAX - 1];
    } migrate;

    struct
    {
        DECLARE_BITMAP(running_page_mask, PAGES_PER_UVM_VA_BLOCK);
    } update_read_duplicated_pages;

} uvm_va_block_context_t;

typedef enum
{
    UVM_VA_BLOCK_TRANSFER_MODE_MOVE = 1,
    UVM_VA_BLOCK_TRANSFER_MODE_COPY = 2
} uvm_va_block_transfer_mode_t;

#endif
