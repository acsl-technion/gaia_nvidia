/*******************************************************************************
    Copyright (c) 2015 NVIDIA Corporation

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

#include "uvm8_test.h"
#include "uvm8_test_ioctl.h"
#include "uvm8_gpu.h"
#include "uvm8_global.h"
#include "uvm8_hal.h"
#include "uvm8_tlb_batch.h"
#include "uvm8_mmu.h"
#include "uvm8_kvmalloc.h"
// KEPLER_*
#include "cla0b5.h"
#include "cla06f.h"
// PASCAL_*
#include "clb069.h" // MAXWELL_FAULT_BUFFER_A
#include "clc0b5.h"
#include "clc06f.h"
// ARCHITECTURE_*
#include "ctrl2080mc.h"

#define BIG_PAGE_SIZE_PASCAL (1 << 16)

static void fake_ce_memset_8(uvm_push_t *push, uvm_gpu_address_t dst, NvU64 value, size_t size)
{
    size_t i;

    UVM_ASSERT(dst.aperture == UVM_APERTURE_SYS);

    for (i = 0; i < size; i += 8)
        *(NvU64 *)phys_to_virt(dst.address + i) = value;
}

void *cpu_addr_from_fake(uvm_gpu_address_t fake_gpu_addr)
{
    if (fake_gpu_addr.is_virtual)
        return (void*)fake_gpu_addr.address;

    UVM_ASSERT(fake_gpu_addr.aperture == UVM_APERTURE_SYS);
    return phys_to_virt(fake_gpu_addr.address);
}

static void fake_ce_memcopy(uvm_push_t *push, uvm_gpu_address_t dst, uvm_gpu_address_t src, size_t size)
{
    memcpy(cpu_addr_from_fake(dst), cpu_addr_from_fake(src), size);
}

void fake_wait_for_idle(uvm_push_t *push)
{
}

void fake_noop(uvm_push_t *push, NvU32 size)
{
    push->next += size / 4;
}

void fake_membar(uvm_push_t *push)
{
}

#define FAKE_TLB_INVALS_COUNT_MAX UVM_TLB_BATCH_MAX_ENTRIES

typedef struct
{
    NvU64 base;
    NvU64 size;
    NvU32 page_size;
    NvU32 depth;
    uvm_membar_t membar;
} fake_tlb_invalidate_t;

static NvU32 g_fake_invals_count = 0;
static fake_tlb_invalidate_t *g_fake_invals = NULL;
static fake_tlb_invalidate_t *g_last_fake_inval;
static bool g_fake_tlb_invals_tracking_enabled = false;

// Allocate the tracking for TLB invalidates
static NV_STATUS fake_tlb_invals_alloc(void)
{
    UVM_ASSERT(!g_fake_invals);
    g_fake_invals = (fake_tlb_invalidate_t *)uvm_kvmalloc(sizeof(*g_fake_invals) * FAKE_TLB_INVALS_COUNT_MAX);
    if (!g_fake_invals)
        return NV_ERR_NO_MEMORY;

    return NV_OK;
}

// Free the tracking for TLB invalidates
static void fake_tlb_invals_free(void)
{
    uvm_kvfree(g_fake_invals);
    g_fake_invals = NULL;
}

static void fake_tlb_invals_reset(void)
{
    UVM_ASSERT(g_fake_tlb_invals_tracking_enabled);

    g_fake_invals_count = 0;
}

static void fake_tlb_invals_enable(void)
{
    UVM_ASSERT(g_fake_invals);

    g_fake_tlb_invals_tracking_enabled = true;
}

static void fake_tlb_invals_disable(void)
{
    UVM_ASSERT(g_fake_invals);

    fake_tlb_invals_reset();
    g_fake_tlb_invals_tracking_enabled = false;
}

// Fake TLB invalidate VA that just saves off the parameters so that they can be verified later
static void fake_tlb_invalidate_va(uvm_push_t *push, uvm_gpu_phys_address_t pdb,
        NvU32 depth, NvU64 base, NvU64 size, NvU32 page_size, uvm_membar_t membar)
{
    if (!g_fake_tlb_invals_tracking_enabled)
        return;

    ++g_fake_invals_count;

    if (g_fake_invals_count == FAKE_TLB_INVALS_COUNT_MAX + 1) {
        // Assert on the first overflow
        UVM_ASSERT(0);
    }

    if (g_fake_invals_count > FAKE_TLB_INVALS_COUNT_MAX)
        return;

    g_last_fake_inval = &g_fake_invals[g_fake_invals_count - 1];

    g_last_fake_inval->base = base;
    g_last_fake_inval->size = size;
    g_last_fake_inval->page_size = page_size;
    g_last_fake_inval->depth = depth;
    g_last_fake_inval->membar = membar;
}

static void fake_tlb_invalidate_all(uvm_push_t *push, uvm_gpu_phys_address_t pdb, NvU32 depth, uvm_membar_t membar)
{
    fake_tlb_invalidate_va(push, pdb, depth, 0, -1, 0, membar);
}


static bool assert_no_invalidate(void)
{
    UVM_ASSERT(g_fake_tlb_invals_tracking_enabled);

    if (g_fake_invals_count != 0) {
        UVM_TEST_PRINT("Expected no invalidates, but got %u instead\n", g_fake_invals_count);
        return false;
    }
    return true;
}

static bool assert_and_reset_last_invalidate(NvU32 expected_depth, bool expected_membar)
{
    bool result = true;

    UVM_ASSERT(g_fake_tlb_invals_tracking_enabled);

    if (g_fake_invals_count == 0) {
        UVM_TEST_PRINT("Expected an invalidate, but got none\n");
        return false;
    }
    if (g_fake_invals_count > FAKE_TLB_INVALS_COUNT_MAX) {
        UVM_TEST_PRINT("Too many invalidates %u\n", g_fake_invals_count);
        return false;
    }

    if (g_last_fake_inval->depth != expected_depth) {
        UVM_TEST_PRINT("Expected depth %u, got %u instead\n", expected_depth, g_last_fake_inval->depth);
        result = false;
    }
    if ((g_last_fake_inval->membar == UVM_MEMBAR_NONE) == expected_membar) {
        UVM_TEST_PRINT("Expected %s membar, got %s instead\n",
                expected_membar ? "a" : "no",
                uvm_membar_string(g_last_fake_inval->membar));
        result = false;
    }
    fake_tlb_invals_reset();
    return result;
}

static bool assert_last_invalidate_all(NvU32 expected_depth, bool expected_membar)
{
    UVM_ASSERT(g_fake_tlb_invals_tracking_enabled);

    if (g_fake_invals_count != 1) {
        UVM_TEST_PRINT("Expected a single invalidate, but got %u instead\n", g_fake_invals_count);
        return false;
    }
    if (g_last_fake_inval->base != 0 || g_last_fake_inval->size != -1) {
        UVM_TEST_PRINT("Expected invalidate all but got range [0x%llx, 0x%llx) instead\n",
                g_last_fake_inval->base, g_last_fake_inval->base + g_last_fake_inval->size);
        return false;
    }
    if (g_last_fake_inval->depth != expected_depth) {
        UVM_TEST_PRINT("Expected depth %u, got %u instead\n", expected_depth, g_last_fake_inval->depth);
        return false;
    }
    return true;
}

static bool assert_invalidate_range_specific(fake_tlb_invalidate_t *inval,
        NvU64 base, NvU64 size, NvU32 page_size, NvU32 expected_depth, bool expected_membar)
{
    UVM_ASSERT(g_fake_tlb_invals_tracking_enabled);

    if (g_fake_invals_count == 0) {
        UVM_TEST_PRINT("Expected an invalidate for range [0x%llx, 0x%llx), but got none\n",
                base, base + size);
        return false;
    }

    if ((inval->base != base || inval->size != size) && inval->base != 0 && inval->size != -1) {
        UVM_TEST_PRINT("Expected invalidate range [0x%llx, 0x%llx), but got range [0x%llx, 0x%llx) instead\n",
                base, base + size,
                inval->base, inval->base + inval->size);
        return false;
    }
    if (inval->depth != expected_depth) {
        UVM_TEST_PRINT("Expected depth %u, got %u instead\n", expected_depth, inval->depth);
        return false;
    }
    if (inval->page_size != page_size && inval->base != 0 && inval->size != -1) {
        UVM_TEST_PRINT("Expected page size %u, got %u instead\n", page_size, inval->page_size);
        return false;
    }

    return true;
}

static bool assert_invalidate_range(NvU64 base, NvU64 size, NvU32 page_size, bool allow_inval_all, NvU32 range_depth, NvU32 all_depth, bool expected_membar)
{
    NvU32 i;

    UVM_ASSERT(g_fake_tlb_invals_tracking_enabled);

    if (g_fake_invals_count == 0) {
        UVM_TEST_PRINT("Expected an invalidate for range [0x%llx, 0x%llx), but got none\n",
                base, base + size);
        return false;
    }

    for (i = 0; i < g_fake_invals_count; ++i) {
        fake_tlb_invalidate_t *inval = &g_fake_invals[i];
        if (inval->base == base && inval->size == size)
            return assert_invalidate_range_specific(inval, base, size, page_size, range_depth, expected_membar);
    }

    if (g_fake_invals_count == 1 && allow_inval_all)
        return assert_last_invalidate_all(all_depth, expected_membar);

    UVM_TEST_PRINT("Couldn't find an invalidate for range [0x%llx, 0x%llx) in:\n", base, base + size);
    for (i = 0; i < g_fake_invals_count; ++i) {
        fake_tlb_invalidate_t *inval = &g_fake_invals[i];
        UVM_TEST_PRINT(" range %d [0x%llx, 0x%llx)\n", i, inval->base, inval->base + inval->size);
    }

    return false;
}

static NV_STATUS test_page_tree_init(uvm_gpu_t *gpu, NvU32 big_page_size, uvm_page_tree_t *tree)
{
    return uvm_page_tree_init(gpu, big_page_size, UVM_APERTURE_SYS, tree);
}

static NV_STATUS test_page_tree_get_ptes(uvm_page_tree_t *tree, NvU32 page_size, NvU64 start, NvLength size, uvm_page_table_range_t *range)
{
    return uvm_page_tree_get_ptes(tree, page_size, start, size, UVM_PMM_ALLOC_FLAGS_NONE, range);
}

static NV_STATUS test_page_tree_get_entry(uvm_page_tree_t *tree, NvU32 page_size, NvU64 start, uvm_page_table_range_t *single)
{
    return uvm_page_tree_get_entry(tree, page_size, start, UVM_PMM_ALLOC_FLAGS_NONE, single);
}

NV_STATUS test_page_tree_alloc_table(uvm_page_tree_t *tree, NvU32 page_size,
        uvm_page_table_range_t *single, uvm_page_table_range_t *children)
{
    return uvm_page_tree_alloc_table(tree, page_size, UVM_PMM_ALLOC_FLAGS_NONE, single, children);
}

static bool assert_entry_no_invalidate(uvm_page_tree_t *tree, NvU32 page_size, NvU64 start)
{
    uvm_page_table_range_t entry;
    bool result = true;

    if (test_page_tree_get_entry(tree, page_size, start, &entry) != NV_OK)
        return false;

    if (!assert_no_invalidate())
        result = false;

    uvm_page_tree_put_ptes(tree, &entry);

    return assert_no_invalidate() && result;
}

static bool assert_entry_invalidate(uvm_page_tree_t *tree, NvU32 page_size, NvU64 start, NvU32 depth, bool membar)
{
    uvm_page_table_range_t entry;
    bool result = true;

    if (test_page_tree_get_entry(tree, page_size, start, &entry) != NV_OK)
        return false;

    if (!assert_and_reset_last_invalidate(depth, false))
        result = false;

    uvm_page_tree_put_ptes(tree, &entry);

    return assert_and_reset_last_invalidate(depth, membar) && result;
}

static NV_STATUS allocate_root(uvm_gpu_t *gpu)
{
    uvm_page_tree_t tree;
    MEM_NV_CHECK_RET(test_page_tree_init(gpu, BIG_PAGE_SIZE_PASCAL, &tree), NV_OK);
    uvm_page_tree_deinit(&tree);
    return NV_OK;
}

static NV_STATUS alloc_64k_memory(uvm_gpu_t *gpu)
{
    uvm_page_tree_t tree;
    uvm_page_table_range_t range;

    NvLength size = 64 * 1024;
    MEM_NV_CHECK_RET(test_page_tree_init(gpu, BIG_PAGE_SIZE_PASCAL, &tree), NV_OK);
    MEM_NV_CHECK_RET(test_page_tree_get_ptes(&tree, UVM_PAGE_SIZE_64K, 0, size, &range), NV_OK);
    TEST_CHECK_RET(range.entry_count == 1);
    TEST_CHECK_RET(range.table->depth == 4);
    TEST_CHECK_RET(range.start_index == 0);
    TEST_CHECK_RET(range.page_size == UVM_PAGE_SIZE_64K);
    TEST_CHECK_RET(tree.root->ref_count == 1);
    TEST_CHECK_RET(tree.root->entries[0]->ref_count == 1);
    TEST_CHECK_RET(tree.root->entries[0]->entries[0]->ref_count == 1);
    TEST_CHECK_RET(tree.root->entries[0]->entries[0]->entries[0]->ref_count == 1);
    TEST_CHECK_RET(tree.root->entries[0]->entries[0]->entries[0]->entries[0]->ref_count == 1);
    TEST_CHECK_RET(range.table == tree.root->entries[0]->entries[0]->entries[0]->entries[0]);
    uvm_page_tree_put_ptes(&tree, &range);
    UVM_ASSERT(tree.root->ref_count == 0);
    uvm_page_tree_deinit(&tree);
    return NV_OK;
}

static NV_STATUS alloc_adjacent_64k_memory(uvm_gpu_t *gpu)
{
    uvm_page_tree_t tree;
    uvm_page_table_range_t range1;
    uvm_page_table_range_t range2;

    NvLength size = 64 * 1024;
    MEM_NV_CHECK_RET(test_page_tree_init(gpu, BIG_PAGE_SIZE_PASCAL, &tree), NV_OK);
    MEM_NV_CHECK_RET(test_page_tree_get_ptes(&tree, UVM_PAGE_SIZE_64K, size, size, &range1), NV_OK);
    TEST_CHECK_RET(range1.entry_count == 1);

    MEM_NV_CHECK_RET(test_page_tree_get_ptes(&tree, UVM_PAGE_SIZE_64K, 0, size, &range2), NV_OK);
    TEST_CHECK_RET(range2.entry_count == 1);
    TEST_CHECK_RET(range1.table == range2.table);
    TEST_CHECK_RET(range1.table == tree.root->entries[0]->entries[0]->entries[0]->entries[0]);
    TEST_CHECK_RET(range1.start_index == 1);
    TEST_CHECK_RET(range2.start_index == 0);

    uvm_page_tree_put_ptes(&tree, &range1);
    uvm_page_tree_put_ptes(&tree, &range2);
    uvm_page_tree_deinit(&tree);
    return NV_OK;
}

static NV_STATUS alloc_adjacent_pde_64k_memory(uvm_gpu_t *gpu)
{
    uvm_page_tree_t tree;
    uvm_page_table_range_t range;
    uvm_page_table_range_t next_range;
    NvLength size = 64 * 1024;

    MEM_NV_CHECK_RET(test_page_tree_init(gpu, BIG_PAGE_SIZE_PASCAL, &tree), NV_OK);
    MEM_NV_CHECK_RET(test_page_tree_get_ptes(&tree, UVM_PAGE_SIZE_64K, 0, size, &range), NV_OK);
    TEST_CHECK_RET(range.entry_count == 1);
    MEM_NV_CHECK_RET(test_page_tree_get_ptes(&tree, UVM_PAGE_SIZE_64K, 2 * 1024 * 1024, size, &next_range), NV_OK);
    TEST_CHECK_RET(range.table == tree.root->entries[0]->entries[0]->entries[0]->entries[0]);
    TEST_CHECK_RET(next_range.table == tree.root->entries[0]->entries[0]->entries[0]->entries[2]);
    uvm_page_tree_put_ptes(&tree, &range);
    uvm_page_tree_put_ptes(&tree, &next_range);
    uvm_page_tree_deinit(&tree);
    return NV_OK;
}


static NV_STATUS alloc_nearby_pde_64k_memory(uvm_gpu_t *gpu)
{
    uvm_page_tree_t tree;
    uvm_page_table_range_t range;
    uvm_page_table_range_t next_range;
    NvLength size = 64 * 1024;
    MEM_NV_CHECK_RET(test_page_tree_init(gpu, BIG_PAGE_SIZE_PASCAL, &tree), NV_OK);
    MEM_NV_CHECK_RET(test_page_tree_get_ptes(&tree, UVM_PAGE_SIZE_64K, 6 * 1024 * 1024, size, &range), NV_OK);
    TEST_CHECK_RET(range.entry_count == 1);
    MEM_NV_CHECK_RET(test_page_tree_get_ptes(&tree, UVM_PAGE_SIZE_64K, 2 * 1024 * 1024, size, &next_range), NV_OK);
    TEST_CHECK_RET(range.table == tree.root->entries[0]->entries[0]->entries[0]->entries[6]);
    TEST_CHECK_RET(next_range.table == tree.root->entries[0]->entries[0]->entries[0]->entries[2]);
    uvm_page_tree_put_ptes(&tree, &range);
    uvm_page_tree_put_ptes(&tree, &next_range);
    uvm_page_tree_deinit(&tree);
    return NV_OK;
}

static NV_STATUS allocate_then_free_all_16_64k(uvm_gpu_t *gpu)
{
    uvm_page_tree_t tree;
    uvm_page_table_range_t range[16];

    NvLength size = 64 * 1024;
    NvLength stride = 32 * size;
    NvLength start = stride * 256;
    int i;

    MEM_NV_CHECK_RET(test_page_tree_init(gpu, BIG_PAGE_SIZE_PASCAL, &tree), NV_OK);

    for (i = 0; i < 16; i++)
        MEM_NV_CHECK_RET(test_page_tree_get_ptes(&tree, UVM_PAGE_SIZE_64K, start + i * stride, size, range + i), NV_OK);

    TEST_CHECK_RET(tree.root->entries[0]->entries[0]->entries[1]->ref_count == 16);

    for (i = 0; i < 16; i++)
        uvm_page_tree_put_ptes(&tree, range + i);

    UVM_ASSERT(tree.root->ref_count == 0);
    uvm_page_tree_deinit(&tree);
    return NV_OK;
}

static NV_STATUS allocate_then_free_8_8_64k(uvm_gpu_t *gpu)
{
    uvm_page_tree_t tree;
    uvm_page_table_range_t range[16];

    NvLength size = 64 * 1024;
    NvLength stride = 32 * size;
    NvLength start = stride * 248 + 256LL * 1024 * 1024 * 1024 + (1LL << 47);
    int i;

    MEM_NV_CHECK_RET(test_page_tree_init(gpu, BIG_PAGE_SIZE_PASCAL, &tree), NV_OK);

    for (i = 0; i < 16; i++)
        MEM_NV_CHECK_RET(test_page_tree_get_ptes(&tree, UVM_PAGE_SIZE_64K, start + i * stride , size, range + i), NV_OK);

    TEST_CHECK_RET(tree.root->entries[1]->entries[1]->entries[0]->ref_count == 8);
    TEST_CHECK_RET(tree.root->entries[1]->entries[1]->entries[1]->ref_count == 8);

    for (i = 0; i < 16; i++)
        uvm_page_tree_put_ptes(&tree, range + i);

    UVM_ASSERT(tree.root->ref_count == 0);
    uvm_page_tree_deinit(&tree);
    return NV_OK;
}

static NV_STATUS get_single_page_2m(uvm_gpu_t *gpu)
{
    uvm_page_tree_t tree;
    uvm_page_table_range_t range;

    // use a start address not at the beginning of a PDE3 entry's range
    NvU64 start = 34983UL * (1 << 21);
    NvLength size = 1 << 21;

    MEM_NV_CHECK_RET(test_page_tree_init(gpu, BIG_PAGE_SIZE_PASCAL, &tree), NV_OK);
    MEM_NV_CHECK_RET(test_page_tree_get_ptes(&tree, UVM_PAGE_SIZE_2M, start, size, &range), NV_OK);

    TEST_CHECK_RET(range.entry_count == 1);
    TEST_CHECK_RET(range.table->depth == 3);
    TEST_CHECK_RET(range.page_size == UVM_PAGE_SIZE_2M);

    uvm_page_tree_put_ptes(&tree, &range);
    TEST_CHECK_RET(tree.root->ref_count == 0);
    uvm_page_tree_deinit(&tree);
    return NV_OK;
}


static NV_STATUS get_entire_table_4k(uvm_gpu_t *gpu)
{
    uvm_page_tree_t tree;
    uvm_page_table_range_t range;

    NvU64 start = 1UL << 47;

    NvLength size = 1 << 21;

    MEM_NV_CHECK_RET(test_page_tree_init(gpu, BIG_PAGE_SIZE_PASCAL, &tree), NV_OK);
    MEM_NV_CHECK_RET(test_page_tree_get_ptes(&tree, UVM_PAGE_SIZE_4K, start, size, &range), NV_OK);

    TEST_CHECK_RET(range.table == tree.root->entries[1]->entries[0]->entries[0]->entries[1]);
    TEST_CHECK_RET(range.entry_count == 512);
    TEST_CHECK_RET(range.table->depth == 4);
    TEST_CHECK_RET(range.page_size == UVM_PAGE_SIZE_4K);
    TEST_CHECK_RET(tree.root->ref_count == 1);

    uvm_page_tree_put_ptes(&tree, &range);
    uvm_page_tree_deinit(&tree);
    return NV_OK;
}

static NV_STATUS split_4k_from_2m(uvm_gpu_t *gpu)
{
    uvm_page_tree_t tree;
    uvm_page_table_range_t range_2m;
    uvm_page_table_range_t range_adj;
    uvm_page_table_range_t range_4k;
    uvm_page_table_range_t range_64k;

    NvU64 start = 1UL << 48;
    NvLength size = 1 << 21;

    MEM_NV_CHECK_RET(test_page_tree_init(gpu, BIG_PAGE_SIZE_PASCAL, &tree), NV_OK);
    MEM_NV_CHECK_RET(test_page_tree_get_ptes(&tree, UVM_PAGE_SIZE_2M, start, size, &range_2m), NV_OK);
    MEM_NV_CHECK_RET(test_page_tree_get_ptes(&tree, UVM_PAGE_SIZE_2M, start + size, size, &range_adj), NV_OK);

    TEST_CHECK_RET(range_2m.entry_count == 1);
    TEST_CHECK_RET(range_2m.table->depth == 3);
    TEST_CHECK_RET(range_adj.entry_count == 1);
    TEST_CHECK_RET(range_adj.table->depth == 3);

    // Need to release the 2 MB page so that the reference count is right.
    uvm_page_tree_put_ptes(&tree, &range_2m);
    MEM_NV_CHECK_RET(test_page_tree_get_ptes(&tree, UVM_PAGE_SIZE_4K, start, 64 * 1024, &range_4k), NV_OK);
    MEM_NV_CHECK_RET(test_page_tree_get_ptes(&tree, UVM_PAGE_SIZE_64K, start + 64 * 1024, size - 64 * 1024, &range_64k), NV_OK);

    TEST_CHECK_RET(range_4k.entry_count == 16);
    TEST_CHECK_RET(range_4k.table->depth == 4);
    TEST_CHECK_RET(range_4k.table == tree.root->entries[2]->entries[0]->entries[0]->entries[1]);
    TEST_CHECK_RET(range_4k.start_index == 0);

    TEST_CHECK_RET(range_64k.entry_count == 31);
    TEST_CHECK_RET(range_64k.table == tree.root->entries[2]->entries[0]->entries[0]->entries[0]);
    TEST_CHECK_RET(range_64k.start_index == 1);

    // Free everything
    uvm_page_tree_put_ptes(&tree, &range_adj);
    uvm_page_tree_put_ptes(&tree, &range_4k);
    uvm_page_tree_put_ptes(&tree, &range_64k);

    uvm_page_tree_deinit(&tree);
    return NV_OK;
}

static NV_STATUS get_512mb_range(uvm_gpu_t *gpu)
{
    uvm_page_tree_t tree;
    uvm_page_table_range_t range;

    NvU64 start = 512 * (1 << 20);
    NvU64 size = start;

    MEM_NV_CHECK_RET(test_page_tree_init(gpu, BIG_PAGE_SIZE_PASCAL, &tree), NV_OK);
    MEM_NV_CHECK_RET(test_page_tree_get_ptes(&tree, UVM_PAGE_SIZE_2M, start, size, &range), NV_OK);
    TEST_CHECK_RET(range.entry_count == 256);
    TEST_CHECK_RET(range.table->depth == 3);
    TEST_CHECK_RET(range.start_index == 0);
    uvm_page_tree_put_ptes(&tree, &range);
    uvm_page_tree_deinit(&tree);
    return NV_OK;
}

static NV_STATUS get_two_free_apart(uvm_gpu_t *gpu)
{
    uvm_page_tree_t tree;
    uvm_page_table_range_t range1;
    uvm_page_table_range_t range2;

    NvLength size = 1024 * 1024;
    MEM_NV_CHECK_RET(test_page_tree_init(gpu, BIG_PAGE_SIZE_PASCAL, &tree), NV_OK);
    MEM_NV_CHECK_RET(test_page_tree_get_ptes(&tree, UVM_PAGE_SIZE_4K, size, size, &range1), NV_OK);
    TEST_CHECK_RET(range1.entry_count == 256);
    TEST_CHECK_RET(range1.table->ref_count == 256);

    MEM_NV_CHECK_RET(test_page_tree_get_ptes(&tree, UVM_PAGE_SIZE_4K, 0, size, &range2), NV_OK);
    TEST_CHECK_RET(range2.entry_count == 256);
    TEST_CHECK_RET(range2.table->ref_count == 512);
    TEST_CHECK_RET(range1.table == range2.table);
    // 4k page is second entry in a dual PDE
    TEST_CHECK_RET(range1.table == tree.root->entries[0]->entries[0]->entries[0]->entries[1]);
    TEST_CHECK_RET(range1.start_index == 256);
    TEST_CHECK_RET(range2.start_index == 0);

    uvm_page_tree_put_ptes(&tree, &range1);
    TEST_CHECK_RET(range2.table->ref_count == 256);
    TEST_CHECK_RET(range2.table == tree.root->entries[0]->entries[0]->entries[0]->entries[1]);
    uvm_page_tree_put_ptes(&tree, &range2);
    uvm_page_tree_deinit(&tree);
    return NV_OK;

}

static NV_STATUS get_overlapping_dual_pdes(uvm_gpu_t *gpu)
{
    uvm_page_tree_t tree;
    uvm_page_table_range_t range4k;
    uvm_page_table_range_t range64k;

    NvLength size = 1024 * 1024;
    MEM_NV_CHECK_RET(test_page_tree_init(gpu, BIG_PAGE_SIZE_PASCAL, &tree), NV_OK);
    MEM_NV_CHECK_RET(test_page_tree_get_ptes(&tree, UVM_PAGE_SIZE_4K, size, size, &range4k), NV_OK);
    TEST_CHECK_RET(range4k.entry_count == 256);
    TEST_CHECK_RET(range4k.table->ref_count == 256);

    MEM_NV_CHECK_RET(test_page_tree_get_ptes(&tree, UVM_PAGE_SIZE_64K, size, size, &range64k), NV_OK);
    TEST_CHECK_RET(range64k.entry_count == 16);
    TEST_CHECK_RET(range64k.table->ref_count == 16);
    // 4k page is second entry in a dual PDE
    TEST_CHECK_RET(range64k.table == tree.root->entries[0]->entries[0]->entries[0]->entries[0]);
    TEST_CHECK_RET(range64k.start_index == 16);
    TEST_CHECK_RET(range4k.start_index == 256);

    uvm_page_tree_put_ptes(&tree, &range64k);
    TEST_CHECK_RET(range4k.table->ref_count == 256);
    TEST_CHECK_RET(range4k.table == tree.root->entries[0]->entries[0]->entries[0]->entries[1]);
    uvm_page_tree_put_ptes(&tree, &range4k);

    UVM_ASSERT(tree.root->ref_count == 0);
    uvm_page_tree_deinit(&tree);
    return NV_OK;
}

static NV_STATUS split_and_free(uvm_gpu_t *gpu)
{
    uvm_page_tree_t tree;
    uvm_page_table_range_t range;

    // 45 = 1 + 2 + 3 + ... + 9
    NvU64 size = 45 * (2 << 20);
    NvU32 i;
    NvU32 sum = 0;

    MEM_NV_CHECK_RET(test_page_tree_init(gpu, BIG_PAGE_SIZE_PASCAL, &tree), NV_OK);
    MEM_NV_CHECK_RET(test_page_tree_get_ptes(&tree, UVM_PAGE_SIZE_2M, 0, size, &range), NV_OK);
    TEST_CHECK_RET(range.entry_count == 45);
    TEST_CHECK_RET(range.table->depth == 3);
    TEST_CHECK_RET(range.start_index == 0);

    for (i = 1; i <= 9; i++) {
        range.entry_count = i;
        range.start_index = sum;
        uvm_page_tree_put_ptes(&tree, &range);
        sum += i;
    }
    UVM_ASSERT(tree.root->ref_count == 0);
    uvm_page_tree_deinit(&tree);
    return NV_OK;
}

static NV_STATUS check_sizes(uvm_gpu_t *gpu)
{
    NvU32 user_sizes = UVM_PAGE_SIZE_2M;
    NvU32 kernel_sizes = UVM_PAGE_SIZE_4K | 256;

    if (UVM_PAGE_SIZE_64K >= PAGE_SIZE)
        user_sizes |= UVM_PAGE_SIZE_64K;
    if (UVM_PAGE_SIZE_4K >= PAGE_SIZE)
        user_sizes |= UVM_PAGE_SIZE_4K;

    TEST_CHECK_RET(uvm_mmu_user_chunk_sizes(gpu) == user_sizes);
    TEST_CHECK_RET(uvm_mmu_kernel_chunk_sizes(gpu) == kernel_sizes);
    return NV_OK;
}

static NV_STATUS fast_split_normal(uvm_gpu_t *gpu)
{
    uvm_page_tree_t tree;
    uvm_page_table_range_t parent;
    uvm_page_table_range_t child_4k;
    uvm_page_table_range_t child_64k;

    NvU64 start = 0;

    MEM_NV_CHECK_RET(test_page_tree_init(gpu, BIG_PAGE_SIZE_PASCAL, &tree), NV_OK);
    MEM_NV_CHECK_RET(test_page_tree_get_entry(&tree, UVM_PAGE_SIZE_2M, start, &parent), NV_OK);
    TEST_CHECK_RET(parent.entry_count == 1);
    TEST_CHECK_RET(parent.table->depth == 3);
    TEST_CHECK_RET(parent.page_size == UVM_PAGE_SIZE_2M);

    MEM_NV_CHECK_RET(test_page_tree_alloc_table(&tree, UVM_PAGE_SIZE_4K, &parent, &child_4k), NV_OK);
    TEST_CHECK_RET(child_4k.table->host_parent == parent.table);
    TEST_CHECK_RET(child_4k.entry_count == 512);
    TEST_CHECK_RET(child_4k.page_size == UVM_PAGE_SIZE_4K);
    TEST_CHECK_RET(parent.table->ref_count == 2);
    TEST_CHECK_RET(parent.table->entries[1] == child_4k.table);

    MEM_NV_CHECK_RET(test_page_tree_alloc_table(&tree, UVM_PAGE_SIZE_64K, &parent, &child_64k), NV_OK);
    TEST_CHECK_RET(child_64k.table->host_parent == parent.table);
    TEST_CHECK_RET(child_64k.entry_count == 32);
    TEST_CHECK_RET(child_64k.page_size == UVM_PAGE_SIZE_64K);
    TEST_CHECK_RET(parent.table->ref_count == 3);
    TEST_CHECK_RET(parent.table->entries[0] == child_64k.table);

    uvm_page_tree_put_ptes(&tree, &parent);
    TEST_CHECK_RET(parent.table->ref_count == 2);
    uvm_page_tree_put_ptes(&tree, &child_4k);
    TEST_CHECK_RET(parent.table->entries[1] == NULL);
    uvm_page_tree_put_ptes(&tree, &child_64k);
    uvm_page_tree_deinit(&tree);
    return NV_OK;
}

static NV_STATUS fast_split_double_backoff(uvm_gpu_t *gpu)
{
    uvm_page_tree_t tree;
    uvm_page_table_range_t parent;
    uvm_page_table_range_t child_4k;
    uvm_page_table_range_t child_64k;
    uvm_page_table_range_t child_64k2;

    NvU64 start = 0;

    MEM_NV_CHECK_RET(test_page_tree_init(gpu, BIG_PAGE_SIZE_PASCAL, &tree), NV_OK);
    MEM_NV_CHECK_RET(test_page_tree_get_entry(&tree, UVM_PAGE_SIZE_2M, start, &parent), NV_OK);
    TEST_CHECK_RET(parent.entry_count == 1);
    TEST_CHECK_RET(parent.table->depth == 3);
    TEST_CHECK_RET(parent.page_size == UVM_PAGE_SIZE_2M);

    MEM_NV_CHECK_RET(test_page_tree_alloc_table(&tree, UVM_PAGE_SIZE_4K, &parent, &child_4k), NV_OK);
    TEST_CHECK_RET(child_4k.table->host_parent == parent.table);
    TEST_CHECK_RET(child_4k.entry_count == 512);
    TEST_CHECK_RET(child_4k.page_size == UVM_PAGE_SIZE_4K);
    TEST_CHECK_RET(parent.table->ref_count == 2);
    TEST_CHECK_RET(parent.table->entries[1] == child_4k.table);

    MEM_NV_CHECK_RET(test_page_tree_alloc_table(&tree, UVM_PAGE_SIZE_64K, &parent, &child_64k), NV_OK);
    TEST_CHECK_RET(child_64k.table->host_parent == parent.table);
    TEST_CHECK_RET(child_64k.entry_count == 32);
    TEST_CHECK_RET(child_64k.page_size == UVM_PAGE_SIZE_64K);
    TEST_CHECK_RET(parent.table->ref_count == 3);
    TEST_CHECK_RET(parent.table->entries[0] == child_64k.table);

    MEM_NV_CHECK_RET(test_page_tree_alloc_table(&tree, UVM_PAGE_SIZE_64K, &parent, &child_64k2), NV_OK);
    TEST_CHECK_RET(child_64k2.table->host_parent == parent.table);
    TEST_CHECK_RET(child_64k2.entry_count == 32);
    TEST_CHECK_RET(child_64k2.table->ref_count == 64);
    TEST_CHECK_RET(child_64k2.page_size == UVM_PAGE_SIZE_64K);
    TEST_CHECK_RET(child_64k2.table == child_64k.table);
    TEST_CHECK_RET(parent.table->ref_count == 3);
    TEST_CHECK_RET(parent.table->entries[0] == child_64k2.table);

    uvm_page_tree_put_ptes(&tree, &child_64k2);

    uvm_page_tree_put_ptes(&tree, &parent);
    TEST_CHECK_RET(parent.table->ref_count == 2);
    uvm_page_tree_put_ptes(&tree, &child_4k);
    TEST_CHECK_RET(parent.table->entries[1] == NULL);
    uvm_page_tree_put_ptes(&tree, &child_64k);
    uvm_page_tree_deinit(&tree);
    return NV_OK;
}


static NV_STATUS test_pascal_tlb_invalidates(uvm_gpu_t *gpu)
{
    NV_STATUS status = NV_OK;
    uvm_page_tree_t tree;
    uvm_page_table_range_t entries[5];
    int i;

    // Depth 4
    NvU64 extent_pte = UVM_PAGE_SIZE_2M;
    // Depth 3
    NvU64 extent_pde0 = extent_pte * (1ull << 8);
    // Depth 2
    NvU64 extent_pde1 = extent_pde0 * (1ull << 9);
    // Depth 1
    NvU64 extent_pde2 = extent_pde1 * (1ull << 9);

    MEM_NV_CHECK_RET(test_page_tree_init(gpu, BIG_PAGE_SIZE_PASCAL, &tree), NV_OK);

    fake_tlb_invals_enable();

    TEST_CHECK_RET(assert_entry_invalidate(&tree, UVM_PAGE_SIZE_4K, 0, 0, true));
    TEST_CHECK_RET(assert_entry_invalidate(&tree, UVM_PAGE_SIZE_4K, 0, 0, true));

    TEST_CHECK_RET(test_page_tree_get_entry(&tree, UVM_PAGE_SIZE_4K, 0, &entries[0]) == NV_OK);
    TEST_CHECK_RET(assert_and_reset_last_invalidate(0, false));

    TEST_CHECK_RET(assert_entry_no_invalidate(&tree, UVM_PAGE_SIZE_4K, extent_pte - UVM_PAGE_SIZE_4K));

    TEST_CHECK_RET(assert_entry_invalidate(&tree, UVM_PAGE_SIZE_64K, 0, 3, true));

    TEST_CHECK_RET(test_page_tree_get_entry(&tree, UVM_PAGE_SIZE_64K, 0, &entries[1]) == NV_OK);
    TEST_CHECK_RET(assert_and_reset_last_invalidate(3, false));

    TEST_CHECK_RET(test_page_tree_get_entry(&tree, UVM_PAGE_SIZE_4K, extent_pde0, &entries[2]) == NV_OK);
    TEST_CHECK_RET(assert_and_reset_last_invalidate(2, false));

    TEST_CHECK_RET(test_page_tree_get_entry(&tree, UVM_PAGE_SIZE_4K, extent_pde1, &entries[3]) == NV_OK);
    TEST_CHECK_RET(assert_and_reset_last_invalidate(1, false));

    TEST_CHECK_RET(test_page_tree_get_entry(&tree, UVM_PAGE_SIZE_4K, extent_pde2, &entries[4]) == NV_OK);
    TEST_CHECK_RET(assert_and_reset_last_invalidate(0, false));

    for (i = 4; i > 1; --i) {
        uvm_page_tree_put_ptes(&tree, &entries[i]);
        TEST_CHECK_RET(assert_and_reset_last_invalidate(4 - i, true));
    }

    uvm_page_tree_put_ptes(&tree, &entries[0]);
    TEST_CHECK_RET(assert_and_reset_last_invalidate(3, true));

    uvm_page_tree_put_ptes(&tree, &entries[1]);
    TEST_CHECK_RET(assert_and_reset_last_invalidate(0, true));

    fake_tlb_invals_disable();

    uvm_page_tree_deinit(&tree);
    return status;
}

static NV_STATUS test_tlb_batch_invalidates_case(uvm_page_tree_t *tree, NvU64 base, NvU64 size, NvU32 min_page_size, NvU32 max_page_size)
{
    NV_STATUS status = NV_OK;
    uvm_push_t push;
    uvm_tlb_batch_t batch;
    uvm_gpu_t *gpu = tree->gpu;
    int i, j;

    MEM_NV_CHECK_RET(uvm_push_begin_fake(gpu, &push), NV_OK);

    for (i = 1; i < 10; ++i) {
        // If invalidate all ends up being used, the expected depth is the
        // minimum depth across all the ranges. Start off with the min page size
        // as that's the deepest.
        NvU32 expected_inval_all_depth = tree->hal->page_table_depth(min_page_size);
        NvU32 total_pages = 0;

        fake_tlb_invals_enable();

        uvm_tlb_batch_begin(tree, &batch);

        for (j = 0; j < i; ++j) {
            NvU32 used_max_page_size = (j & 1) ? max_page_size : min_page_size;
            NvU32 expected_range_depth = tree->hal->page_table_depth(used_max_page_size);
            expected_inval_all_depth = min(expected_inval_all_depth, expected_range_depth);
            uvm_tlb_batch_invalidate(&batch, base + j * 2 * size, size, min_page_size | used_max_page_size, UVM_MEMBAR_NONE);
            total_pages += size / min_page_size;
        }

        uvm_tlb_batch_end(&batch, &push, UVM_MEMBAR_NONE);

        for (j = 0; j < i; ++j) {
            NvU32 used_max_page_size = (j & 1) ? max_page_size : min_page_size;
            NvU32 expected_range_depth = tree->hal->page_table_depth(used_max_page_size);
            bool allow_inval_all = (total_pages > gpu->tlb_batch.max_pages) ||
                                   !gpu->tlb_batch.va_invalidate_supported ||
                                   (i > UVM_TLB_BATCH_MAX_ENTRIES);
            TEST_CHECK_RET(assert_invalidate_range(base + j * 2 * size, size, min_page_size,
                    allow_inval_all, expected_range_depth, expected_inval_all_depth, false));
        }

        fake_tlb_invals_disable();
    }

    uvm_push_end_fake(&push);

    return status;
}

static NV_STATUS test_pascal_tlb_batch_invalidates(uvm_gpu_t *gpu)
{
    NV_STATUS status = NV_OK;
    uvm_page_tree_t tree;

    NvU32 min_index;
    NvU32 max_index;
    NvU32 size_index;

    static const NvU32 page_sizes[] = { UVM_PAGE_SIZE_4K, UVM_PAGE_SIZE_64K, UVM_PAGE_SIZE_2M };
    static const NvU32 sizes_in_max_pages[] = { 1, 2, 3, 5, 7, 32 };

    MEM_NV_CHECK_RET(test_page_tree_init(gpu, BIG_PAGE_SIZE_PASCAL, &tree), NV_OK);

    for (min_index = 0; min_index < ARRAY_SIZE(page_sizes); ++min_index) {
        for (max_index = min_index; max_index < ARRAY_SIZE(page_sizes); ++max_index) {
            for (size_index = 0; size_index < ARRAY_SIZE(sizes_in_max_pages); ++size_index) {
                NvU32 min_page_size = page_sizes[min_index];
                NvU32 max_page_size = page_sizes[max_index];
                NvU32 size = sizes_in_max_pages[size_index] * max_page_size;

                TEST_CHECK_GOTO(test_tlb_batch_invalidates_case(&tree, min_index * max_page_size, size, min_page_size, max_page_size) == NV_OK, done);
            }
        }
    }

done:
    uvm_page_tree_deinit(&tree);
    return status;
}

typedef struct
{
    NvU64 count;
    NV_STATUS status;
} test_pte_maker_data_t;

static NvU64 test_range_vec_pte_maker(uvm_page_table_range_vec_t *range_vec, NvU64 offset, void *void_data)
{
    test_pte_maker_data_t *data = (test_pte_maker_data_t *)void_data;
    if (range_vec->page_size * data->count != offset) {
        data->status = NV_ERR_INVALID_STATE;
    }
    ++data->count;
    return range_vec->size + offset;
}

static bool assert_range_vec_ptes(uvm_page_table_range_vec_t *range_vec, bool expecting_cleared)
{
    NvU32 i;
    NvU32 entry;
    NvU64 offset = 0;

    for (i = 0; i < range_vec->range_count; ++i) {
        uvm_page_table_range_t *range = &range_vec->ranges[i];

        for (entry = 0; entry < range->entry_count; ++entry) {
            uvm_gpu_phys_address_t pte_addr = uvm_page_table_range_entry_address(range_vec->tree, range, entry);
            NvU64 *pte = (NvU64*)phys_to_virt(pte_addr.address);
            NvU64 expected_pte = expecting_cleared ? 0 : range_vec->size + offset;
            if (*pte != expected_pte) {
                UVM_TEST_PRINT("PTE is 0x%llx instead of 0x%llx for offset 0x%llx within range [0x%llx, 0x%llx)\n",
                        *pte, expected_pte, offset, range_vec->start, range_vec->size);
                return false;
            }
            offset += range_vec->page_size;
        }
    }

    return true;
}

static NV_STATUS test_range_vec_write_ptes(uvm_page_table_range_vec_t *range_vec, uvm_membar_t membar)
{
    test_pte_maker_data_t data = { 0 };
    NvU32 page_table_depth = range_vec->tree->hal->page_table_depth(range_vec->page_size);

    fake_tlb_invals_enable();

    TEST_CHECK_RET(uvm_page_table_range_vec_write_ptes(range_vec, membar, test_range_vec_pte_maker, &data) == NV_OK);
    TEST_CHECK_RET(data.status == NV_OK);
    TEST_CHECK_RET(data.count == range_vec->size / range_vec->page_size);
    TEST_CHECK_RET(assert_invalidate_range_specific(g_last_fake_inval,
            range_vec->start, range_vec->size, range_vec->page_size, page_table_depth, membar != UVM_MEMBAR_NONE));
    TEST_CHECK_RET(assert_range_vec_ptes(range_vec, false));

    fake_tlb_invals_disable();

    return NV_OK;
}

static NV_STATUS test_range_vec_clear_ptes(uvm_page_table_range_vec_t *range_vec, uvm_membar_t membar)
{
    NvU32 page_table_depth = range_vec->tree->hal->page_table_depth(range_vec->page_size);

    fake_tlb_invals_enable();

    TEST_CHECK_RET(uvm_page_table_range_vec_clear_ptes(range_vec, membar) == NV_OK);
    TEST_CHECK_RET(assert_and_reset_last_invalidate(page_table_depth, membar != UVM_MEMBAR_NONE));
    TEST_CHECK_RET(assert_range_vec_ptes(range_vec, true));

    fake_tlb_invals_disable();

    return NV_OK;
}

static NV_STATUS test_range_vec_create(uvm_page_tree_t *tree, NvU64 start, NvU64 size, NvU32 page_size, uvm_page_table_range_vec_t **range_vec_out)
{
    uvm_page_table_range_vec_t *range_vec;

    TEST_CHECK_RET(uvm_page_table_range_vec_create(tree, start, size, page_size, &range_vec) == NV_OK);
    TEST_CHECK_RET(test_range_vec_write_ptes(range_vec, UVM_MEMBAR_NONE) == NV_OK);
    TEST_CHECK_RET(test_range_vec_clear_ptes(range_vec, UVM_MEMBAR_GPU) == NV_OK);
    TEST_CHECK_RET(test_range_vec_write_ptes(range_vec, UVM_MEMBAR_NONE) == NV_OK);
    TEST_CHECK_RET(test_range_vec_write_ptes(range_vec, UVM_MEMBAR_SYS) == NV_OK);
    TEST_CHECK_RET(test_range_vec_clear_ptes(range_vec, UVM_MEMBAR_SYS) == NV_OK);

    *range_vec_out = range_vec;

    return NV_OK;
}

// Test page table range vector APIs.
// Notably the test leaks the page_tree and range_vec on error as it's hard to
// clean up on failure and the destructors would likely assert.
static NV_STATUS test_range_vec(uvm_gpu_t *gpu, NvU32 big_page_size, NvU32 page_size)
{
    NV_STATUS status = NV_OK;
    uvm_page_tree_t tree;
    uvm_page_table_range_vec_t *range_vec;
    NvU64 pde_coverage;
    NvU64 page_table_entries;
    NvU64 start;
    NvU64 size;
    NvU32 i;
    NvU32 offsets[4];

    MEM_NV_CHECK_RET(test_page_tree_init(gpu, big_page_size, &tree), NV_OK);

    pde_coverage = uvm_mmu_pde_coverage(&tree, page_size);
    page_table_entries = pde_coverage / page_size;

    // Interesting page offsets
    offsets[0] = 0;
    offsets[1] = 1;
    offsets[2] = page_table_entries / 2;
    offsets[3] = page_table_entries - 1;

    // A single page
    size = page_size;
    for (i = 0; i < ARRAY_SIZE(offsets); ++i) {
        NvU32 offset = offsets[i];
        start = offset * page_size;
        TEST_CHECK_RET(test_range_vec_create(&tree, start, size, page_size, &range_vec) == NV_OK);
        TEST_CHECK_RET(range_vec->range_count == 1);
        TEST_CHECK_RET(range_vec->ranges[0].start_index == offset);
        TEST_CHECK_RET(range_vec->ranges[0].entry_count == 1);
        uvm_page_table_range_vec_destroy(range_vec);
    }

    // A full page table extent offset by a non-zero multiple of page_size
    size = pde_coverage;
    for (i = 1; i < ARRAY_SIZE(offsets); ++i) {
        NvU32 offset = offsets[i];
        start = pde_coverage + offset * page_size;
        TEST_CHECK_RET(test_range_vec_create(&tree, start, size, page_size, &range_vec) == NV_OK);
        TEST_CHECK_RET(range_vec->range_count == 2);
        TEST_CHECK_RET(range_vec->ranges[0].start_index == offset);
        TEST_CHECK_RET(range_vec->ranges[0].entry_count == page_table_entries - offset);
        TEST_CHECK_RET(range_vec->ranges[1].start_index == 0);
        TEST_CHECK_RET(range_vec->ranges[1].entry_count == offset);
        uvm_page_table_range_vec_destroy(range_vec);
    }

    // One page on each side of the page table extent boundary
    start = pde_coverage - page_size;
    size = 2 * page_size;
    TEST_CHECK_RET(test_range_vec_create(&tree, start, size, page_size, &range_vec) == NV_OK);
    TEST_CHECK_RET(range_vec->range_count == 2);
    TEST_CHECK_RET(range_vec->ranges[0].entry_count == 1);
    TEST_CHECK_RET(range_vec->ranges[1].entry_count == 1);
    uvm_page_table_range_vec_destroy(range_vec);

    // Two pages on each side of the page table extent boundary and a full page table extent in between
    start = pde_coverage - 2 * page_size;
    size = pde_coverage + 4 * page_size;
    TEST_CHECK_RET(test_range_vec_create(&tree, start, size, page_size, &range_vec) == NV_OK);
    TEST_CHECK_RET(range_vec->range_count == 3);
    TEST_CHECK_RET(range_vec->ranges[0].entry_count == 2);
    TEST_CHECK_RET(range_vec->ranges[1].start_index == 0);
    TEST_CHECK_RET(range_vec->ranges[1].entry_count == page_table_entries);
    TEST_CHECK_RET(range_vec->ranges[2].entry_count == 2);
    uvm_page_table_range_vec_destroy(range_vec);

    uvm_page_tree_deinit(&tree);
    return status;
}

static NV_STATUS alloc_64k_memory_kepler(uvm_gpu_t *gpu)
{
    uvm_page_tree_t tree;
    uvm_page_table_range_t range;

    NvLength size = 64 * 1024;
    MEM_NV_CHECK_RET(test_page_tree_init(gpu, UVM_PAGE_SIZE_64K, &tree), NV_OK);
    MEM_NV_CHECK_RET(test_page_tree_get_ptes(&tree, UVM_PAGE_SIZE_64K, 0, size, &range), NV_OK);
    TEST_CHECK_RET(range.entry_count == 1);
    TEST_CHECK_RET(range.table->depth == 1);
    TEST_CHECK_RET(range.start_index == 0);
    TEST_CHECK_RET(tree.root->ref_count == 1);
    TEST_CHECK_RET(tree.root->entries[0]->ref_count == 1);
    TEST_CHECK_RET(range.table == tree.root->entries[0]);
    uvm_page_tree_put_ptes(&tree, &range);
    UVM_ASSERT(tree.root->ref_count == 0);
    uvm_page_tree_deinit(&tree);
    return NV_OK;
}

static NV_STATUS alloc_128k_memory_kepler(uvm_gpu_t *gpu)
{
    uvm_page_tree_t tree;
    uvm_page_table_range_t range;
    NvLength size = 128 * 1024;

    // 64k big page mode
    MEM_NV_CHECK_RET(test_page_tree_init(gpu, UVM_PAGE_SIZE_64K, &tree), NV_OK);
    MEM_NV_CHECK_RET(test_page_tree_get_ptes(&tree, UVM_PAGE_SIZE_64K, 0, size, &range), NV_OK);
    TEST_CHECK_RET(range.entry_count == 2);
    TEST_CHECK_RET(range.table->depth == 1);
    TEST_CHECK_RET(range.start_index == 0);
    TEST_CHECK_RET(range.page_size == UVM_PAGE_SIZE_64K);
    TEST_CHECK_RET(tree.root->ref_count == 1);
    TEST_CHECK_RET(tree.root->entries[0]->ref_count == 2);
    TEST_CHECK_RET(range.table == tree.root->entries[0]);
    uvm_page_tree_put_ptes(&tree, &range);
    UVM_ASSERT(tree.root->ref_count == 0);
    uvm_page_tree_deinit(&tree);

    // 128k big page mode
    MEM_NV_CHECK_RET(test_page_tree_init(gpu, UVM_PAGE_SIZE_128K, &tree), NV_OK);
    MEM_NV_CHECK_RET(test_page_tree_get_ptes(&tree, UVM_PAGE_SIZE_128K, 0, size, &range), NV_OK);
    TEST_CHECK_RET(range.entry_count == 1);
    TEST_CHECK_RET(range.table->depth == 1);
    TEST_CHECK_RET(range.start_index == 0);
    TEST_CHECK_RET(tree.root->ref_count == 1);
    TEST_CHECK_RET(range.page_size == UVM_PAGE_SIZE_128K);
    TEST_CHECK_RET(tree.root->entries[0]->ref_count == 1);
    TEST_CHECK_RET(range.table == tree.root->entries[0]);
    uvm_page_tree_put_ptes(&tree, &range);
    UVM_ASSERT(tree.root->ref_count == 0);
    uvm_page_tree_deinit(&tree);

    return NV_OK;

}

static uvm_mmu_page_table_alloc_t fake_table_alloc(uvm_aperture_t aperture, NvU64 address)
{
    return (uvm_mmu_page_table_alloc_t){.addr = uvm_gpu_phys_address(aperture, address) };
}

static NV_STATUS entry_test_pascal(uvm_gpu_t *gpu)
{
    static const NvU32 page_sizes[] = {UVM_PAGE_SIZE_4K, UVM_PAGE_SIZE_64K, UVM_PAGE_SIZE_2M};
    NvU64 pde_bits[2];
    size_t i;
    uvm_mmu_page_table_alloc_t *phys_allocs[2] = {NULL, NULL};
    uvm_mmu_page_table_alloc_t alloc_sys = fake_table_alloc(UVM_APERTURE_SYS, 0x399999999999000LL);
    uvm_mmu_page_table_alloc_t alloc_vid = fake_table_alloc(UVM_APERTURE_VID, 0x1BBBBBB000LL);
    // big versions have [11:8] set as well to test the page table merging
    uvm_mmu_page_table_alloc_t alloc_big_sys = fake_table_alloc(UVM_APERTURE_SYS, 0x399999999999900LL);
    uvm_mmu_page_table_alloc_t alloc_big_vid = fake_table_alloc(UVM_APERTURE_VID, 0x1BBBBBBB00LL);

    uvm_mmu_mode_hal_t *hal = gpu->arch_hal->mmu_mode_hal(UVM_PAGE_SIZE_64K);

    // Make sure cleared PDEs  work as expected
    hal->make_pde(pde_bits, phys_allocs, 0);
    TEST_CHECK_RET(pde_bits[0] == 0);

    memset(pde_bits, 0xFF, sizeof(pde_bits));
    hal->make_pde(pde_bits, phys_allocs, 3);
    TEST_CHECK_RET(pde_bits[0] == 0 && pde_bits[1] == 0);

    // Sys and videmem PDEs
    phys_allocs[0] = &alloc_sys;
    hal->make_pde(pde_bits, phys_allocs, 0);
    TEST_CHECK_RET(pde_bits[0] == 0x3999999999990C);

    phys_allocs[0] = &alloc_vid;
    hal->make_pde(pde_bits, phys_allocs, 0);
    TEST_CHECK_RET(pde_bits[0] == 0x1BBBBBB0A);

    // Dual PDEs
    phys_allocs[0] = &alloc_big_sys;
    phys_allocs[1] = &alloc_vid;
    hal->make_pde(pde_bits, phys_allocs, 3);
    TEST_CHECK_RET(pde_bits[0] == 0x3999999999999C && pde_bits[1] == 0x1BBBBBB0A);

    phys_allocs[0] = &alloc_big_vid;
    phys_allocs[1] = &alloc_sys;
    hal->make_pde(pde_bits, phys_allocs, 3);
    TEST_CHECK_RET(pde_bits[0] == 0x1BBBBBBBA && pde_bits[1] == 0x3999999999990C);

    for (i = 0; i < ARRAY_SIZE(page_sizes); i++) {
        // Page table entries
        if (page_sizes[i] == UVM_PAGE_SIZE_64K)
            TEST_CHECK_RET(hal->unmapped_pte(page_sizes[i]) == 0x20);
        else
            TEST_CHECK_RET(hal->unmapped_pte(page_sizes[i]) == 0);

        TEST_CHECK_RET(hal->make_pte(UVM_APERTURE_SYS,
                                     0x399999999999000LL,
                                     UVM_PROT_READ_WRITE_ATOMIC,
                                     NV_TRUE, // volatile
                                     page_sizes[i]) == 0x3999999999990D);

        // change volatile to false
        TEST_CHECK_RET(hal->make_pte(UVM_APERTURE_SYS,
                                     0x399999999999000LL,
                                     UVM_PROT_READ_WRITE_ATOMIC,
                                     NV_FALSE,
                                     page_sizes[i]) == 0x39999999999905);

        // remove atomic
        TEST_CHECK_RET(hal->make_pte(UVM_APERTURE_SYS,
                                     0x399999999999000LL,
                                     UVM_PROT_READ_WRITE,
                                     NV_FALSE,
                                     page_sizes[i]) == 0x39999999999985);

        // read only
        TEST_CHECK_RET(hal->make_pte(UVM_APERTURE_SYS,
                                     0x399999999999000LL,
                                     UVM_PROT_READ_ONLY,
                                     NV_FALSE,
                                     page_sizes[i]) == 0x399999999999C5);

        // local video
        TEST_CHECK_RET(hal->make_pte(UVM_APERTURE_VID,
                                     0x1BBBBBB000LL,
                                     UVM_PROT_READ_ONLY,
                                     NV_FALSE,
                                     page_sizes[i]) == 0x1BBBBBBC1);

        // peer 0
        TEST_CHECK_RET(hal->make_pte(UVM_APERTURE_PEER_0,
                                     0x1BBBBBB000LL,
                                     UVM_PROT_READ_ONLY,
                                     NV_FALSE,
                                     page_sizes[i]) == 0x1BBBBBBC3);

        // peer 7
        TEST_CHECK_RET(hal->make_pte(UVM_APERTURE_PEER_7,
                                     0x1BBBBBB000LL,
                                     UVM_PROT_READ_ONLY,
                                     NV_FALSE,
                                     page_sizes[i]) == 0xFBBBBBBC3);
    }

    return NV_OK;
}

static NV_STATUS entry_test_kepler(uvm_gpu_t *gpu)
{
    static const NvU32 big_page_sizes[] = {UVM_PAGE_SIZE_64K, UVM_PAGE_SIZE_128K};
    NvU64 pde_bits;
    uvm_mmu_page_table_alloc_t *phys_allocs[2];
    uvm_mmu_page_table_alloc_t alloc_sys = fake_table_alloc(UVM_APERTURE_SYS, 0x9999999000LL);
    uvm_mmu_page_table_alloc_t alloc_vid = fake_table_alloc(UVM_APERTURE_VID, 0x1BBBBBB000LL);
    uvm_mmu_mode_hal_t *hal;
    NvU32 i, j, big_page_size, page_size;

    for (i = 0; i < ARRAY_SIZE(big_page_sizes); i++) {
        big_page_size = big_page_sizes[i];
        hal = gpu->arch_hal->mmu_mode_hal(big_page_size);

        memset(phys_allocs, 0, sizeof(phys_allocs));

        hal->make_pde(&pde_bits, phys_allocs, 0);
        TEST_CHECK_RET(pde_bits == 0x0L);

        phys_allocs[0] = &alloc_sys;
        phys_allocs[1] = &alloc_vid;
        hal->make_pde(&pde_bits, phys_allocs, 0);
        TEST_CHECK_RET(pde_bits == 0x1BBBBBBD99999992LL);

        phys_allocs[0] = &alloc_vid;
        phys_allocs[1] = &alloc_sys;
        hal->make_pde(&pde_bits, phys_allocs, 0);
        TEST_CHECK_RET(pde_bits == 0x9999999E1BBBBBB1LL);

        for (j = 0; j <= 2; j++) {
            if (j == 0)
                page_size = UVM_PAGE_SIZE_4K;
            else
                page_size = big_page_size;

            if (page_size == UVM_PAGE_SIZE_4K)
                TEST_CHECK_RET(hal->unmapped_pte(page_size) == 0);
            else
                TEST_CHECK_RET(hal->unmapped_pte(page_size) == 0x2);

            TEST_CHECK_RET(hal->make_pte(UVM_APERTURE_SYS,
                                         0x9999999000LL,
                                         UVM_PROT_READ_WRITE_ATOMIC,
                                         NV_TRUE, // volatile
                                         page_size) == 0x599999991LL);

            // change volatile to false
            TEST_CHECK_RET(hal->make_pte(UVM_APERTURE_SYS,
                                         0x9999999000LL,
                                         UVM_PROT_READ_WRITE_ATOMIC,
                                         NV_FALSE,
                                         page_size) == 0x499999991LL);
            // remove atomic
            TEST_CHECK_RET(hal->make_pte(UVM_APERTURE_SYS,
                                         0x9999999000LL,
                                         UVM_PROT_READ_WRITE,
                                         NV_FALSE,
                                         page_size) == 0x499999991LL);

            // read only
            TEST_CHECK_RET(hal->make_pte(UVM_APERTURE_SYS,
                                         0x9999999000LL,
                                         UVM_PROT_READ_ONLY,
                                         NV_FALSE,
                                         page_size) == 0x8000000499999995LL);

            // local video
            TEST_CHECK_RET(hal->make_pte(UVM_APERTURE_VID,
                                         0x1BBBBBB000LL,
                                         UVM_PROT_READ_ONLY,
                                         NV_FALSE,
                                         page_size) == 0x800000001BBBBBB5LL);

            // peer 0
            TEST_CHECK_RET(hal->make_pte(UVM_APERTURE_PEER_0,
                                         0x1BBBBBB000LL,
                                         UVM_PROT_READ_ONLY,
                                         NV_FALSE,
                                         page_size) == 0x800000021BBBBBB5LL);

            // peer 7
            TEST_CHECK_RET(hal->make_pte(UVM_APERTURE_PEER_7,
                                         0x1BBBBBB000LL,
                                         UVM_PROT_READ_ONLY,
                                         NV_FALSE,
                                         page_size) == 0x80000002FBBBBBB5LL);
        }
    }

    return NV_OK;
}

static NV_STATUS alloc_4k_kepler(uvm_gpu_t *gpu)
{
    uvm_page_tree_t tree;
    uvm_page_table_range_t range;
    NvLength size = 4096;

    // 64k big page mode
    MEM_NV_CHECK_RET(test_page_tree_init(gpu, UVM_PAGE_SIZE_64K, &tree), NV_OK);
    MEM_NV_CHECK_RET(test_page_tree_get_ptes(&tree, UVM_PAGE_SIZE_4K, 0, size, &range), NV_OK);
    TEST_CHECK_RET(range.entry_count == 1);
    TEST_CHECK_RET(range.table->depth == 1);
    TEST_CHECK_RET(range.start_index == 0);
    TEST_CHECK_RET(range.page_size == UVM_PAGE_SIZE_4K);
    TEST_CHECK_RET(tree.root->ref_count == 1);
    TEST_CHECK_RET(range.table == tree.root->entries[1]);
    TEST_CHECK_RET(tree.root->entries[1]->ref_count == 1);
    uvm_page_tree_put_ptes(&tree, &range);
    UVM_ASSERT(tree.root->ref_count == 0);
    uvm_page_tree_deinit(&tree);

    // 128k big page mode
    MEM_NV_CHECK_RET(test_page_tree_init(gpu, UVM_PAGE_SIZE_128K, &tree), NV_OK);
    MEM_NV_CHECK_RET(test_page_tree_get_ptes(&tree, UVM_PAGE_SIZE_4K, 0, size, &range), NV_OK);
    TEST_CHECK_RET(range.entry_count == 1);
    TEST_CHECK_RET(range.table->depth == 1);
    TEST_CHECK_RET(range.start_index == 0);
    TEST_CHECK_RET(range.page_size == UVM_PAGE_SIZE_4K);
    TEST_CHECK_RET(tree.root->ref_count == 1);
    TEST_CHECK_RET(range.table == tree.root->entries[1]);
    TEST_CHECK_RET(tree.root->entries[1]->ref_count == 1);
    uvm_page_tree_put_ptes(&tree, &range);
    UVM_ASSERT(tree.root->ref_count == 0);
    uvm_page_tree_deinit(&tree);

    return NV_OK;
}

static NV_STATUS shrink_test(uvm_gpu_t *gpu, NvU32 big_page_size, NvU32 page_size)
{
    uvm_page_tree_t tree;
    uvm_page_table_range_t range;
    NvU64 addr = 0;
    NvLength size;
    NvU32 num_pages, new_page_count;
    int alignment;

    MEM_NV_CHECK_RET(test_page_tree_init(gpu, big_page_size, &tree), NV_OK);

    for (num_pages = 1; num_pages <= 3; num_pages++) {
        for (alignment = 0; alignment <= 2; alignment++) {
            size = num_pages * page_size;

            // Get the alignment of the range within a PDE
            switch (alignment) {
                case 0: // Start of the PDE
                    addr = 0;
                    break;
                case 1: // In the middle of the PDE
                    addr = page_size;
                    break;
                case 2: // At the end of the PDE
                    addr = uvm_mmu_pde_coverage(&tree, page_size) - size;
                    break;
            }

            for (new_page_count = 0; new_page_count <= num_pages; new_page_count++) {
                MEM_NV_CHECK_RET(test_page_tree_get_ptes(&tree, page_size, addr, size, &range), NV_OK);
                TEST_CHECK_RET(range.table->ref_count == num_pages);
                TEST_CHECK_RET(range.entry_count == num_pages);
                TEST_CHECK_RET(range.start_index == addr / page_size);

                uvm_page_table_range_shrink(&tree, &range, new_page_count);

                if (new_page_count) {
                    TEST_CHECK_RET(range.table->ref_count == new_page_count);
                    TEST_CHECK_RET(range.entry_count == new_page_count);
                    TEST_CHECK_RET(range.start_index == addr / page_size);
                    uvm_page_tree_put_ptes(&tree, &range);
                }

                TEST_CHECK_RET(tree.root->ref_count == 0);
            }
        }
    }

    uvm_page_tree_deinit(&tree);
    return NV_OK;
}

static NV_STATUS get_upper_test(uvm_gpu_t *gpu, NvU32 big_page_size, NvU32 page_size)
{
    uvm_page_tree_t tree;
    uvm_page_table_range_t range, upper_range;
    NvU64 addr = 0;
    NvLength size;
    NvU32 num_pages, num_upper_pages;
    int alignment, put_upper_first;

    MEM_NV_CHECK_RET(test_page_tree_init(gpu, big_page_size, &tree), NV_OK);

    for (num_pages = 1; num_pages <= 3; num_pages++) {
        for (alignment = 0; alignment <= 2; alignment++) {
            size = num_pages * page_size;

            // Get the alignment of the range within a PDE
            switch (alignment) {
                case 0: // Start of the PDE
                    addr = 0;
                    break;
                case 1: // In the middle of the PDE
                    addr = page_size;
                    break;
                case 2: // At the end of the PDE
                    addr = uvm_mmu_pde_coverage(&tree, page_size) - size;
                    break;
            }

            for (num_upper_pages = 1; num_upper_pages <= num_pages; num_upper_pages++) {
                for (put_upper_first = 0; put_upper_first <= 1; put_upper_first++) {
                    MEM_NV_CHECK_RET(test_page_tree_get_ptes(&tree, page_size, addr, size, &range), NV_OK);
                    TEST_CHECK_RET(range.table->ref_count == num_pages);
                    TEST_CHECK_RET(range.entry_count == num_pages);
                    TEST_CHECK_RET(range.start_index == addr / page_size);

                    uvm_page_table_range_get_upper(&tree, &range, &upper_range, num_upper_pages);

                    TEST_CHECK_RET(range.entry_count == num_pages);
                    TEST_CHECK_RET(range.start_index == addr / page_size);

                    TEST_CHECK_RET(upper_range.entry_count == num_upper_pages);
                    TEST_CHECK_RET(upper_range.start_index == range.start_index + num_pages - num_upper_pages);

                    TEST_CHECK_RET(range.table->ref_count == num_pages + num_upper_pages);

                    if (put_upper_first) {
                        uvm_page_tree_put_ptes(&tree, &upper_range);
                        TEST_CHECK_RET(range.entry_count == num_pages);
                        TEST_CHECK_RET(range.start_index == addr / page_size);
                        TEST_CHECK_RET(range.table->ref_count == num_pages);
                        uvm_page_tree_put_ptes(&tree, &range);
                    }
                    else {
                        uvm_page_tree_put_ptes(&tree, &range);
                        TEST_CHECK_RET(upper_range.entry_count == num_upper_pages);
                        TEST_CHECK_RET(upper_range.start_index == (addr / page_size) + num_pages - num_upper_pages);
                        TEST_CHECK_RET(range.table->ref_count == num_upper_pages);
                        uvm_page_tree_put_ptes(&tree, &upper_range);
                    }

                    TEST_CHECK_RET(tree.root->ref_count == 0);
                }
            }
        }
    }

    uvm_page_tree_deinit(&tree);
    return NV_OK;
}

static uvm_host_hal_t fake_host_hal = {
        .noop = fake_noop,
        .wait_for_idle = fake_wait_for_idle,
        .membar_sys = fake_membar,
        .membar_gpu = fake_membar,
        .tlb_invalidate_all = fake_tlb_invalidate_all,
        .tlb_invalidate_va = fake_tlb_invalidate_va,
};
static uvm_ce_hal_t fake_ce_hal = {
        .memset_8 = fake_ce_memset_8,
        .memcopy = fake_ce_memcopy,
};

static NV_STATUS fake_gpu_init(NvU32 host_class, NvU32 ce_class, NvU32 architecture, NvU32 fault_buffer_class, uvm_gpu_t *fake_gpu)
{
    memset(fake_gpu, 0, sizeof(*fake_gpu));

    fake_gpu->ce_class = ce_class;
    fake_gpu->host_class = host_class;
    fake_gpu->architecture = architecture;
    fake_gpu->fault_buffer_class = fault_buffer_class;

    TEST_CHECK_RET(uvm_hal_init_gpu(fake_gpu) == NV_OK);

    fake_gpu->arch_hal->init_properties(fake_gpu);

    // The PTE allocation code expects the address space tree HAL to be present (for example, when checking the
    // addressing capabilities of a GPU).
    // The selected page size (64K) should work across all supported GPU architectures.
    fake_gpu->address_space_tree.hal = fake_gpu->arch_hal->mmu_mode_hal(UVM_PAGE_SIZE_64K);

    fake_gpu->host_hal = &fake_host_hal;
    fake_gpu->ce_hal = &fake_ce_hal;

    return NV_OK;
}

static NV_STATUS fake_gpu_init_kepler(uvm_gpu_t *fake_gpu)
{
    return fake_gpu_init(KEPLER_CHANNEL_GPFIFO_A, KEPLER_DMA_COPY_A, NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GK100,
                         0, fake_gpu);
}

static NV_STATUS fake_gpu_init_pascal(uvm_gpu_t *fake_gpu)
{
    return fake_gpu_init(PASCAL_CHANNEL_GPFIFO_A, PASCAL_DMA_COPY_A, NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GP100,
                         MAXWELL_FAULT_BUFFER_A, fake_gpu);
}

static NV_STATUS kepler_test_page_tree(uvm_gpu_t *kepler)
{
    // create a fake Kepler GPU for this test.
    static const NvU32 big_page_sizes[] = {UVM_PAGE_SIZE_64K, UVM_PAGE_SIZE_128K};
    NvU32 i, j, big_page_size, page_size;

    TEST_CHECK_RET(fake_gpu_init_kepler(kepler) == NV_OK);

    MEM_NV_CHECK_RET(allocate_root(kepler), NV_OK);
    MEM_NV_CHECK_RET(alloc_64k_memory_kepler(kepler), NV_OK);
    MEM_NV_CHECK_RET(alloc_128k_memory_kepler(kepler), NV_OK);
    MEM_NV_CHECK_RET(alloc_4k_kepler(kepler), NV_OK);
    TEST_CHECK_RET(entry_test_kepler(kepler) == NV_OK);

    for (i = 0; i < ARRAY_SIZE(big_page_sizes); i++) {
        big_page_size = big_page_sizes[i];
        for (j = 0; j < 2; j++) {
            page_size = (j == 0) ? UVM_PAGE_SIZE_4K : big_page_size;

            MEM_NV_CHECK_RET(shrink_test(kepler, big_page_size, page_size), NV_OK);
            MEM_NV_CHECK_RET(get_upper_test(kepler, big_page_size, page_size), NV_OK);
            MEM_NV_CHECK_RET(test_range_vec(kepler, big_page_size, page_size), NV_OK);
        }
    }

    return NV_OK;
}

static NV_STATUS pascal_test_page_tree(uvm_gpu_t *pascal)
{
    // create a fake Pascal GPU for this test.
    NvU32 tlb_batch_saved_max_pages;
    static const NvU32 page_sizes[] = {UVM_PAGE_SIZE_4K, UVM_PAGE_SIZE_64K, UVM_PAGE_SIZE_2M};
    NvU32 i, page_size;

    TEST_CHECK_RET(fake_gpu_init_pascal(pascal) == NV_OK);

    MEM_NV_CHECK_RET(allocate_root(pascal), NV_OK);
    MEM_NV_CHECK_RET(alloc_64k_memory(pascal), NV_OK);
    MEM_NV_CHECK_RET(alloc_adjacent_64k_memory(pascal), NV_OK);
    MEM_NV_CHECK_RET(alloc_adjacent_pde_64k_memory(pascal), NV_OK);
    MEM_NV_CHECK_RET(alloc_nearby_pde_64k_memory(pascal), NV_OK);
    MEM_NV_CHECK_RET(allocate_then_free_all_16_64k(pascal), NV_OK);
    MEM_NV_CHECK_RET(allocate_then_free_8_8_64k(pascal), NV_OK);
    MEM_NV_CHECK_RET(get_single_page_2m(pascal), NV_OK);
    MEM_NV_CHECK_RET(get_entire_table_4k(pascal), NV_OK);
    MEM_NV_CHECK_RET(split_4k_from_2m(pascal), NV_OK);
    MEM_NV_CHECK_RET(get_512mb_range(pascal), NV_OK);
    MEM_NV_CHECK_RET(get_two_free_apart(pascal), NV_OK);
    MEM_NV_CHECK_RET(get_overlapping_dual_pdes(pascal), NV_OK);
    MEM_NV_CHECK_RET(split_and_free(pascal), NV_OK);
    MEM_NV_CHECK_RET(entry_test_pascal(pascal), NV_OK);
    MEM_NV_CHECK_RET(check_sizes(pascal), NV_OK);
    MEM_NV_CHECK_RET(fast_split_normal(pascal), NV_OK);
    MEM_NV_CHECK_RET(fast_split_double_backoff(pascal), NV_OK);
    MEM_NV_CHECK_RET(test_pascal_tlb_invalidates(pascal), NV_OK);
    MEM_NV_CHECK_RET(test_pascal_tlb_batch_invalidates(pascal), NV_OK);

    // Run the test again with a bigger limit on max pages
    tlb_batch_saved_max_pages = pascal->tlb_batch.max_pages;
    pascal->tlb_batch.max_pages = 1024 * 1024;
    MEM_NV_CHECK_RET(test_pascal_tlb_batch_invalidates(pascal), NV_OK);
    pascal->tlb_batch.max_pages = tlb_batch_saved_max_pages;

    // And with per VA invalidates disabled
    pascal->tlb_batch.va_invalidate_supported = false;
    MEM_NV_CHECK_RET(test_pascal_tlb_batch_invalidates(pascal), NV_OK);
    pascal->tlb_batch.va_invalidate_supported = true;

    for (i = 0; i < ARRAY_SIZE(page_sizes); i++) {
        page_size = page_sizes[i];
        MEM_NV_CHECK_RET(shrink_test(pascal, BIG_PAGE_SIZE_PASCAL, page_size), NV_OK);
        MEM_NV_CHECK_RET(get_upper_test(pascal, BIG_PAGE_SIZE_PASCAL, page_size), NV_OK);
        MEM_NV_CHECK_RET(test_range_vec(pascal, BIG_PAGE_SIZE_PASCAL, page_size), NV_OK);
    }

    return NV_OK;
}

NV_STATUS uvm8_test_page_tree(UVM_TEST_PAGE_TREE_PARAMS *params, struct file *filp)
{
    NV_STATUS status = NV_OK;
    uvm_gpu_t *gpu;

    gpu = uvm_kvmalloc(sizeof(*gpu));
    if (!gpu)
        return NV_ERR_NO_MEMORY;

    // At least test_pascal_tlb_invalidates() relies on global state
    // (g_tlb_invalidate_*) so make sure only one test instance can run at a time.
    uvm_mutex_lock(&g_uvm_global.global_lock);

    // Allocate the fake TLB tracking state. Notably tests still need to enable
    // and disable the tracking with explicit fake_tlb_invals_enable/disable()
    // calls.
    TEST_CHECK_GOTO(fake_tlb_invals_alloc() == NV_OK, done);

    TEST_CHECK_GOTO(pascal_test_page_tree(gpu) == NV_OK, done);
    TEST_CHECK_GOTO(kepler_test_page_tree(gpu) == NV_OK, done);

    fake_tlb_invals_free();

done:
    uvm_mutex_unlock(&g_uvm_global.global_lock);

    uvm_kvfree(gpu);

    return status;
}
