#include "os/linux/vma.h"
#include "core/error.h"
#include "core/log.h"
#include <algorithm>
#include <unordered_set>

namespace lmpfs::linux {

namespace {

// ---- direct-map helpers (replicated from process_list.cpp) ----
bool dm_pa(VAddr va, const KernelContext& k, PAddr max_pa, PAddr& out) {
    if (va < k.direct_map_base) return false;
    u64 off = va - k.direct_map_base;
    if (off >= max_pa) return false;
    out = off; return true;
}
bool read_dm_u64(const PhysicalLayer& phys, const KernelContext& k, VAddr va, u64& v) {
    PAddr pa; if (!dm_pa(va, k, phys.max_address(), pa)) return false;
    return phys.read_pod(pa, v);
}
bool read_dm_u32(const PhysicalLayer& phys, const KernelContext& k, VAddr va, u32& v) {
    PAddr pa; if (!dm_pa(va, k, phys.max_address(), pa)) return false;
    return phys.read_pod(pa, v);
}
template <typename T>
bool read_dm(const PhysicalLayer& phys, const KernelContext& k, VAddr va, T& v) {
    static_assert(std::is_trivially_copyable_v<T>);
    PAddr pa; if (!dm_pa(va, k, phys.max_address(), pa)) return false;
    return phys.read_pod(pa, v);
}

// ---- Maple tree constants (include/linux/maple_tree.h) ----
constexpr u64 kMapleNodePointerMask = 0xFFULL;
constexpr u64 kMapleNodeTypeShift   = 3;
constexpr u64 kMapleNodeTypeMask    = 0x0F;
enum MapleNodeType : u8 {
    MAPLE_DENSE     = 0,
    MAPLE_LEAF_64   = 1,
    MAPLE_RANGE_64  = 2,
    MAPLE_ARANGE_64 = 3,
};

// Field offsets inside maple_range_64 / maple_arange_64 (from ISF).
constexpr u64 kMR64_SlotOff   = 0x80; // 16 slots × 8 B
constexpr u64 kMR64_SlotCount = 16;
constexpr u64 kMA64_SlotOff   = 0x50; // 10 slots × 8 B
constexpr u64 kMA64_SlotCount = 10;

struct VmaOffsets {
    u64 vm_start, vm_end, vm_flags, vm_pgoff, vm_file;
};
struct MmOffsets {
    u64 mm_mt;   // maple_tree (0x40 .. +0x10)
    u64 pgd;     // 0x78
    u64 ma_root; // offset of ma_root inside maple_tree (0x8 from start)
};

VmaOffsets get_vma_offsets(const IsfSymbols& isf) {
    return {
        isf.field_offset("vm_area_struct", "vm_start"),
        isf.field_offset("vm_area_struct", "vm_end"),
        isf.field_offset("vm_area_struct", "vm_flags"),
        isf.field_offset("vm_area_struct", "vm_pgoff"),
        isf.field_offset("vm_area_struct", "vm_file"),
    };
}
MmOffsets get_mm_offsets(const IsfSymbols& isf) {
    return {
        isf.field_offset("mm_struct", "mm_mt"),
        isf.field_offset("mm_struct", "pgd"),
        isf.field_offset("maple_tree", "ma_root"),
    };
}

// Hard cap so corrupt maple-tree walks (e.g. dying processes whose mm slab
// is being reused) don't blow up the vector indefinitely. Real Linux
// processes top out around a few thousand VMAs; 100 000 is generous.
constexpr std::size_t kMaxVmasPerProcess = 100'000;

void read_vma(const PhysicalLayer& phys, const KernelContext& k,
              VAddr vma_va, const VmaOffsets& o, std::vector<Vma>& out)
{
    if (out.size() >= kMaxVmasPerProcess) return;
    Vma v{};
    if (!read_dm(phys, k, vma_va + o.vm_start, v.vm_start)) return;
    if (!read_dm(phys, k, vma_va + o.vm_end,   v.vm_end))   return;
    if (v.vm_end <= v.vm_start)                              return;
    if (v.vm_end - v.vm_start > 0x40000000000ULL)            return; // sanity: <4TB
    read_dm(phys, k, vma_va + o.vm_flags, v.vm_flags);
    read_dm(phys, k, vma_va + o.vm_pgoff, v.vm_pgoff);
    read_dm(phys, k, vma_va + o.vm_file,  v.vm_file);
    out.push_back(v);
}

void walk_maple_node(const PhysicalLayer& phys, const KernelContext& kctx,
                     const VmaOffsets& voff, u64 mte, u64 expected_depth,
                     u64 depth, std::unordered_set<u64>& seen,
                     std::vector<Vma>& out)
{
    if (depth > 16) return; // hard recursion guard
    if (mte == 0)   return;
    if (seen.count(mte)) return;
    seen.insert(mte);

    u64 node_pa_va = mte & ~kMapleNodePointerMask;   // pointer to maple_node (kernel VA, direct-map)
    u8  node_type  = static_cast<u8>((mte >> kMapleNodeTypeShift) & kMapleNodeTypeMask);

    auto walk_slot_array = [&](u64 slot_off, u64 slot_count, bool recurse) {
        for (u64 i = 0; i < slot_count; ++i) {
            if (out.size() >= kMaxVmasPerProcess) return;
            u64 slot = 0;
            if (!read_dm(phys, kctx, node_pa_va + slot_off + i * 8, slot)) continue;
            if (slot == 0) continue;
            if (recurse) {
                walk_maple_node(phys, kctx, voff, slot, expected_depth, depth + 1, seen, out);
            } else {
                // LEAF: slot is a vm_area_struct pointer (no tag bits).
                read_vma(phys, kctx, slot, voff, out);
            }
        }
    };

    switch (node_type) {
        case MAPLE_LEAF_64:   walk_slot_array(kMR64_SlotOff, kMR64_SlotCount, false); break;
        case MAPLE_RANGE_64:  walk_slot_array(kMR64_SlotOff, kMR64_SlotCount, true);  break;
        case MAPLE_ARANGE_64: walk_slot_array(kMA64_SlotOff, kMA64_SlotCount, true);  break;
        case MAPLE_DENSE:     /* allocator pool, never expected for mm_mt */          break;
        default:
            log::debug("maple: unknown node type {} at {:#x}", node_type, node_pa_va);
            break;
    }
}

} // anonymous

std::vector<Vma> enumerate_vmas(const PhysicalLayer& phys,
                                const IsfSymbols&    isf,
                                const KernelContext& kctx,
                                const Process&       p)
{
    std::vector<Vma> out;
    if (p.mm == 0) return out; // kernel thread

    auto vo = get_vma_offsets(isf);
    auto mo = get_mm_offsets(isf);

    // mm->mm_mt is an embedded maple_tree starting at offset mm_mt.
    // ma_root within maple_tree is at mo.ma_root (typically 0x8).
    u64 ma_root = 0;
    if (!read_dm(phys, kctx, p.mm + mo.mm_mt + mo.ma_root, ma_root)) return out;
    if (ma_root == 0) return out;

    // For a tree with only one entry, ma_root might be the data pointer directly
    // (low bits 0). For a tree with nodes, ma_root has type bits set in the low byte.
    // Volatility distinguishes by examining the low bits / flags. We treat ma_root
    // as the root mte and recurse.
    std::unordered_set<u64> seen;
    walk_maple_node(phys, kctx, vo, ma_root, /*expected_depth=*/8, /*depth=*/1, seen, out);

    // Sort and de-duplicate by vm_start.
    std::sort(out.begin(), out.end(),
              [](const Vma& a, const Vma& b) { return a.vm_start < b.vm_start; });
    out.erase(std::unique(out.begin(), out.end(),
              [](const Vma& a, const Vma& b) {
                  return a.vm_start == b.vm_start && a.vm_end == b.vm_end;
              }), out.end());
    return out;
}

PAddr resolve_user_pgd(const PhysicalLayer& phys,
                       const IsfSymbols&    isf,
                       const KernelContext& kctx,
                       const Process&       p)
{
    if (p.mm == 0) return 0;
    auto mo = get_mm_offsets(isf);
    u64 pgd_va = 0;
    if (!read_dm(phys, kctx, p.mm + mo.pgd, pgd_va)) return 0;
    if (pgd_va == 0) return 0;
    PAddr pgd_pa = 0;
    if (!dm_pa(pgd_va, kctx, phys.max_address(), pgd_pa)) return 0;
    return pgd_pa;
}

} // namespace lmpfs::linux
