#pragma once
#include "core/types.h"
#include "formats/physical_layer.h"
#include "symbols/isf_symbols.h"
#include "arch/x86_64/paging.h"
#include <memory>

namespace lmpfs::linux {

struct KernelContext {
    PAddr     dtb               = 0;   // physical address of init_top_pgt (0 if unresolved)
    i64       kaslr_phys_shift  = 0;   // physical relocation of kernel image
    i64       kaslr_virt_shift  = 0;   // virtual relocation (KASLR slide)
    VAddr     init_task_va      = 0;   // KASLR-shifted virtual address of init_task
    PAddr     init_task_pa      = 0;   // physical address of init_task
    VAddr     direct_map_base   = 0;   // page_offset_base (kernel direct map start)
    std::string banner;
    bool      dtb_validated     = false; // true if banner round-trip succeeded
    const char* dtb_strategy    = "?"; // which DTB strategy was picked
};

// Translate a kernel-direct-map VA to PA.  Returns 0 if VA is outside the map.
inline PAddr kdmap_va_to_pa(VAddr va, VAddr direct_map_base, PAddr max_pa) {
    if (va < direct_map_base) return ~0ULL;
    u64 off = va - direct_map_base;
    if (off >= max_pa) return ~0ULL;
    return static_cast<PAddr>(off);
}

// Resolves KASLR, DTB and init_task by scanning the dump for the swapper
// signature, then anchoring against the supplied ISF symbol table.
// Throws on failure.
KernelContext resolve_kernel(const PhysicalLayer& phys, const IsfSymbols& isf);

// Static (no KASLR) kernel-vaddr -> paddr for the kernel text mapping.
// Always:  paddr = vaddr - 0xffffffff80000000 + kaslr_phys_shift
inline PAddr kernel_va_to_pa_static(VAddr va, i64 kaslr_phys_shift) {
    return static_cast<PAddr>(va - 0xffffffff80000000ULL) + kaslr_phys_shift;
}

} // namespace lmpfs::linux
