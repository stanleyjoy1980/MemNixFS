// kallsyms.h — extract the Linux kernel's compressed symbol table directly
// from a memory dump, with **no ISF symbols required**.
//
// Why this exists
// ===============
// BTF (read elsewhere from the dump's `.BTF` section) gives us complete kernel
// *types* — but no symbol *addresses*. A BTF-derived ISF has an empty
// `symbols` section, which means everything that needs a kernel-VA anchor
// (kallsyms, modules, dmesg, validated DTB walks) runs in "degraded mode".
//
// kallsyms is the kernel's own symbol table, embedded in `.rodata` as a set
// of compressed tables (token table + Huffman-ish per-token name encoding).
// It lives at known relative offsets inside the kernel image, so it shows up
// in every memory dump from a kernel built with `CONFIG_KALLSYMS=y` (which is
// essentially every distro kernel since forever).
//
// Together: BTF → types, kallsyms → addresses. The pair produces a
// fully-functional offline ISF with zero external files / network.
//
// Algorithm
// =========
// 1. **Signature-scan for `kallsyms_token_index`** in physical memory.
//    It's a packed `u16[256]` with very distinctive constraints
//    (first==0, monotonic non-decreasing, max<2048, deltas ≤ ~40).
// 2. **Validate `kallsyms_token_table`** sitting immediately before
//    the index: 256 NUL-terminated short strings whose start offsets
//    exactly match the index values.
// 3. **Walk backward** to recover (in reverse memory order):
//    `kallsyms_markers` → `kallsyms_names` → `kallsyms_num_syms` →
//    (`kallsyms_seqs_of_names`, ≥6.2 only) → `kallsyms_relative_base`
//    → `kallsyms_offsets`.
// 4. **Decode** each symbol's compressed name (1-byte length prefix +
//    sequence of single-byte token indices) and resolve its kernel
//    virtual address from `offsets[i]` + `relative_base`.
//
// Reference: kernel `kernel/kallsyms.c`, `scripts/kallsyms.c`, and
// `volatility3/framework/symbols/linux/_internal.py` (the
// `LinuxUtilities.find_kallsyms` flow, where the algorithm originated).
//
#pragma once
#include "core/types.h"
#include "formats/physical_layer.h"
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace lmpfs::linux {

struct KallsymsEntry {
    VAddr       address;   // kernel virtual address (KASLR-shifted)
    char        type;      // 't', 'T', 'd', 'D', 'b', 'B', 'r', 'R', 'a', etc.
    std::string name;
};

struct KallsymsResult {
    bool        ok = false;
    std::string error;

    std::vector<KallsymsEntry>                symbols;
    // Fast name → first-matching-entry lookup (kallsyms can have duplicates
    // — e.g. static `inline` functions present in multiple translation units —
    // but the first occurrence is almost always the canonical one).
    std::unordered_map<std::string, std::size_t> by_name;

    // Diagnostics (PAs of the structures we located, plus key values).
    PAddr token_table_pa = 0;
    PAddr token_index_pa = 0;
    PAddr markers_pa     = 0;
    PAddr names_pa       = 0;
    PAddr num_syms_pa    = 0;
    PAddr offsets_pa     = 0;
    PAddr relative_base_pa = 0;

    u32   num_syms       = 0;
    u32   num_markers    = 0;
    u32   names_size     = 0;
    u32   token_table_size = 0;

    bool  base_relative  = true;   // false → 8-byte absolute addresses
    VAddr relative_base  = 0;
};

// Extract kallsyms purely from physical memory. No ISF, no banner, no
// KASLR shift required (we recover everything from the dump itself).
// The resulting `address` fields are post-KASLR kernel VAs — exactly what
// the running kernel reports through /proc/kallsyms.
KallsymsResult extract_kallsyms(const PhysicalLayer& phys);

// Convenience: return the first symbol matching `name`, or nullptr.
const KallsymsEntry* find_symbol(const KallsymsResult& r, const std::string& name);

} // namespace lmpfs::linux
