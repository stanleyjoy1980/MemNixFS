// dtb_resolver.h — multi-strategy kernel DTB (CR3 / init_top_pgt PA) resolver.
//
// Knowing the DTB unlocks every kernel-space VA → PA translation: kallsyms,
// modules, dmesg, vmalloc'd structures, anything not in the linear direct map.
//
// We try strategies in order of reliability and pick the first one whose
// resulting DTB validates against a known kernel-text symbol (`linux_banner`).
// That makes the resolver robust against:
//   * KASLR layouts with non-default phys_base
//   * ISF/dump kernel-release skew (we'd fail validation cleanly instead of
//     silently producing wrong reads)
//   * Future dump formats whose only invariant is "PGD lives somewhere in
//     physical memory" (brute-force fallback)
//
// References:
//   vol3:    framework/automagic/linux.py  (LinuxIntelStacker.find_aslr,
//            LinuxIntelVMCOREINFOStacker._vmcoreinfo_get_dtb)
//   MemProcFS:  vmm/vmmwininit.c  (Windows DTB discovery; same brute-force pattern)
//
#pragma once
#include "core/types.h"
#include "formats/physical_layer.h"
#include "symbols/isf_symbols.h"
#include <optional>
#include <vector>

namespace lmpfs::linux {

struct DtbCandidate {
    PAddr        dtb            = 0;   // physical address of init_top_pgt
    i64          phys_shift     = 0;   // KASLR physical shift
    i64          virt_shift     = 0;   // KASLR virtual shift (== phys_shift on x86_64)
    const char*  strategy       = "?"; // which method produced this candidate
};

struct DtbResolution {
    PAddr        dtb;
    i64          phys_shift;
    i64          virt_shift;
    const char*  strategy;
    bool         validated;            // walked DTB + read banner OK?
};

// Walks `dtb` to translate the post-KASLR address of `linux_banner` and
// checks that the bytes there start with "Linux version ". This is the
// definitive correctness test for a DTB candidate.
bool validate_dtb_via_banner(const PhysicalLayer& phys,
                             const IsfSymbols&    isf,
                             PAddr                dtb,
                             i64                  virt_shift);

// Tries strategies in order, returning the first candidate that validates.
// Throws if every strategy fails (programmer error or unsupported dump).
DtbResolution resolve_dtb(const PhysicalLayer&             phys,
                          const IsfSymbols&                isf,
                          PAddr                            init_task_pa,
                          const std::vector<std::pair<PAddr, i64>>& banner_shifts);

} // namespace lmpfs::linux
