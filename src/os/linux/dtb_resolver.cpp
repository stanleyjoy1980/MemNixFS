// dtb_resolver.cpp — see header for design notes.
#include "os/linux/dtb_resolver.h"
#include "os/linux/kernel_resolver.h"
#include "arch/x86_64/paging.h"
#include "core/error.h"
#include "core/log.h"
#include <algorithm>
#include <cstring>

namespace lmpfs::linux {

namespace {

constexpr u64 kStartKernelMap = 0xffffffff80000000ULL;
constexpr u64 k2MiB           = 0x200000ULL;

// Static (pre-KASLR) PA of a kernel-text-mapping symbol.
inline PAddr static_text_pa(VAddr va) { return static_cast<PAddr>(va - kStartKernelMap); }

// Compute init_top_pgt's PA for a given phys_shift.
inline std::optional<PAddr>
dtb_for_shift(const IsfSymbols& isf, i64 phys_shift) {
    const SymbolInfo* sym = isf.find_symbol("init_top_pgt");
    if (!sym) sym = isf.find_symbol("init_level4_pgt");
    if (!sym) sym = isf.find_symbol("swapper_pg_dir");
    if (!sym) return std::nullopt;
    return static_cast<PAddr>(static_cast<i64>(static_text_pa(sym->address)) + phys_shift);
}

} // anonymous

bool validate_dtb_via_banner(const PhysicalLayer& phys,
                             const IsfSymbols&    isf,
                             PAddr                dtb,
                             i64                  virt_shift)
{
    const SymbolInfo* banner = isf.find_symbol("linux_banner");
    if (!banner) return false;

    // PGD PA must be at least 4 KiB-aligned (hardware requirement).
    if (dtb & 0xFFFULL) return false;
    if (dtb == 0 || dtb >= phys.max_address()) return false;

    x86_64::PageTable pt(phys, dtb);
    VAddr banner_va = banner->address + virt_shift;

    char buf[32] = {};
    pt.read(banner_va, buf, sizeof(buf));
    return std::strncmp(buf, "Linux version ", 14) == 0;
}

DtbResolution
resolve_dtb(const PhysicalLayer&                       phys,
            const IsfSymbols&                          isf,
            PAddr                                      init_task_pa,
            const std::vector<std::pair<PAddr, i64>>&  banner_shifts)
{
    std::vector<DtbCandidate> cands;

    // -------- Strategy 1: banner-anchored (most reliable on x86_64 KASLR) --
    // The IMAGE banner has a 2 MiB-aligned shift; printk-buffer copies don't.
    for (auto& [_, sh] : banner_shifts) {
        if ((sh & (k2MiB - 1)) != 0) continue;
        if (auto dtb = dtb_for_shift(isf, sh)) {
            cands.push_back({ *dtb, sh, sh, "banner-anchored" });
        }
    }

    // -------- Strategy 2: init_task-anchored (current behaviour) -----------
    if (auto sym = isf.find_symbol("init_task")) {
        i64 sh = static_cast<i64>(init_task_pa) - static_cast<i64>(static_text_pa(sym->address));
        if (auto dtb = dtb_for_shift(isf, sh)) {
            cands.push_back({ *dtb, sh, sh, "init_task-anchored" });
        }
    }

    // -------- Strategy 3: brute-force PGD scan ----------------------------
    // Linux abandons `init_top_pgt` after early boot and runs from a
    // dynamically-allocated PGD whose PA isn't a symbol in the ISF. We scan
    // physical memory for any page that walks to the banner correctly. The
    // banner-anchored phys_shift is canonical (we computed virt_shift from
    // it), so we only need to find the right DTB PA.
    //
    // Heuristic for "looks like a PML4" early-out (skip ~99.9 % of candidates
    // without reading 4 levels):
    //   * PML4[511] (kernel-text PML4E) must be present
    //   * Its physical address must be inside the dump
    //   * Most user-half entries (0..255) should be zero
    //
    // For the few survivors, run the full validate_dtb_via_banner check.
    {
        const i64 sh = !banner_shifts.empty()
            ? banner_shifts.front().second
            : 0;
        // Pick the first 2-MB-aligned banner shift if any; otherwise reuse the
        // init_task shift.
        i64 best_shift = 0;
        for (auto& [_, s] : banner_shifts) {
            if ((s & (k2MiB - 1)) == 0) { best_shift = s; break; }
        }
        if (best_shift == 0 && !cands.empty()) best_shift = cands.back().phys_shift;
        if (best_shift == 0) best_shift = sh;

        log::debug("Brute-force PGD scan (best_shift={:#x})...", best_shift);

        const PAddr maxa = phys.max_address();
        const auto* banner_sym = isf.find_symbol("linux_banner");
        if (banner_sym) {
            VAddr banner_va = banner_sym->address + best_shift;
            // Each PML4 entry occupies bytes [4088, 4096) of the page.
            // Read just that 8-byte entry per candidate page first.
            std::size_t scanned = 0, plausible = 0;
            constexpr std::size_t kReportEvery = 0x4000000; // every 64 MiB scanned
            for (PAddr pa = 0; pa + 0x1000 <= maxa; pa += 0x1000) {
                ++scanned;
                if ((scanned & 0xFFF) == 0 && (pa % kReportEvery == 0))
                    log::debug("  scanned {} GiB...", pa >> 30);

                u64 pml4_e511 = 0;
                if (!phys.read_pod(pa + 0xFF8, pml4_e511)) continue;
                if (!(pml4_e511 & 0x1)) continue;                          // not present
                const u64 pdpt_pa = pml4_e511 & 0x000ffffffffff000ULL;
                if (pdpt_pa == 0 || pdpt_pa >= maxa) continue;
                // Cheap: most user-half entry 0 should be zero or present-and-canonical.
                u64 pml4_e0 = 0;
                phys.read_pod(pa, pml4_e0);
                if ((pml4_e0 & 1) && (pml4_e0 & 0x000ffffffffff000ULL) >= maxa) continue;
                ++plausible;

                if (validate_dtb_via_banner(phys, isf, pa, best_shift)) {
                    log::debug("Brute-force found DTB: {:#x} (after {} candidates, {} plausible)",
                              pa, scanned, plausible);
                    cands.push_back({ pa, best_shift, best_shift, "brute-force" });
                    break;
                }
            }
            if (cands.empty() || cands.back().strategy != std::string("brute-force"))
                log::warn("Brute-force scan completed: {} pages, {} plausible, NO match",
                          scanned, plausible);
        }
    }

    // Dedup by DTB (multiple banners may produce the same dtb).
    std::sort(cands.begin(), cands.end(),
              [](auto& a, auto& b) { return a.dtb < b.dtb; });
    cands.erase(std::unique(cands.begin(), cands.end(),
                            [](auto& a, auto& b) { return a.dtb == b.dtb; }),
                cands.end());

    log::debug("DTB resolver: {} candidate(s)", cands.size());
    for (auto& c : cands) {
        log::debug("  candidate dtb={:#x} shift={:#x} strategy={}",
                   c.dtb, c.phys_shift, c.strategy);
    }

    // Validate each candidate. Pick the first that walks back to the banner.
    for (auto& c : cands) {
        if (validate_dtb_via_banner(phys, isf, c.dtb, c.virt_shift)) {
            log::debug("DTB validated via banner: dtb={:#x} shift={:#x} strategy={}",
                      c.dtb, c.phys_shift, c.strategy);
            return DtbResolution{ c.dtb, c.phys_shift, c.virt_shift, c.strategy, true };
        }
        log::debug("  candidate dtb={:#x} FAILED banner validation", c.dtb);
    }

    // All candidates failed. Return the most likely one (banner-anchored if
    // present, else init_task) un-validated so the rest of the engine still
    // works in degraded mode.
    if (!cands.empty()) {
        const auto& c = cands.front();
        log::warn("DTB unvalidated! Using best guess dtb={:#x} (strategy={}). "
                  "Kernel-VA reads (kallsyms, modules, dmesg) may be wrong.",
                  c.dtb, c.strategy);
        return DtbResolution{ c.dtb, c.phys_shift, c.virt_shift, c.strategy, false };
    }

    throw_error("DTB resolution: no candidates (ISF missing init_top_pgt + no init_task + no banner)");
}

} // namespace lmpfs::linux
