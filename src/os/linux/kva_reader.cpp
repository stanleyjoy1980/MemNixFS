// kva_reader.cpp — see header.
#include "os/linux/kva_reader.h"
#include "app/engine.h"
#include "symbols/isf_symbols.h"
#include "arch/x86_64/paging.h"
#include "formats/physical_layer.h"
#include "os/linux/kernel_resolver.h"
#include "core/log.h"
#include <atomic>
#include <vector>

namespace lmpfs::linux {

namespace {

constexpr u64 kStartKernelMap = 0xffffffff80000000ULL;
constexpr u64 kPhysmapStart   = 0xffff800000000000ULL;
constexpr u64 kVmallocStart   = 0xffffffffc0000000ULL;

inline PAddr kva_to_pa_image(VAddr va, i64 phys_shift) {
    return static_cast<PAddr>(static_cast<i64>(va - kStartKernelMap) + phys_shift);
}

// Resolve init_mm.pgd → PA, cached on first call. Returns 0 if unavailable.
// Thread-safety: load-acquire / store-release on the cache; the resolve path
// is idempotent so a benign race just redoes the work.
PAddr resolve_init_mm_pgd_pa(const Engine& eng) {
    static std::atomic<PAddr> cached{ ~PAddr{0} };
    PAddr v = cached.load(std::memory_order_acquire);
    if (v != ~PAddr{0}) return v;

    const auto& isf = eng.isf();
    const auto& k   = eng.kernel();
    PAddr resolved = 0;

    auto* init_mm_sym = isf.find_symbol("init_mm");
    if (!init_mm_sym) { cached.store(0, std::memory_order_release); return 0; }

    u64 pgd_off = 0;
    try { pgd_off = isf.field_offset("mm_struct", "pgd"); }
    catch (...) { cached.store(0, std::memory_order_release); return 0; }

    // init_mm is a kernel-image symbol.
    PAddr init_mm_pa = kva_to_pa_image(init_mm_sym->address, k.kaslr_phys_shift);
    VAddr pgd_va = 0;
    if (!eng.phys().read_pod(init_mm_pa + pgd_off, pgd_va) || pgd_va == 0) {
        log::debug("kva_reader: init_mm.pgd read failed (PA={:#x}+pgd_off={:#x})",
                   init_mm_pa, pgd_off);
        cached.store(0, std::memory_order_release);
        return 0;
    }

    if (pgd_va >= kStartKernelMap) {
        resolved = kva_to_pa_image(pgd_va, k.kaslr_phys_shift);
        log::info("kva_reader: init_mm.pgd VA={:#x} (image) → PA={:#x}",
                  pgd_va, resolved);
    } else if (k.direct_map_base != 0 && pgd_va >= k.direct_map_base &&
               pgd_va < kStartKernelMap) {
        resolved = static_cast<PAddr>(pgd_va - k.direct_map_base);
        log::info("kva_reader: init_mm.pgd VA={:#x} (direct-map) → PA={:#x}",
                  pgd_va, resolved);
    } else {
        log::warn("kva_reader: init_mm.pgd VA={:#x} in no known range", pgd_va);
    }
    cached.store(resolved, std::memory_order_release);
    return resolved;
}

} // anonymous

bool kva_read(const Engine& eng, VAddr va, void* dst, std::size_t n) {
    const auto& k = eng.kernel();

    // 1) Vmalloc / modules: only PGD walk. Try primary DTB; if it doesn't
    //    have vmalloc populated, fall back to init_mm.pgd.
    if (va >= kVmallocStart) {
        if (k.dtb_validated) {
            if (eng.kernel_pt().read(va, dst, n) == n) return true;
        }
        PAddr init_pgd = resolve_init_mm_pgd_pa(eng);
        if (init_pgd != 0) {
            x86_64::PageTable pt(eng.phys(), init_pgd);
            if (pt.read(va, dst, n) == n) return true;
        }
        return false;
    }

    // 2) Direct-map (kmalloc / slab) — linear translation, fastest.
    if (va >= kPhysmapStart && va < kStartKernelMap &&
        k.direct_map_base != 0 && va >= k.direct_map_base)
    {
        PAddr pa = static_cast<PAddr>(va - k.direct_map_base);
        if (eng.phys().read(pa, dst, n) == n) return true;
    }

    // 3) Kernel image — linear translation.
    if (va >= kStartKernelMap && va < kVmallocStart) {
        PAddr pa = kva_to_pa_image(va, k.kaslr_phys_shift);
        if (eng.phys().read(pa, dst, n) == n) return true;
    }

    // 4) Last-ditch: walk whichever PGD we have. Useful for the rare case
    //    where the dump is captured before direct_map_base is set up, or
    //    direct_map_base happened to be wrong.
    if (k.dtb_validated) {
        if (eng.kernel_pt().read(va, dst, n) == n) return true;
    }
    PAddr init_pgd = resolve_init_mm_pgd_pa(eng);
    if (init_pgd != 0) {
        x86_64::PageTable pt(eng.phys(), init_pgd);
        if (pt.read(va, dst, n) == n) return true;
    }
    return false;
}

std::string kva_read_cstr(const Engine& eng, VAddr va, std::size_t maxlen) {
    if (va == 0) return {};
    std::vector<char> buf(maxlen, 0);
    if (!kva_read(eng, va, buf.data(), maxlen)) return {};
    std::size_t n = 0;
    while (n < maxlen && buf[n]) ++n;
    return std::string(buf.data(), n);
}

KvaTranslate kva_translate(const Engine& eng, VAddr va) {
    KvaTranslate r;
    const auto& k = eng.kernel();

    // Validate the translation by actually probing one byte at the resolved
    // PA — without this we'd happily report "0x… via direct-map" for VAs
    // outside the dump's physical span, which is misleading.
    auto probe = [&](PAddr pa) -> bool {
        u8 b;
        return eng.phys().read(pa, &b, 1) == 1;
    };

    // 1) Vmalloc / modules — PGD walk required.
    if (va >= kVmallocStart) {
        if (k.dtb_validated) {
            if (auto pa = eng.kernel_pt().translate(va); pa && probe(*pa)) {
                r.ok = true; r.pa = *pa; r.strategy = "vmalloc-dtb"; return r;
            }
        }
        PAddr init_pgd = resolve_init_mm_pgd_pa(eng);
        if (init_pgd != 0) {
            x86_64::PageTable pt(eng.phys(), init_pgd);
            if (auto pa = pt.translate(va); pa && probe(*pa)) {
                r.ok = true; r.pa = *pa; r.strategy = "vmalloc-init-mm"; return r;
            }
        }
        return r;
    }

    // 2) Direct-map (linear).
    if (va >= kPhysmapStart && va < kStartKernelMap &&
        k.direct_map_base != 0 && va >= k.direct_map_base)
    {
        PAddr pa = static_cast<PAddr>(va - k.direct_map_base);
        if (probe(pa)) {
            r.ok = true; r.pa = pa; r.strategy = "direct-map"; return r;
        }
    }

    // 3) Kernel image (linear).
    if (va >= kStartKernelMap && va < kVmallocStart) {
        PAddr pa = kva_to_pa_image(va, k.kaslr_phys_shift);
        if (probe(pa)) {
            r.ok = true; r.pa = pa; r.strategy = "kernel-image"; return r;
        }
    }

    // 4) Last-ditch PGD walks (rare: dumps captured before direct_map_base is
    //    set up, or where direct_map_base is wrong).
    if (k.dtb_validated) {
        if (auto pa = eng.kernel_pt().translate(va); pa && probe(*pa)) {
            r.ok = true; r.pa = *pa; r.strategy = "fallback-dtb"; return r;
        }
    }
    PAddr init_pgd = resolve_init_mm_pgd_pa(eng);
    if (init_pgd != 0) {
        x86_64::PageTable pt(eng.phys(), init_pgd);
        if (auto pa = pt.translate(va); pa && probe(*pa)) {
            r.ok = true; r.pa = *pa; r.strategy = "fallback-init-mm"; return r;
        }
    }
    return r;
}

} // namespace lmpfs::linux
