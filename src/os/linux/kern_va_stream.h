// kern_va_stream.h — exposes the kernel virtual-address window as one large
// sparse file (`/mem/kern_va.raw`).
//
// File-offset 0 maps to canonical-kernel-half start (`0xffff_8000_0000_0000`)
// and the file spans 128 TiB — the entire canonical kernel half on 4-level
// paging x86_64. That window covers, in order:
//
//     offset 0x0000_0000_0000 .. 0x7fff_ffff_ffff  (128 TiB)  →
//       VA   0xffff_8000_0000_0000 .. 0xffff_ffff_ffff_ffff
//
//       └─ contains: direct-map / physmap (linear, fastest)
//                    fixmap + vmemmap + cpu_entry_area
//                    KASAN shadow
//                    kernel image (linear via kaslr_phys_shift)
//                    vmalloc + modules (PGD-walked)
//
// Translation per page (4 KiB granularity) is delegated to `kva_read()`,
// which already implements the 3-strategy direct-map / image-shift / PGD-walk
// chain with init_mm.pgd fallback. Pages that don't resolve come back as
// zeros — matches sparse-file semantics and how MemProcFS exposes its
// `/mem.kmem` view.
//
// References:
//   MemProcFS: m_vfsroot.c registers analogous kernel-space views.
//   vol3:      no direct equivalent (vol3 doesn't expose a flat file).
//
#pragma once
#include "core/stream.h"
#include "core/types.h"

namespace lmpfs {
class Engine;
}

namespace lmpfs::linux {

// Stream-reader exposing 128 TiB of kernel virtual address space starting at
// the canonical kernel-half boundary. Thread-safe: every read translates
// independently through `kva_read()`.
class KernVaRawStream : public StreamReader {
public:
    // Canonical kernel-half boundary on 4-level paging x86_64.
    static constexpr VAddr kBase = 0xffff800000000000ULL;
    // 128 TiB — distance from kBase to (kBase + (1<<47) - 1) inclusive +1,
    // i.e. the full canonical kernel half.
    static constexpr u64   kSpan = 0x800000000000ULL;

    explicit KernVaRawStream(const Engine& eng) : eng_(eng) {}

    u64 size() const override { return kSpan; }

    // Reads `len` bytes starting at file-offset `offset`. Always returns
    // `len` (or less only if `offset + len > size()`); unmapped 4-KiB pages
    // are zero-filled. Safe for concurrent dispatchers (kva_read is itself
    // re-entrant on disjoint VAs).
    std::size_t read(u64 offset, void* out, std::size_t len) override;

private:
    const Engine& eng_;
};

} // namespace lmpfs::linux
