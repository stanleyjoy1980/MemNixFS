// kva_reader.h — multi-strategy kernel-VA → physical reader.
//
// On x86_64 a kernel VA can live in one of three regions, each requiring a
// different translation:
//
//   [0xffff_8000_0000_0000 .. 0xffff_ffff_7fff_ffff]  direct-map (physmap):
//       linear; subtract `direct_map_base`.
//   [0xffff_ffff_8000_0000 .. 0xffff_ffff_bfff_ffff]  kernel image:
//       linear; apply `kaslr_phys_shift`.
//   [0xffff_ffff_c000_0000 .. 0xffff_ffff_ffff_ffff]  vmalloc / modules:
//       arbitrary mapping; only a PGD walk works.
//
// On top of that, the DTB the brute-force resolver finds may walk the
// kernel-image area correctly (it validates against `linux_banner`) but lack
// vmalloc PUD entries — typically the case when the resolver locked onto a
// per-task PGD or the PTI user-half PGD. We fall back to `init_mm.pgd`
// which is guaranteed to be the kernel's master PGD with every kernel-half
// entry populated.
//
// All callers in os/linux/ should use `kva_read` instead of rolling their
// own translation logic — that's how we ended up with three subtly-different
// implementations (dmesg.cpp, modules.cpp, fdtable.cpp) before.
#pragma once
#include "core/types.h"
#include <cstddef>
#include <string>

namespace lmpfs {
class Engine;
}

namespace lmpfs::linux {

// Reads `n` bytes at kernel VA `va` into `dst`. Returns true iff all n bytes
// resolved successfully via one of the strategies above.
bool kva_read(const Engine& eng, VAddr va, void* dst, std::size_t n);

template <typename T>
inline bool kva_read_pod(const Engine& eng, VAddr va, T& out) {
    return kva_read(eng, va, &out, sizeof(T));
}

// Reads a NUL-terminated string at `va`, up to `maxlen` bytes.
std::string kva_read_cstr(const Engine& eng, VAddr va, std::size_t maxlen);

// Translate-only variant: returns the PA `va` maps to via the strategy that
// would succeed, *without* doing the I/O. Used by `/misc/virt2phys/<va>` to
// report the translation result without producing bytes.
//
// `ok=false` means no strategy mapped this VA. On success:
//   strategy ∈ { "direct-map", "kernel-image", "vmalloc-dtb",
//                "vmalloc-init-mm", "fallback-dtb", "fallback-init-mm" }
//
struct KvaTranslate {
    bool        ok       = false;
    PAddr       pa       = 0;
    const char* strategy = "unmapped";
};
KvaTranslate kva_translate(const Engine& eng, VAddr va);

} // namespace lmpfs::linux
