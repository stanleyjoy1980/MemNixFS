// btf_probe.h — detect whether a Linux dump carries embedded BTF type info.
//
// BTF (BPF Type Format) is the kernel's compact type information format.
// Kernels built with CONFIG_DEBUG_INFO_BTF=y (Ubuntu ≥ 20.04, Fedora ≥ 32,
// RHEL 8.2+, modern Debian, etc.) embed the entire kernel type universe as a
// small (~3 MB) BTF blob inside the kernel image. Because that blob lives in
// the .BTF ELF section of vmlinux, it ends up in any kernel memory dump.
//
// If present, BTF gives us an offline-capable path to a Volatility ISF: read
// the blob from the dump, run a BTF → ISF converter (deferred, separate
// project), use the result. No vmlinux file, no network, no apt-get.
//
// For now, this probe just reports whether BTF is detectable in the dump.
// The full converter ships as a follow-up.
//
// References:
//   Kernel src: kernel/bpf/btf.c, include/uapi/linux/btf.h
//   pahole -J: builds BTF from DWARF
//   bpftool btf dump file: human-readable BTF dump
//
#pragma once
#include "core/types.h"
#include "formats/physical_layer.h"
#include <optional>
#include <vector>

namespace lmpfs::linux {

struct BtfInfo {
    PAddr offset_pa;   // physical address where BTF starts
    u64   size;        // total size in bytes
    u32   version;     // major:minor in low 16 bits (1.0 = kernels < 5.x BTF)
};

// Scans the dump for ALL plausible BTF blobs. Returns them sorted by size
// descending; the largest is typically the kernel's main `.BTF` section
// (~3 MB on modern Ubuntu/Fedora). Smaller ones are per-module BTFs.
std::vector<BtfInfo> probe_btf_all(const PhysicalLayer& phys);

// Convenience: largest BTF blob, or nullopt if none.
std::optional<BtfInfo> probe_btf(const PhysicalLayer& phys);

// Reads the BTF bytes from the dump into a buffer (suitable for the
// BTF→ISF converter).
ByteBuf read_btf(const PhysicalLayer& phys, const BtfInfo& info);

} // namespace lmpfs::linux
