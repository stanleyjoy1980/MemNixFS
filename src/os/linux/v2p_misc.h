// v2p_misc.h — dynamic VFS nodes for ad-hoc virtual↔physical address
// translation. Modeled after MemProcFS's `/misc/virt2phys` and
// `/misc/phys2virt`, but reshaped for our read-only stateless VFS:
//
// Instead of MemProcFS's "echo VA > virt2phys, cat virt2phys" pattern
// (which needs a writable file and per-handle state), we encode the
// query in the path:
//
//     /misc/virt2phys/0xffffffffa7fb3580
//     /misc/virt2phys/0xffffffffa7fb3580.txt
//     /misc/virt2phys/ffffffffa7fb3580           ← bare hex also OK
//
// Reading the file returns a 1-line text report:
//
//     VA       : 0xffffffffa7fb3580
//     PA       : 0x48bb3580
//     Strategy : kernel-image
//     Notes    : linear; VA - 0xffffffff80000000 + kaslr_phys_shift
//
// This is friendly to scripting (`cat /misc/virt2phys/0x…` is one op),
// bookmarkable in Explorer, and trivially concurrency-safe (no shared
// state, no per-open buffer).
//
// References:
//   MemProcFS: m_proc_virt2phys.c (per-process), m_phys2virt.c.
//   vol3:      no direct equivalent.
//
#pragma once
#include "vfs/vfs.h"

namespace lmpfs {
class Engine;
}

namespace lmpfs::linux {

// Mounted at /misc/virt2phys/. `list()` returns just the README.
// `find(<name>)` parses <name> as hex (with or without `0x` prefix and
// `.txt` suffix), translates the VA, and returns a LazyFileNode whose
// content is the human-readable translation report.
//
// Engine reference is captured by value — the engine outlives the VFS
// (engine owns the tree).
vfs::NodePtr build_virt2phys_dir(const Engine& eng);

// Mounted at /misc/phys2virt/. Path-encoded the same way:
//   /misc/phys2virt/0x48bb3580
// Reports the VAs that map to that PA via the kernel views:
//   * direct-map alias  (PA + direct_map_base)         — always
//   * kernel-image alias (PA - kaslr_phys_shift +
//                         0xffffffff80000000)          — when PA is in
//                                                        image span
// We do NOT scan every PGD entry — that's a full reverse-map walk and is
// O(n) over the entire address space. The direct-map / image aliases
// cover the forensically interesting cases (kernel data + kernel code).
// A future enhancement could walk the kernel PGD for vmalloc-region
// reverse mappings; for now we say so in the report.
vfs::NodePtr build_phys2virt_dir(const Engine& eng);

} // namespace lmpfs::linux
