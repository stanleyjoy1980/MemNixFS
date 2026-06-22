// dentry_path.h — Linux dentry → absolute path resolution.
//
// The kernel's `d_path()` function walks `d_parent` up to the filesystem
// root, then container_of()s the `vfsmount` into `struct mount`, hops to
// `mnt_parent.mnt` + `mnt_mountpoint`, and continues in the parent fs.
// This mirrors that logic. Used by:
//
//   * fdtable.cpp     — to label each `struct file*` with its source path
//   * pagecache.cpp   — to label each cached inode (via i_dentry.first)
//
// All offsets live in `DentryOffsets`; resolve them once per use site, then
// pass the struct around to avoid hammering the ISF for every lookup.
#pragma once
#include "core/types.h"
#include "symbols/isf_symbols.h"
#include <string>

namespace lmpfs {
class Engine;
}

namespace lmpfs::linux {

struct DentryOffsets {
    // dentry fields
    u64 d_parent    = 0;
    u64 d_name      = 0;     // qstr embedded
    u64 d_iname     = 0;     // inline shortname (d_iname or d_shortname); 0 = absent
    u64 d_inode     = 0;
    u64 qstr_len    = 0;
    u64 qstr_name   = 0;
    // mount-point traversal (optional — ok=false means "stop at fs root")
    u64 vfsmount_in_mount = 0x20;
    u64 mnt_parent        = 0x10;
    u64 mnt_mountpoint    = 0x18;
    bool mount_ok = false;
    // inode → dentry (optional; used by pagecache)
    u64 inode_i_dentry  = 0;
    u64 hlist_first_off = 0;     // hlist_head.first == offset 0
    u64 dentry_d_alias  = 0;     // dentry.d_u.d_alias linkage; varies per kernel
};

DentryOffsets resolve_dentry_offsets(const IsfSymbols& isf);

// Walk `dentry_va` (with optional mount context `vfsmount_va`) up to the
// global root, producing an absolute path. Returns "(null)" if dentry_va==0,
// "/" if the dentry IS the root, or a partial path with "?" placeholders if
// any intermediate component is unreadable.
std::string dentry_to_path(const Engine& eng,
                            VAddr dentry_va, VAddr vfsmount_va,
                            const DentryOffsets& d);

} // namespace lmpfs::linux
