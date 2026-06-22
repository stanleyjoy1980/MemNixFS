// mountinfo.h — Enumerate the kernel's mount namespace.
//
// On modern (≥ 6.x) Linux, mounts are linked from:
//
//   init_task.nsproxy   → struct nsproxy
//     .mnt_ns           → struct mnt_namespace
//       .root           → struct mount *      (the root mount, mounted on "/")
//       .mounts         → rb_root of all mounts (each rb_node embedded in
//                         struct mount @ mnt_node @ offset 0x40)
//
//   struct mount {
//     ...
//     .mnt_parent       struct mount *        (self for the root mount)
//     .mnt_mountpoint   struct dentry *       (dentry in PARENT's fs where
//                                              this mount is anchored)
//     .mnt              struct vfsmount       (embedded — mnt_root, mnt_sb)
//     .mnt_mounts       struct list_head      (head of child-mount list)
//     .mnt_child        struct list_head      (this mount's link into
//                                              parent.mnt_mounts)
//     .mnt_devname      const char *
//   }
//
// We DFS from the root, using mnt_mounts/mnt_child for the tree shape, and
// compose each mount's global path by calling `dentry_to_path` on
// `mnt_mountpoint` with the *parent* mount's vfsmount as context — that
// reuses the same path-resolution code we already use for /proc/<pid>/fd/.
//
// The output is consumed by the page-cache module to compose true global
// paths (e.g. `/snap/core22/current/usr/bin/bash` instead of just the
// squashfs-local `/usr/bin/bash`), and exposed directly as
// `/sys/mountinfo` for analysts.
#pragma once
#include "core/types.h"
#include "core/stream.h"
#include <string>
#include <unordered_map>
#include <vector>

namespace lmpfs { class Engine; }

namespace lmpfs::linux {

struct MountInfo {
    VAddr       mount_va     = 0;
    VAddr       vfsmount_va  = 0;     // &mount->mnt (i.e. mount_va + 0x20)
    VAddr       parent_va    = 0;
    VAddr       sb_va        = 0;
    VAddr       mnt_root     = 0;     // sb's root dentry
    std::string global_path  = {};    // e.g. "/", "/dev", "/proc", "/snap/core22/current"
    std::string fs_name      = {};    // "ext4", "tmpfs", "squashfs", …
    std::string devname      = {};    // mount->mnt_devname (the device string)
    u32         mnt_id       = 0;
    bool        is_root      = false; // mount->mnt_parent == mount
};

// Walks `init_task.nsproxy.mnt_ns.root` recursively via mnt_mounts/mnt_child.
// Returns the full list of mounts in this kernel's primary namespace, each
// with a fully-composed global path. Empty if any of the required ISF
// symbols are missing or the DTB hasn't been validated.
std::vector<MountInfo> enumerate_mounts(const Engine& eng);

// Map sb_va → "primary" mount (the first one we find for each sb). Lets the
// page-cache module turn an `inode.i_sb` into a vfsmount for dentry_to_path.
std::unordered_map<VAddr, MountInfo> build_sb_to_mount_map(
    const std::vector<MountInfo>& mounts);

// `/proc/mountinfo`-style formatted listing, exposed at /sys/mountinfo.
ByteBuf format_mountinfo(const Engine& eng);

} // namespace lmpfs::linux
