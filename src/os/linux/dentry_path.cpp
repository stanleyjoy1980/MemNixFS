// dentry_path.cpp — see header.
#include "os/linux/dentry_path.h"
#include "os/linux/kva_reader.h"
#include "app/engine.h"
#include "core/log.h"
#include <vector>

namespace lmpfs::linux {

namespace {

// Read a dentry's leaf name. Tries qstr.name (long names, kmalloc'd buffer)
// first; falls back to the inline shortname union (d_shortname/d_iname).
std::string read_dentry_name(const Engine& eng, VAddr dentry_va,
                              const DentryOffsets& d)
{
    if (dentry_va == 0) return {};

    u32 name_len = 0;
    VAddr name_ptr = 0;
    kva_read_pod(eng, dentry_va + d.d_name + d.qstr_len,  name_len);
    kva_read_pod(eng, dentry_va + d.d_name + d.qstr_name, name_ptr);

    if (name_len > 0 && name_len <= 255 && name_ptr != 0) {
        std::vector<char> buf(name_len + 1, 0);
        if (kva_read(eng, name_ptr, buf.data(), name_len))
            return std::string(buf.data(), name_len);
    }

    if (d.d_iname == 0) return {};
    constexpr std::size_t kInlineCap = 40;
    std::vector<char> in(kInlineCap, 0);
    if (kva_read(eng, dentry_va + d.d_iname, in.data(), kInlineCap)) {
        std::size_t n = 0;
        while (n < kInlineCap && in[n]) ++n;
        return std::string(in.data(), n);
    }
    return {};
}

} // anonymous

DentryOffsets resolve_dentry_offsets(const IsfSymbols& isf) {
    DentryOffsets d{};
    try {
        d.d_parent  = isf.field_offset("dentry", "d_parent");
        d.d_name    = isf.field_offset("dentry", "d_name");
        d.d_inode   = isf.field_offset("dentry", "d_inode");
        d.qstr_len  = isf.field_offset("qstr",   "len");
        d.qstr_name = isf.field_offset("qstr",   "name");
    } catch (const std::exception& e) {
        log::debug("dentry_path: required field missing — {}", e.what());
        return d;
    }
    // Inline shortname — different name across kernels.
    try { d.d_iname = isf.field_offset("dentry", "d_shortname"); }
    catch (...) {
        try { d.d_iname = isf.field_offset("dentry", "d_iname"); }
        catch (...) { d.d_iname = 0; }
    }
    // Mount-point hop fields.
    try {
        d.vfsmount_in_mount = isf.field_offset("mount", "mnt");
        d.mnt_parent        = isf.field_offset("mount", "mnt_parent");
        d.mnt_mountpoint    = isf.field_offset("mount", "mnt_mountpoint");
        d.mount_ok = true;
    } catch (const std::exception& e) {
        log::debug("dentry_path: mount fields missing — {}", e.what());
        d.mount_ok = false;
    }
    // inode → dentry linkage (used by pagecache).
    try {
        d.inode_i_dentry = isf.field_offset("inode", "i_dentry");
        // d_u is a union inside dentry; its first member historically is
        // d_alias (hlist_node), used by the kernel to chain dentries that
        // share an inode. The ISF often exposes only the union, not its
        // members — fall back to the union's offset directly.
        d.dentry_d_alias = isf.field_offset("dentry", "d_u");
    } catch (...) {
        d.inode_i_dentry = 0;
        d.dentry_d_alias = 0xb0;   // x86_64 6.x layout fallback
    }
    return d;
}

std::string dentry_to_path(const Engine& eng,
                            VAddr dentry_va, VAddr vfsmount_va,
                            const DentryOffsets& d)
{
    if (dentry_va == 0)        return "(null)";
    if (d.d_parent == 0)       return "(no-dentry-offsets)";

    std::vector<std::string> parts;
    VAddr cur     = dentry_va;
    VAddr cur_mnt = vfsmount_va;
    int depth     = 0;
    while (cur != 0 && depth++ < 256) {
        VAddr parent = 0;
        if (!kva_read_pod(eng, cur + d.d_parent, parent)) break;

        std::string n = read_dentry_name(eng, cur, d);

        const bool at_fs_root = (parent == cur);
        if (!at_fs_root) {
            if (n != "/" && !n.empty()) parts.push_back(std::move(n));
            cur = parent;
            continue;
        }

        // Hit fs root. If we have mount metadata, hop to the parent mount.
        if (!d.mount_ok || cur_mnt == 0) break;

        VAddr mount_va         = cur_mnt - d.vfsmount_in_mount;
        VAddr parent_mount     = 0;
        VAddr mountpoint_dentry = 0;
        if (!kva_read_pod(eng, mount_va + d.mnt_parent,     parent_mount)) break;
        if (!kva_read_pod(eng, mount_va + d.mnt_mountpoint, mountpoint_dentry)) break;
        if (parent_mount == mount_va || parent_mount == 0 ||
            mountpoint_dentry == 0)
            break;

        cur     = mountpoint_dentry;
        cur_mnt = parent_mount + d.vfsmount_in_mount;
    }

    if (parts.empty()) return "/";
    std::string out;
    for (auto it = parts.rbegin(); it != parts.rend(); ++it) {
        out += '/';
        out += *it;
    }
    return out;
}

} // namespace lmpfs::linux
