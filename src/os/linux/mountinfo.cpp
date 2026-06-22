// mountinfo.cpp — see header.
#include "os/linux/mountinfo.h"
#include "os/linux/kva_reader.h"
#include "os/linux/dentry_path.h"
#include "app/engine.h"
#include "symbols/isf_symbols.h"
#include "core/log.h"
#include <fmt/format.h>

namespace lmpfs::linux {

namespace {

struct Off {
    // task_struct
    u64 ts_nsproxy = 0;
    // nsproxy
    u64 ns_mnt_ns = 0;
    // mnt_namespace
    u64 mns_root = 0;
    // mount
    u64 m_mnt_parent  = 0;
    u64 m_mnt_mountpt = 0;
    u64 m_mnt         = 0;   // embedded vfsmount
    u64 m_mnt_mounts  = 0;   // list_head of children
    u64 m_mnt_child   = 0;   // this mount's link in parent's mnt_mounts
    u64 m_mnt_devname = 0;
    u64 m_mnt_id      = 0;
    // vfsmount
    u64 vfs_mnt_root = 0;
    u64 vfs_mnt_sb   = 0;
    // super_block
    u64 sb_s_type = 0;
    u64 sb_s_id   = 0;
    // file_system_type
    u64 fst_name = 0;
    bool ok = false;
};

Off resolve_offsets(const IsfSymbols& isf) {
    Off o{};
    try {
        o.ts_nsproxy   = isf.field_offset("task_struct",     "nsproxy");
        o.ns_mnt_ns    = isf.field_offset("nsproxy",         "mnt_ns");
        o.mns_root     = isf.field_offset("mnt_namespace",   "root");
        o.m_mnt_parent = isf.field_offset("mount",           "mnt_parent");
        o.m_mnt_mountpt= isf.field_offset("mount",           "mnt_mountpoint");
        o.m_mnt        = isf.field_offset("mount",           "mnt");
        o.m_mnt_mounts = isf.field_offset("mount",           "mnt_mounts");
        o.m_mnt_child  = isf.field_offset("mount",           "mnt_child");
        o.vfs_mnt_root = isf.field_offset("vfsmount",        "mnt_root");
        o.vfs_mnt_sb   = isf.field_offset("vfsmount",        "mnt_sb");
        o.sb_s_type    = isf.field_offset("super_block",     "s_type");
        o.sb_s_id      = isf.field_offset("super_block",     "s_id");
        o.fst_name     = isf.field_offset("file_system_type","name");
        o.ok = true;
    } catch (const std::exception& e) {
        log::warn("mountinfo: ISF missing field — {}", e.what());
        return o;
    }
    // Optional fields — best-effort.
    try { o.m_mnt_devname = isf.field_offset("mount", "mnt_devname"); } catch (...) {}
    try { o.m_mnt_id      = isf.field_offset("mount", "mnt_id"); }      catch (...) {}
    return o;
}

// Read a `char *` field's string content from a kernel struct.
std::string read_kernel_strp(const Engine& eng, VAddr struct_va, u64 field_off,
                              std::size_t maxlen)
{
    VAddr p = 0;
    if (!kva_read_pod(eng, struct_va + field_off, p) || p == 0) return {};
    return kva_read_cstr(eng, p, maxlen);
}

// DFS the mount tree starting from `root_mount_va`. We use mnt_mounts /
// mnt_child for the tree shape; mnt_parent/mnt_mountpoint for path
// composition.
void walk_mount_tree(const Engine& eng, const Off& o,
                      VAddr mount_va, VAddr parent_va,
                      const DentryOffsets& dop,
                      std::vector<MountInfo>& out, int depth = 0)
{
    if (mount_va == 0 || depth > 1024) return;

    MountInfo mi{};
    mi.mount_va    = mount_va;
    mi.vfsmount_va = mount_va + o.m_mnt;
    mi.parent_va   = parent_va;
    mi.is_root     = (parent_va == 0) || (parent_va == mount_va);

    // vfsmount.mnt_sb
    kva_read_pod(eng, mi.vfsmount_va + o.vfs_mnt_sb,   mi.sb_va);
    kva_read_pod(eng, mi.vfsmount_va + o.vfs_mnt_root, mi.mnt_root);

    // file-system name
    if (mi.sb_va != 0) {
        VAddr fst = 0;
        if (kva_read_pod(eng, mi.sb_va + o.sb_s_type, fst) && fst != 0)
            mi.fs_name = read_kernel_strp(eng, fst, o.fst_name, 32);
        if (mi.fs_name.empty()) {
            // s_id is an inline char array
            std::string id(32, 0);
            kva_read(eng, mi.sb_va + o.sb_s_id, id.data(), id.size());
            std::size_t k = 0;
            while (k < id.size() && id[k]) ++k;
            mi.fs_name = std::string(id.data(), k);
        }
    }

    if (o.m_mnt_devname) {
        mi.devname = read_kernel_strp(eng, mount_va, o.m_mnt_devname, 64);
    }
    if (o.m_mnt_id) {
        kva_read_pod(eng, mount_va + o.m_mnt_id, mi.mnt_id);
    }

    // Compose the global path of THIS mount's mountpoint.
    if (mi.is_root) {
        mi.global_path = "/";
    } else {
        // Look up mountpoint dentry, then resolve via parent's vfsmount.
        VAddr mp_dentry = 0;
        kva_read_pod(eng, mount_va + o.m_mnt_mountpt, mp_dentry);
        VAddr parent_vfsmount = parent_va + o.m_mnt;
        mi.global_path = dentry_to_path(eng, mp_dentry, parent_vfsmount, dop);
        if (mi.global_path == "(null)" || mi.global_path.empty())
            mi.global_path = fmt::format("(unknown mount @ {:#x})", mount_va);
    }

    out.push_back(mi);

    // Recurse into children via mnt_mounts list (head) →
    // each child has its mnt_child linkage pointing here.
    VAddr children_head = mount_va + o.m_mnt_mounts;
    VAddr child_link = 0;
    if (!kva_read_pod(eng, children_head, child_link)) return;
    while (child_link != 0 && child_link != children_head) {
        VAddr child_mount = child_link - o.m_mnt_child;
        walk_mount_tree(eng, o, child_mount, mount_va, dop, out, depth + 1);
        VAddr next = 0;
        if (!kva_read_pod(eng, child_link, next)) break;
        if (next == child_link) break;
        child_link = next;
    }
}

} // anonymous

std::vector<MountInfo> enumerate_mounts(const Engine& eng) {
    std::vector<MountInfo> out;
    const auto& isf  = eng.isf();
    const auto& kctx = eng.kernel();

    Off o = resolve_offsets(isf);
    if (!o.ok) return out;

    // Prefer the ISF symbol, but fall back to the address the kernel resolver
    // already recovered via the swapper signature scan. On a BTF-only ISF the
    // `init_task` symbol is absent (BTF carries types, not symbol addresses),
    // yet kctx.init_task_va is still populated — so mounts (and the dcache
    // tree walk that seeds off them) work without any DWARF/kallsyms symbols.
    VAddr init_task_va = 0;
    if (auto* sym = isf.find_symbol("init_task"); sym && sym->address)
        init_task_va = sym->address;
    else if (kctx.init_task_va)
        init_task_va = kctx.init_task_va;

    if (init_task_va == 0) {
        log::debug("mountinfo: no init_task address (neither ISF symbol nor "
                   "resolved kctx.init_task_va) — cannot find mnt_ns");
        return out;
    }

    DentryOffsets dop = resolve_dentry_offsets(isf);

    // Read init_task.nsproxy → mnt_ns → root
    VAddr nsproxy = 0;
    if (!kva_read_pod(eng, init_task_va + o.ts_nsproxy, nsproxy) || nsproxy == 0) {
        log::warn("mountinfo: cannot read init_task.nsproxy @ {:#x}",
                  init_task_va + o.ts_nsproxy);
        return out;
    }
    VAddr mnt_ns = 0;
    if (!kva_read_pod(eng, nsproxy + o.ns_mnt_ns, mnt_ns) || mnt_ns == 0) {
        log::warn("mountinfo: cannot read nsproxy.mnt_ns");
        return out;
    }
    VAddr root_mount = 0;
    if (!kva_read_pod(eng, mnt_ns + o.mns_root, root_mount) || root_mount == 0) {
        log::warn("mountinfo: cannot read mnt_namespace.root");
        return out;
    }
    log::debug("mountinfo: root mount = {:#x}", root_mount);

    walk_mount_tree(eng, o, root_mount, /*parent=*/0, dop, out);
    log::info("mountinfo: enumerated {} mount(s) in init namespace", out.size());
    return out;
}

std::unordered_map<VAddr, MountInfo>
build_sb_to_mount_map(const std::vector<MountInfo>& mounts)
{
    std::unordered_map<VAddr, MountInfo> m;
    m.reserve(mounts.size());
    // Iterate in tree-DFS order so /'s root mount lands first and bind
    // mounts under it don't shadow it.
    for (const auto& mi : mounts) {
        if (mi.sb_va == 0) continue;
        m.emplace(mi.sb_va, mi);  // emplace skips if already present
    }
    return m;
}

ByteBuf format_mountinfo(const Engine& eng) {
    auto mounts = enumerate_mounts(eng);
    if (mounts.empty()) {
        const char msg[] =
            "; could not enumerate mounts — ISF missing fields, or DTB not\n"
            "; validated (vmalloc reads disabled).\n";
        return ByteBuf(msg, msg + sizeof(msg) - 1);
    }
    std::string out;
    out.reserve(8 * 1024);
    out += fmt::format("# {} mounts in init mount namespace\n"
                       "# id  fs           device                "
                       "global-path\n"
                       "#----+------------+--------------------+"
                       "-------------------------------\n",
                       mounts.size());
    for (const auto& m : mounts) {
        out += fmt::format("{:>4}  {:<12} {:<20}  {}\n",
                           m.mnt_id,
                           m.fs_name.empty() ? "?" : m.fs_name,
                           m.devname.empty() ? "-" : m.devname,
                           m.global_path);
    }
    return ByteBuf(out.begin(), out.end());
}

} // namespace lmpfs::linux
