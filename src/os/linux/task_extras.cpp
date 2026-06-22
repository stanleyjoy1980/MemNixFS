// task_extras.cpp — see header.
#include "os/linux/task_extras.h"
#include "os/linux/vma.h"
#include "os/linux/kva_reader.h"
#include "os/linux/dentry_path.h"
#include "app/engine.h"
#include "symbols/isf_symbols.h"
#include "core/log.h"
#include <fmt/format.h>
#include <algorithm>
#include <array>
#include <map>
#include <unordered_map>
#include <vector>

namespace lmpfs::linux {

namespace {

// Read a path string from a struct file*'s f_path.dentry chain.
// Reuses the dentry_path infrastructure shared with fdtable/pagecache.
std::string file_to_path(const Engine& eng, VAddr file_va,
                          u64 f_path_off, u64 path_dentry_off,
                          u64 path_mnt_off, const DentryOffsets& dop)
{
    if (file_va == 0) return {};
    VAddr dentry_va = 0, vfsmount_va = 0;
    kva_read_pod(eng, file_va + f_path_off + path_dentry_off, dentry_va);
    kva_read_pod(eng, file_va + f_path_off + path_mnt_off,    vfsmount_va);
    if (!dentry_va) return {};
    return dentry_to_path(eng, dentry_va, vfsmount_va, dop);
}

// Decode task.ptrace bit field into a string. The kernel header
// include/linux/ptrace.h defines:
//   PT_PTRACED         = 0x00000001
//   PT_DTRACE          = 0x00000002
//   PT_SEIZED          = 0x00010000
//   PT_OPT_FLAG_SHIFT  = 3 (PTRACE_O_* in the high bits)
std::string ptrace_flags_str(u32 f) {
    if (f == 0) return "0";
    std::string s;
    auto add = [&](const char* n) { if (!s.empty()) s += "|"; s += n; };
    if (f & 0x00000001) add("PTRACED");
    if (f & 0x00000002) add("DTRACE");
    if (f & 0x00010000) add("SEIZED");
    if (f & 0xff'00'00'00) add("TRACE_*");
    return s.empty() ? fmt::format("{:#x}", f) : s;
}

} // anonymous

ByteBuf gen_libs(const Engine& eng, const Process& p) {
    if (p.mm == 0) {
        const char msg[] = "(kernel thread — no user memory mappings)\n";
        return ByteBuf(msg, msg + sizeof(msg) - 1);
    }

    const auto& isf  = eng.isf();
    const auto& kctx = eng.kernel();

    std::vector<Vma> vmas;
    try { vmas = enumerate_vmas(eng.phys(), isf, kctx, p); }
    catch (...) {
        const char msg[] = "(failed to walk VMAs — see /proc/<pid>/maps)\n";
        return ByteBuf(msg, msg + sizeof(msg) - 1);
    }

    // Resolve struct field offsets once.
    DentryOffsets dop = resolve_dentry_offsets(isf);
    u64 f_path_off = 0, path_dentry_off = 0, path_mnt_off = 0;
    try {
        f_path_off      = isf.field_offset("file",   "f_path");
        path_dentry_off = isf.field_offset("path",   "dentry");
        path_mnt_off    = isf.field_offset("path",   "mnt");
    } catch (...) {
        const char msg[] = "(ISF missing file / path fields)\n";
        return ByteBuf(msg, msg + sizeof(msg) - 1);
    }

    // Group file-backed VMAs by resolved path.
    struct LibInfo {
        std::string  path;
        VAddr        first_start = ~0ULL;
        VAddr        last_end    = 0;
        u64          total       = 0;
        int          n_exec = 0, n_ro = 0, n_rw = 0;
    };
    std::map<std::string, LibInfo> by_path;

    for (const auto& v : vmas) {
        if (v.vm_file == 0) continue;
        std::string path = file_to_path(eng, v.vm_file,
                                         f_path_off, path_dentry_off,
                                         path_mnt_off, dop);
        if (path.empty()) path = fmt::format("(file@{:#x})", v.vm_file);
        auto& li = by_path[path];
        if (li.path.empty()) li.path = path;
        li.first_start = std::min(li.first_start, v.vm_start);
        li.last_end    = std::max(li.last_end,    v.vm_end);
        li.total      += v.vm_end - v.vm_start;
        if      (v.executable()) ++li.n_exec;
        else if (v.writable())   ++li.n_rw;
        else                     ++li.n_ro;
    }

    // Heuristic filter: distinguish "executables / shared libs" from
    // ordinary file-backed data mappings (locales, fonts, etc.). We say
    // it's a library if it has at least one exec mapping.
    std::vector<LibInfo> libs, others;
    for (auto& [_, li] : by_path) {
        if (li.n_exec > 0) libs.push_back(std::move(li));
        else               others.push_back(std::move(li));
    }
    std::sort(libs.begin(), libs.end(),
              [](const LibInfo& a, const LibInfo& b) {
                  return a.first_start < b.first_start;
              });
    std::sort(others.begin(), others.end(),
              [](const LibInfo& a, const LibInfo& b) {
                  return a.first_start < b.first_start;
              });

    std::string out;
    out.reserve(8 * 1024);
    out += fmt::format(
        "# /proc/{}/libs.txt — shared libraries + executables mapped into\n"
        "# pid {} ({}). One row per unique file-backed mapping, deduped by\n"
        "# resolved path. Total {} libraries with executable pages + {}\n"
        "# other file-backed mappings (locales, fonts, …).\n"
        "#\n"
        "# vma_first         vma_last           bytes      vmas         path\n"
        "# ----------------+----------------+-----------+------------+------\n",
        p.pid, p.pid, p.comm, libs.size(), others.size());
    auto emit = [&](const LibInfo& li) {
        out += fmt::format("{:#016x}  {:#016x}  {:>9}  rx={} r--={} rw={}  {}\n",
                           li.first_start, li.last_end, li.total,
                           li.n_exec, li.n_ro, li.n_rw, li.path);
    };
    if (!libs.empty()) {
        out += "# === libraries (has exec pages) ===\n";
        for (const auto& l : libs) emit(l);
    }
    if (!others.empty()) {
        out += "\n# === other file-backed mappings (no exec pages) ===\n";
        for (const auto& l : others) emit(l);
    }
    return ByteBuf(out.begin(), out.end());
}

ByteBuf gen_ptrace(const Engine& eng, const Process& p) {
    const auto& isf = eng.isf();

    // Resolve offsets once. If any is absent (older ISF), return a
    // gentle "(unavailable)" rather than an empty file.
    u64 ptrace_off    = 0;
    u64 parent_off    = 0;
    u64 rparent_off   = 0;
    u64 ptraced_off   = 0;
    u64 ptrace_ent_off = 0;
    u64 pid_off       = 0;
    u64 comm_off      = 0;
    try {
        ptrace_off     = isf.field_offset("task_struct", "ptrace");
        parent_off     = isf.field_offset("task_struct", "parent");
        rparent_off    = isf.field_offset("task_struct", "real_parent");
        ptraced_off    = isf.field_offset("task_struct", "ptraced");
        ptrace_ent_off = isf.field_offset("task_struct", "ptrace_entry");
        pid_off        = isf.field_offset("task_struct", "pid");
        comm_off       = isf.field_offset("task_struct", "comm");
    } catch (const std::exception& e) {
        std::string msg = fmt::format(
            "# /proc/{}/ptrace.txt — ISF missing field: {}\n", p.pid, e.what());
        return ByteBuf(msg.begin(), msg.end());
    }

    auto read_task_brief = [&](VAddr task_va) -> std::pair<u32, std::string> {
        u32 pid = 0;
        std::array<char, 16> comm{};
        if (task_va == 0) return { 0, "(null)" };
        kva_read_pod(eng, task_va + pid_off, pid);
        kva_read(eng, task_va + comm_off, comm.data(), comm.size());
        std::size_t n = 0;
        while (n < comm.size() && comm[n]) ++n;
        return { pid, std::string(comm.data(), n) };
    };

    u32 ptrace_flags = 0;
    kva_read_pod(eng, p.task_va + ptrace_off, ptrace_flags);

    VAddr parent_va  = 0, rparent_va = 0;
    kva_read_pod(eng, p.task_va + parent_off,  parent_va);
    kva_read_pod(eng, p.task_va + rparent_off, rparent_va);

    auto [parent_pid,  parent_comm]  = read_task_brief(parent_va);
    auto [rparent_pid, rparent_comm] = read_task_brief(rparent_va);

    // Walk task.ptraced (list_head of victims). Each ptraced task is
    // linked by its ptrace_entry field. Standard list_head trick:
    //   for (node = head.next; node != &head; node = node->next)
    //     victim = container_of(node, task_struct, ptrace_entry)
    std::vector<std::pair<u32, std::string>> victims;
    VAddr head_va = p.task_va + ptraced_off;
    VAddr first   = 0;
    if (kva_read_pod(eng, head_va, first) && first != 0 && first != head_va) {
        VAddr node = first;
        int   guard = 0;
        while (node != head_va && guard++ < 1024) {
            VAddr victim_va = node - ptrace_ent_off;
            victims.push_back(read_task_brief(victim_va));
            VAddr next = 0;
            if (!kva_read_pod(eng, node, next) || next == node) break;
            node = next;
        }
    }

    std::string out;
    out.reserve(2 * 1024);
    out += fmt::format(
        "# /proc/{}/ptrace.txt — ptrace relationships involving pid {} ({})\n"
        "#\n"
        "ptrace_flags : {} ({:#x})\n"
        "real_parent  : pid={}  comm={}\n"
        "parent       : pid={}  comm={}{}\n",
        p.pid, p.pid, p.comm,
        ptrace_flags_str(ptrace_flags), ptrace_flags,
        rparent_pid, rparent_comm,
        parent_pid,  parent_comm,
        (parent_va != rparent_va)
            ? "   ← differs from real_parent → likely being ptraced"
            : "");

    if (victims.empty()) {
        out += "\nptraced (victims): (none)\n";
    } else {
        out += fmt::format("\nptraced (victims): {} task(s) currently traced by this one\n",
                            victims.size());
        out += fmt::format("  {:>5}  {}\n", "PID", "COMM");
        for (auto& [vpid, vcomm] : victims) {
            out += fmt::format("  {:>5}  {}\n", vpid, vcomm);
        }
    }
    return ByteBuf(out.begin(), out.end());
}

} // namespace lmpfs::linux
