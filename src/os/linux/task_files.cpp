// task_files.cpp — Linux-style /proc/<pid>/* generators.
//
// Algorithms cross-referenced against:
//   volatility3/framework/plugins/linux/envars.py     (argv / environ walk)
//   volatility3/framework/plugins/linux/psaux.py      (status fields)
//   volatility3/framework/plugins/linux/proc.py       (maps format)
//   MemProcFS/vmm/modules/m_misc_procinfo.c           (output shape)
//   MemProcFS/vmm/modules/m_proc_memmap.c             (maps shape)
//
#include "os/linux/task_files.h"
#include "arch/x86_64/paging.h"
#include "core/error.h"
#include "core/log.h"
#include <fmt/format.h>
#include <algorithm>
#include <cstring>

namespace lmpfs::linux {

namespace {

// --- direct-map helpers (kernel slab pointers) ---
bool dm_pa(VAddr va, const KernelContext& k, PAddr max_pa, PAddr& out) {
    if (va < k.direct_map_base) return false;
    u64 off = va - k.direct_map_base;
    if (off >= max_pa) return false;
    out = off; return true;
}
template <typename T>
bool read_dm(const PhysicalLayer& phys, const KernelContext& k, VAddr va, T& v) {
    static_assert(std::is_trivially_copyable_v<T>);
    PAddr pa; if (!dm_pa(va, k, phys.max_address(), pa)) return false;
    return phys.read_pod(pa, v);
}

// Read user-space bytes via a process's own PGD.
ByteBuf read_user_range(const PhysicalLayer& phys, const IsfSymbols& isf,
                        const KernelContext& kctx, const Process& p,
                        u64 va_start, u64 va_end, u64 sanity_cap = (16ULL << 20))
{
    if (p.mm == 0 || va_start >= va_end) return {};
    PAddr pgd = resolve_user_pgd(phys, isf, kctx, p);
    if (pgd == 0) return {};
    x86_64::PageTable pt(phys, pgd);
    u64 len = std::min<u64>(va_end - va_start, sanity_cap);
    ByteBuf out(len);
    pt.read(va_start, out.data(), len);
    return out;
}

// Read a u64 from a kernel struct that lives in the direct map (e.g. mm_struct).
u64 read_struct_u64(const PhysicalLayer& phys, const KernelContext& kctx,
                    VAddr struct_va, u64 field_off, u64 fallback = 0)
{
    u64 v = fallback;
    read_dm(phys, kctx, struct_va + field_off, v);
    return v;
}
u32 read_struct_u32(const PhysicalLayer& phys, const KernelContext& kctx,
                    VAddr struct_va, u64 field_off, u32 fallback = 0)
{
    u32 v = fallback;
    read_dm(phys, kctx, struct_va + field_off, v);
    return v;
}

// Trim trailing NULs so cmdline-style buffers don't include the slack at the
// end of the page where the kernel zero-pads.
ByteBuf trim_trailing_nuls(ByteBuf b) {
    while (!b.empty() && b.back() == 0) b.pop_back();
    return b;
}

const char* state_name(u32 s) {
    // include/linux/sched.h
    switch (s) {
        case 0x0000: return "R (running)";
        case 0x0001: return "S (sleeping)";
        case 0x0002: return "D (disk sleep)";
        case 0x0004: return "T (stopped)";
        case 0x0008: return "t (tracing stop)";
        case 0x0010: return "X (dead)";
        case 0x0020: return "Z (zombie)";
        case 0x0040: return "P (parked)";
        case 0x0080: return "I (idle)";
        default:     return "? (unknown)";
    }
}

// Map our Vma flags bitfield back to the rwxp string used by /proc/PID/maps.
void perm_string(const Vma& v, char buf[5]) {
    buf[0] = v.readable()   ? 'r' : '-';
    buf[1] = v.writable()   ? 'w' : '-';
    buf[2] = v.executable() ? 'x' : '-';
    buf[3] = 'p'; // private mappings; we don't reliably distinguish shared yet
    buf[4] = '\0';
}

} // anonymous

ByteBuf gen_cmdline(const PhysicalLayer& phys, const IsfSymbols& isf,
                    const KernelContext& kctx, const Process& p)
{
    if (p.mm == 0) return {};
    u64 arg_start_off = isf.field_offset("mm_struct", "arg_start");
    u64 arg_end_off   = isf.field_offset("mm_struct", "arg_end");
    u64 arg_start = read_struct_u64(phys, kctx, p.mm, arg_start_off);
    u64 arg_end   = read_struct_u64(phys, kctx, p.mm, arg_end_off);
    auto bytes = read_user_range(phys, isf, kctx, p, arg_start, arg_end);
    return trim_trailing_nuls(std::move(bytes));
}

ByteBuf gen_environ(const PhysicalLayer& phys, const IsfSymbols& isf,
                    const KernelContext& kctx, const Process& p)
{
    auto explain = [](const std::string& s) {
        return ByteBuf(s.begin(), s.end());
    };
    if (p.mm == 0) {
        return explain(fmt::format(
            "; pid {} ({}) has no mm_struct; kernel threads do not have "
            "a user environment.\n", p.pid, p.comm));
    }
    u64 env_start_off = 0, env_end_off = 0;
    try {
        env_start_off = isf.field_offset("mm_struct", "env_start");
        env_end_off   = isf.field_offset("mm_struct", "env_end");
    } catch (const std::exception& e) {
        return explain(fmt::format(
            "; cannot read environment for pid {} ({}): ISF is missing "
            "mm_struct env offsets: {}\n", p.pid, p.comm, e.what()));
    }
    PAddr pgd = resolve_user_pgd(phys, isf, kctx, p);
    if (pgd == 0) {
        return explain(fmt::format(
            "; cannot read environment for pid {} ({}): user PGD could not "
            "be resolved from mm_struct.\n", p.pid, p.comm));
    }
    u64 env_start = read_struct_u64(phys, kctx, p.mm, env_start_off);
    u64 env_end   = read_struct_u64(phys, kctx, p.mm, env_end_off);
    if (env_start == 0 || env_end == 0 || env_end < env_start) {
        return explain(fmt::format(
            "; cannot read environment for pid {} ({}): invalid env range "
            "start={:#x} end={:#x}.\n", p.pid, p.comm, env_start, env_end));
    }
    if (env_start == env_end) {
        return explain(fmt::format(
            "; pid {} ({}) has an empty environment range.\n", p.pid, p.comm));
    }
    auto bytes = read_user_range(phys, isf, kctx, p, env_start, env_end);
    bytes = trim_trailing_nuls(std::move(bytes));
    if (bytes.empty()) {
        return explain(fmt::format(
            "; environment range for pid {} ({}) is mapped as unreadable or "
            "non-resident: start={:#x} end={:#x}.\n",
            p.pid, p.comm, env_start, env_end));
    }
    return bytes;
}

ByteBuf gen_comm(const Process& p) {
    std::string s = p.comm;
    s.push_back('\n');
    return ByteBuf(s.begin(), s.end());
}

ByteBuf gen_maps(const std::vector<Vma>& vmas) {
    std::string out;
    out.reserve(vmas.size() * 80);
    for (const auto& v : vmas) {
        char perm[5]; perm_string(v, perm);
        // Linux fs/proc/task_mmu.c show_map_vma(): anonymous mappings display
        // pgoff = 0; file-backed mappings display vm_pgoff << PAGE_SHIFT.
        u64 pgoff = v.vm_file ? (v.vm_pgoff * 0x1000ULL) : 0;
        out += fmt::format(
            "{:012x}-{:012x} {} {:08x} 00:00 {:<10} {}\n",
            v.vm_start, v.vm_end, perm, pgoff, /*inode=*/0,
            v.vm_file ? "[mapped]" : "");
    }
    return ByteBuf(out.begin(), out.end());
}

ByteBuf gen_status(const PhysicalLayer& phys, const IsfSymbols& isf,
                   const KernelContext& kctx, const Process& p)
{
    // Pull what we can; fall back gracefully where ISF lookup fails.
    u64 state_off = 0, fs_off = 0;
    try { state_off = isf.field_offset("task_struct", "__state"); } catch (...) {}
    try { fs_off    = isf.field_offset("task_struct", "fs");      } catch (...) {}

    u32 state_val = state_off ? read_struct_u32(phys, kctx, p.task_va, state_off) : 0;

    // Credentials — re-read so we get the full set (suid/sgid/fsuid/fsgid).
    u64 cred_off  = isf.field_offset("task_struct", "cred");
    u64 cred_va   = read_struct_u64(phys, kctx, p.task_va, cred_off);

    u32 uid = p.uid, gid = p.gid;
    u32 euid = uid, egid = gid, suid = uid, sgid = gid, fsuid = uid, fsgid = gid;
    if (cred_va) {
        suid  = read_struct_u32(phys, kctx, cred_va, isf.field_offset("cred", "suid"),  uid);
        sgid  = read_struct_u32(phys, kctx, cred_va, isf.field_offset("cred", "sgid"),  gid);
        euid  = read_struct_u32(phys, kctx, cred_va, isf.field_offset("cred", "euid"),  uid);
        egid  = read_struct_u32(phys, kctx, cred_va, isf.field_offset("cred", "egid"),  gid);
        fsuid = read_struct_u32(phys, kctx, cred_va, isf.field_offset("cred", "fsuid"), uid);
        fsgid = read_struct_u32(phys, kctx, cred_va, isf.field_offset("cred", "fsgid"), gid);
    }

    // Umask via fs_struct (best-effort: zero if fs == NULL).
    u32 umask = 0;
    if (fs_off) {
        u64 fs_va = read_struct_u64(phys, kctx, p.task_va, fs_off);
        if (fs_va) {
            try {
                u64 umask_off = isf.field_offset("fs_struct", "umask");
                umask = read_struct_u32(phys, kctx, fs_va, umask_off);
            } catch (...) {}
        }
    }

    std::string out = fmt::format(
        "Name:\t{}\n"
        "Umask:\t{:04o}\n"
        "State:\t{}\n"
        "Tgid:\t{}\n"
        "Pid:\t{}\n"
        "PPid:\t{}\n"
        "TracerPid:\t0\n"
        "Uid:\t{}\t{}\t{}\t{}\n"
        "Gid:\t{}\t{}\t{}\t{}\n",
        p.comm, umask, state_name(state_val),
        p.tgid, p.pid, p.ppid,
        uid, euid, suid, fsuid,
        gid, egid, sgid, fsgid);
    return ByteBuf(out.begin(), out.end());
}

// ---------------------------------------------------------------------------
//  /proc/<pid>/stat — see fs/proc/array.c do_task_stat().
//  Compatible with `ps`, `top`, htop.
// ---------------------------------------------------------------------------
ByteBuf gen_stat(const PhysicalLayer& phys, const IsfSymbols& isf,
                 const KernelContext& kctx, const Process& p)
{
    char state_c = '?';
    try {
        u64 state_off = isf.field_offset("task_struct", "__state");
        u32 sv = read_struct_u32(phys, kctx, p.task_va, state_off);
        switch (sv) {
            case 0x0: state_c = 'R'; break;
            case 0x1: state_c = 'S'; break;
            case 0x2: state_c = 'D'; break;
            case 0x4: state_c = 'T'; break;
            case 0x8: state_c = 't'; break;
            case 0x10: state_c = 'X'; break;
            case 0x20: state_c = 'Z'; break;
            case 0x40: state_c = 'P'; break;
            case 0x80: state_c = 'I'; break;
            default:  state_c = 'S'; break;
        }
    } catch (...) {}

    u64 vsize = 0, rss = 0, start_code = 0, end_code = 0;
    u64 start_stack = 0, arg_start = 0, arg_end = 0, env_start = 0, env_end = 0;
    u64 start_data = 0, end_data = 0, start_brk = 0;
    u64 starttime = 0, utime = 0, stime = 0;
    try {
        if (p.mm) {
            vsize       = read_struct_u64(phys, kctx, p.mm, isf.field_offset("mm_struct", "total_vm")) * 0x1000ULL;
            rss         = read_struct_u64(phys, kctx, p.mm, isf.field_offset("mm_struct", "total_vm"));
            start_code  = read_struct_u64(phys, kctx, p.mm, isf.field_offset("mm_struct", "start_code"));
            end_code    = read_struct_u64(phys, kctx, p.mm, isf.field_offset("mm_struct", "end_code"));
            start_stack = read_struct_u64(phys, kctx, p.mm, isf.field_offset("mm_struct", "start_stack"));
            arg_start   = read_struct_u64(phys, kctx, p.mm, isf.field_offset("mm_struct", "arg_start"));
            arg_end     = read_struct_u64(phys, kctx, p.mm, isf.field_offset("mm_struct", "arg_end"));
            env_start   = read_struct_u64(phys, kctx, p.mm, isf.field_offset("mm_struct", "env_start"));
            env_end     = read_struct_u64(phys, kctx, p.mm, isf.field_offset("mm_struct", "env_end"));
            start_data  = read_struct_u64(phys, kctx, p.mm, isf.field_offset("mm_struct", "start_data"));
            end_data    = read_struct_u64(phys, kctx, p.mm, isf.field_offset("mm_struct", "end_data"));
            start_brk   = read_struct_u64(phys, kctx, p.mm, isf.field_offset("mm_struct", "start_brk"));
        }
    } catch (...) {}
    try {
        starttime = read_struct_u64(phys, kctx, p.task_va, isf.field_offset("task_struct", "start_time"));
        utime     = read_struct_u64(phys, kctx, p.task_va, isf.field_offset("task_struct", "utime"));
        stime     = read_struct_u64(phys, kctx, p.task_va, isf.field_offset("task_struct", "stime"));
    } catch (...) {}

    // Format: 52 space-separated fields per fs/proc/array.c do_task_stat().
    // We fill the ones we have; the rest are zero. The (comm) is wrapped in
    // parens and may contain spaces.
    std::string out = fmt::format(
        "{} ({}) {} "                  // pid comm state
        "{} 0 0 0 0 "                  // ppid pgrp session tty_nr tpgid
        "0 0 0 0 0 "                   // flags minflt cminflt majflt cmajflt
        "{} {} 0 0 "                   // utime stime cutime cstime
        "20 0 1 0 "                    // priority nice num_threads itrealvalue
        "{} {} {} 0 "                  // starttime vsize rss rsslim
        "{} {} {} 0 0 "                // startcode endcode startstack kstkesp kstkeip
        "0 0 0 0 "                     // signal blocked sigignore sigcatch (obsolete)
        "0 0 0 0 0 0 0 0 0 "           // wchan nswap cnswap exit_signal processor rt_priority policy delayacct_blkio_ticks guest_time
        "0 {} {} {} {} {} {} {} 0\n",  // cguest_time start_data end_data start_brk arg_start arg_end env_start env_end exit_code
        p.pid, p.comm, state_c,
        p.ppid,
        utime, stime,
        starttime, vsize, rss,
        start_code, end_code, start_stack,
        start_data, end_data, start_brk, arg_start, arg_end, env_start, env_end);
    return ByteBuf(out.begin(), out.end());
}

// ---------------------------------------------------------------------------
//  /proc/<pid>/statm — "size resident shared text lib data dt" in pages.
// ---------------------------------------------------------------------------
ByteBuf gen_statm(const PhysicalLayer& phys, const IsfSymbols& isf,
                  const KernelContext& kctx, const Process& p)
{
    if (!p.mm) {
        std::string s = "0 0 0 0 0 0 0\n";
        return ByteBuf(s.begin(), s.end());
    }
    u64 total = 0, shared = 0, exec = 0, data = 0, stack = 0;
    try {
        total  = read_struct_u64(phys, kctx, p.mm, isf.field_offset("mm_struct", "total_vm"));
        exec   = read_struct_u64(phys, kctx, p.mm, isf.field_offset("mm_struct", "exec_vm"));
        data   = read_struct_u64(phys, kctx, p.mm, isf.field_offset("mm_struct", "data_vm"));
        stack  = read_struct_u64(phys, kctx, p.mm, isf.field_offset("mm_struct", "stack_vm"));
    } catch (...) {}
    // resident set size — we don't have a cheap counter, approximate as
    // total_vm (will be revisited once we implement page-presence scanning).
    u64 rss = total;
    std::string s = fmt::format("{} {} {} {} 0 {} 0\n",
                                total, rss, shared, exec, data + stack);
    return ByteBuf(s.begin(), s.end());
}

// ---------------------------------------------------------------------------
//  /proc/<pid>/limits — rlimit array (16 entries).
// ---------------------------------------------------------------------------
ByteBuf gen_limits(const PhysicalLayer& phys, const IsfSymbols& isf,
                   const KernelContext& kctx, const Process& p)
{
    // Names + units in RLIMIT_* order (include/uapi/asm-generic/resource.h).
    static const char* names[16] = {
        "Max cpu time",          "Max file size",          "Max data size",
        "Max stack size",        "Max core file size",     "Max resident set",
        "Max processes",         "Max open files",         "Max locked memory",
        "Max address space",     "Max file locks",         "Max pending signals",
        "Max msgqueue size",     "Max nice priority",      "Max realtime priority",
        "Max realtime timeout"
    };
    static const char* units[16] = {
        "seconds", "bytes",   "bytes",  "bytes", "bytes",
        "bytes",   "processes","files", "bytes", "bytes",
        "locks",   "signals", "bytes",  "",      "",      "us"
    };
    constexpr u64 RLIM_INFINITY = ~0ULL;

    u64 signal_va = read_struct_u64(phys, kctx, p.task_va,
                                    isf.field_offset("task_struct", "signal"));
    if (!signal_va) {
        std::string s = "(signal_struct unavailable)\n";
        return ByteBuf(s.begin(), s.end());
    }
    u64 rlim_arr = signal_va + isf.field_offset("signal_struct", "rlim");

    std::string out = fmt::format(
        "{:<25} {:<20} {:<20} {}\n",
        "Limit", "Soft Limit", "Hard Limit", "Units");
    for (int i = 0; i < 16; ++i) {
        u64 soft = read_struct_u64(phys, kctx, rlim_arr, i * 16 + 0);
        u64 hard = read_struct_u64(phys, kctx, rlim_arr, i * 16 + 8);
        std::string ss = (soft == RLIM_INFINITY) ? "unlimited" : std::to_string(soft);
        std::string hs = (hard == RLIM_INFINITY) ? "unlimited" : std::to_string(hard);
        out += fmt::format("{:<25} {:<20} {:<20} {}\n", names[i], ss, hs, units[i]);
    }
    return ByteBuf(out.begin(), out.end());
}

// ---------------------------------------------------------------------------
//  /proc/<pid>/loginuid + /proc/<pid>/oom_score_adj
// ---------------------------------------------------------------------------
ByteBuf gen_loginuid(const PhysicalLayer& phys, const IsfSymbols& isf,
                     const KernelContext& kctx, const Process& p)
{
    u32 uid = (u32)-1;
    try {
        uid = read_struct_u32(phys, kctx, p.task_va,
                              isf.field_offset("task_struct", "loginuid"));
    } catch (...) {}
    std::string s = fmt::format("{}\n", uid);
    return ByteBuf(s.begin(), s.end());
}

ByteBuf gen_oom_score_adj(const PhysicalLayer& phys, const IsfSymbols& isf,
                          const KernelContext& kctx, const Process& p)
{
    int adj = 0;
    try {
        u64 signal_va = read_struct_u64(phys, kctx, p.task_va,
                                        isf.field_offset("task_struct", "signal"));
        if (signal_va) {
            int16_t raw = 0;
            read_dm(phys, kctx, signal_va + isf.field_offset("signal_struct", "oom_score_adj"), raw);
            adj = static_cast<int>(raw);
        }
    } catch (...) {}
    std::string s = fmt::format("{}\n", adj);
    return ByteBuf(s.begin(), s.end());
}

// ---------------------------------------------------------------------------
//  Path resolution: walk dentry tree up to the filesystem root.
//  Doesn't cross mount boundaries (for that we'd walk the vfsmount tree —
//  TODO). Names ≤ 32 bytes live in d_shortname; longer names are referenced
//  via d_name.name.
// ---------------------------------------------------------------------------
namespace {

std::string read_dentry_name(const PhysicalLayer& phys, const KernelContext& kctx,
                             const IsfSymbols& isf, VAddr dentry_va)
{
    u64 d_name_off = isf.field_offset("dentry", "d_name");
    // qstr layout: hash_len (u64) | len (u32 at +4 i.e. high half of hash_len) | name (ptr at +8)
    u32 len = read_struct_u32(phys, kctx, dentry_va, d_name_off + 4);
    u64 name_va = read_struct_u64(phys, kctx, dentry_va, d_name_off + 8);
    if (len == 0 || name_va == 0) return {};
    if (len > 4096) len = 4096; // sanity
    std::vector<char> buf(len + 1, 0);
    PAddr name_pa = 0;
    if (!dm_pa(name_va, kctx, phys.max_address(), name_pa)) return {};
    phys.read(name_pa, buf.data(), len);
    return std::string(buf.data(), len);
}

std::string resolve_dentry_path(const PhysicalLayer& phys, const KernelContext& kctx,
                                const IsfSymbols& isf, VAddr dentry_va,
                                int max_depth = 64)
{
    u64 d_parent_off = isf.field_offset("dentry", "d_parent");
    std::vector<std::string> comps;
    VAddr cur = dentry_va;
    for (int i = 0; i < max_depth && cur; ++i) {
        VAddr parent = 0;
        if (!read_dm(phys, kctx, cur + d_parent_off, parent)) break;
        std::string name = read_dentry_name(phys, kctx, isf, cur);
        if (parent == cur) {
            // root of this filesystem; "/" is implicit
            break;
        }
        if (!name.empty()) comps.push_back(std::move(name));
        cur = parent;
    }
    std::string out;
    for (auto it = comps.rbegin(); it != comps.rend(); ++it) {
        out.push_back('/');
        out += *it;
    }
    if (out.empty()) out = "/";
    return out;
}

ByteBuf gen_path_for_file(const PhysicalLayer& phys, const IsfSymbols& isf,
                          const KernelContext& kctx, VAddr file_va)
{
    if (file_va == 0) return {};
    u64 f_path_off  = isf.field_offset("file",   "f_path");
    u64 dentry_off  = isf.field_offset("path",   "dentry");
    VAddr dentry_va = 0;
    if (!read_dm(phys, kctx, file_va + f_path_off + dentry_off, dentry_va)) return {};
    if (!dentry_va) return {};
    auto path = resolve_dentry_path(phys, kctx, isf, dentry_va);
    path.push_back('\n');
    return ByteBuf(path.begin(), path.end());
}

ByteBuf gen_path_for_struct_path(const PhysicalLayer& phys, const IsfSymbols& isf,
                                 const KernelContext& kctx, VAddr fs_va,
                                 const char* field /* "root" or "pwd" */)
{
    if (fs_va == 0) return {};
    u64 sub_off    = isf.field_offset("fs_struct", field);
    u64 dentry_off = isf.field_offset("path", "dentry");
    VAddr dentry_va = 0;
    if (!read_dm(phys, kctx, fs_va + sub_off + dentry_off, dentry_va)) return {};
    if (!dentry_va) return {};
    auto path = resolve_dentry_path(phys, kctx, isf, dentry_va);
    path.push_back('\n');
    return ByteBuf(path.begin(), path.end());
}

} // anonymous

ByteBuf gen_exe(const PhysicalLayer& phys, const IsfSymbols& isf,
                const KernelContext& kctx, const Process& p)
{
    if (!p.mm) return {};
    u64 exe_file_va = read_struct_u64(phys, kctx, p.mm,
                                      isf.field_offset("mm_struct", "exe_file"));
    return gen_path_for_file(phys, isf, kctx, exe_file_va);
}

ByteBuf gen_cwd(const PhysicalLayer& phys, const IsfSymbols& isf,
                const KernelContext& kctx, const Process& p)
{
    u64 fs_va = read_struct_u64(phys, kctx, p.task_va,
                                isf.field_offset("task_struct", "fs"));
    return gen_path_for_struct_path(phys, isf, kctx, fs_va, "pwd");
}

ByteBuf gen_root(const PhysicalLayer& phys, const IsfSymbols& isf,
                 const KernelContext& kctx, const Process& p)
{
    u64 fs_va = read_struct_u64(phys, kctx, p.task_va,
                                isf.field_offset("task_struct", "fs"));
    return gen_path_for_struct_path(phys, isf, kctx, fs_va, "root");
}

// ---------------------------------------------------------------------------
//  /proc/<pid>/capabilities — cred caps as bit masks.
// ---------------------------------------------------------------------------
ByteBuf gen_capabilities(const PhysicalLayer& phys, const IsfSymbols& isf,
                         const KernelContext& kctx, const Process& p)
{
    u64 cred_va = read_struct_u64(phys, kctx, p.task_va,
                                  isf.field_offset("task_struct", "cred"));
    if (!cred_va) return ByteBuf{};
    u64 inh = 0, perm = 0, eff = 0, bset = 0, amb = 0;
    try {
        inh  = read_struct_u64(phys, kctx, cred_va, isf.field_offset("cred", "cap_inheritable"));
        perm = read_struct_u64(phys, kctx, cred_va, isf.field_offset("cred", "cap_permitted"));
        eff  = read_struct_u64(phys, kctx, cred_va, isf.field_offset("cred", "cap_effective"));
        bset = read_struct_u64(phys, kctx, cred_va, isf.field_offset("cred", "cap_bset"));
        amb  = read_struct_u64(phys, kctx, cred_va, isf.field_offset("cred", "cap_ambient"));
    } catch (...) {}
    std::string s = fmt::format(
        "CapInh:\t{:016x}\n"
        "CapPrm:\t{:016x}\n"
        "CapEff:\t{:016x}\n"
        "CapBnd:\t{:016x}\n"
        "CapAmb:\t{:016x}\n",
        inh, perm, eff, bset, amb);
    return ByteBuf(s.begin(), s.end());
}

} // namespace lmpfs::linux
