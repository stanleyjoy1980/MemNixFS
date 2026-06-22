// sysinfo.cpp — see header.
#include "os/linux/sysinfo.h"
#include "os/linux/kva_reader.h"
#include "os/linux/mountinfo.h"
#include "app/engine.h"
#include "symbols/isf_symbols.h"
#include "symbols/kallsyms.h"
#include "core/log.h"
#include <fmt/format.h>
#include <cstring>

namespace lmpfs::linux {

namespace {

// __NEW_UTS_LEN is 64 (since pre-2.6). Plus trailing NUL = 65 bytes per
// field. Most distros are well under that.
constexpr std::size_t kUtsFieldLen = 65;

// Find a kallsyms symbol by exact name. Returns 0 if absent.
VAddr resolve_kallsym(const Engine& eng, const char* name) {
    const auto& ks = eng.kallsyms();
    if (!ks.ok) return 0;
    for (const auto& s : ks.symbols) if (s.name == name) return s.address;
    return 0;
}

} // anonymous

ByteBuf format_hostname(const Engine& eng) {
    VAddr utsns_va = 0;
    // Prefer ISF (it carries the symbol; kallsyms is a fallback when the
    // ISF doesn't ship). The ISF lookup is also resilient to KASLR.
    if (auto* sym = eng.isf().find_symbol("init_uts_ns")) {
        utsns_va = sym->address;
    } else {
        utsns_va = resolve_kallsym(eng, "init_uts_ns");
    }
    if (utsns_va == 0) {
        const char msg[] = "(unknown — `init_uts_ns` symbol not in ISF/kallsyms)\n";
        return ByteBuf(msg, msg + sizeof(msg) - 1);
    }
    // uts_namespace.name is a `struct new_utsname` whose first field is
    // `sysname`. We want `nodename` (the hostname). Read the ISF offsets;
    // fall back to the hardcoded layout used on every kernel ≥ 2.6 if the
    // ISF doesn't carry the types.
    u64 name_off = 0, nodename_off = kUtsFieldLen;
    try {
        name_off     = eng.isf().field_offset("uts_namespace", "name");
        nodename_off = eng.isf().field_offset("new_utsname",   "nodename");
    } catch (...) {
        // Modern layout: uts_namespace.name starts with a few small
        // fields (ns_common, kref, …). The exact offset varies, but the
        // ISF nearly always has it; this fallback is only for ISFs that
        // strip private types.
        name_off     = 0x18;          // typical for 6.x
        nodename_off = kUtsFieldLen;
    }
    char buf[kUtsFieldLen]; std::memset(buf, 0, sizeof(buf));
    if (!kva_read(eng, utsns_va + name_off + nodename_off,
                   buf, sizeof(buf) - 1)) {
        const char msg[] = "(read of uts_namespace.name.nodename failed)\n";
        return ByteBuf(msg, msg + sizeof(msg) - 1);
    }
    // Truncate at first NUL or non-printable.
    std::size_t n = 0;
    while (n < sizeof(buf) - 1 && buf[n] >= 0x20 && buf[n] < 0x7F) ++n;
    std::string out(buf, n);
    out.push_back('\n');
    return ByteBuf(out.begin(), out.end());
}

ByteBuf format_uptime(const Engine& eng) {
    // jiffies_64 holds total ticks since boot. Reading it gives seconds
    // when divided by HZ.
    //
    // HZ detection: not directly readable as a runtime value. Most modern
    // distros default to CONFIG_HZ_1000 (Ubuntu, Fedora, Debian, Arch).
    // We document the assumption and dump the raw jiffies value too so
    // operators with non-default HZ can recompute manually.
    constexpr u64 kAssumedHZ = 1000;

    VAddr jaddr = 0;
    if (auto* sym = eng.isf().find_symbol("jiffies_64")) jaddr = sym->address;
    if (!jaddr) jaddr = resolve_kallsym(eng, "jiffies_64");
    if (!jaddr) {
        const char msg[] = "(unknown — `jiffies_64` symbol not in ISF/kallsyms)\n";
        return ByteBuf(msg, msg + sizeof(msg) - 1);
    }
    u64 jiffies = 0;
    if (!kva_read_pod(eng, jaddr, jiffies) || jiffies == 0) {
        const char msg[] = "(read of jiffies_64 failed)\n";
        return ByteBuf(msg, msg + sizeof(msg) - 1);
    }
    // The kernel does NOT start jiffies_64 at 0: it initializes to
    // INITIAL_JIFFIES = (unsigned int)(-300*HZ) so that timer wrap-around bugs
    // surface ~5 min after boot instead of ~49 days. We MUST subtract it, or
    // every dump reports a bogus ~49.7-day uptime. (HZ-independent: the macro
    // scales with HZ, and we use the same kAssumedHZ for both terms.)
    const u64 kInitialJiffies =
        static_cast<u64>(static_cast<u32>(-static_cast<i64>(300 * kAssumedHZ)));
    const u64 uptime_ticks =
        (jiffies >= kInitialJiffies) ? (jiffies - kInitialJiffies) : jiffies;

    // /proc/uptime format: "<uptime_s>.<centisec> <idle_s>.<centisec>\n".
    // We don't have idle accurately, so emit just the uptime followed
    // by 0.0 — most consumers only read the first column.
    double up_s = double(uptime_ticks) / double(kAssumedHZ);
    auto out = fmt::format(
        "{:.2f} 0.00\n"
        "# Computed as (jiffies_64 - INITIAL_JIFFIES) / HZ (assumed {}).\n"
        "# Raw jiffies_64 = {} ticks; INITIAL_JIFFIES = {} ticks. Override the\n"
        "# HZ assumption by recomputing yourself if CONFIG_HZ != 1000.\n",
        up_s, kAssumedHZ, jiffies, kInitialJiffies);
    return ByteBuf(out.begin(), out.end());
}

ByteBuf format_mounts(const Engine& eng) {
    auto mnts = enumerate_mounts(eng);
    std::string out;
    out.reserve(8 * 1024);
    if (mnts.empty()) {
        out += "(no mounts enumerated — see /sys/mountinfo for diagnostics)\n";
        return ByteBuf(out.begin(), out.end());
    }
    // /proc/mounts format:  <device> <mountpoint> <fstype> <options> 0 0
    //
    // We don't carry per-mount options (they live in vfsmount.mnt_flags
    // and the sb-specific options string; not reliably ISF-typed). Emit
    // a placeholder "rw" so the column count is right.
    for (const auto& m : mnts) {
        out += fmt::format("{} {} {} rw 0 0\n",
                           m.devname.empty() ? "(none)" : m.devname,
                           m.global_path.empty() ? "/" : m.global_path,
                           m.fs_name.empty() ? "unknown" : m.fs_name);
    }
    return ByteBuf(out.begin(), out.end());
}

// =========================================================================
//   /sys/cpuinfo  — boot_cpu_data (a struct cpuinfo_x86)
// =========================================================================
//
// We read just the most useful fields: family / model / stepping / cache
// size / vendor_id (16-char string) / model_id (64-char string). Reading
// the full feature-flags array would require enumerating ~30+ x86_capability
// dwords, which isn't worth the maintenance burden when the more useful
// per-CPU info is identical to boot CPU on uniprocessor / SMP-x86 systems.
//
// The ISF nearly always has `cpuinfo_x86` typed because vmlinux ships
// dwarf info for it. We try the ISF; if absent, fall back to a typical
// 6.x layout.
ByteBuf format_cpuinfo(const Engine& eng) {
    VAddr bcd = 0;
    if (auto* s = eng.isf().find_symbol("boot_cpu_data")) bcd = s->address;
    if (!bcd) bcd = resolve_kallsym(eng, "boot_cpu_data");
    if (!bcd) {
        const char msg[] = "(unknown — `boot_cpu_data` symbol not in ISF/kallsyms)\n";
        return ByteBuf(msg, msg + sizeof(msg) - 1);
    }
    u64 off_family  = 0, off_vendor = 0, off_model = 0, off_step = 0;
    u64 off_cachesz = 0, off_vendor_id = 0, off_model_id = 0;
    bool have_layout = false;
    try {
        off_family    = eng.isf().field_offset("cpuinfo_x86", "x86");
        off_vendor    = eng.isf().field_offset("cpuinfo_x86", "x86_vendor");
        off_model     = eng.isf().field_offset("cpuinfo_x86", "x86_model");
        off_step      = eng.isf().field_offset("cpuinfo_x86", "x86_stepping");
        try { off_cachesz = eng.isf().field_offset("cpuinfo_x86", "x86_cache_size"); }
        catch (...) {}
        off_vendor_id = eng.isf().field_offset("cpuinfo_x86", "x86_vendor_id");
        off_model_id  = eng.isf().field_offset("cpuinfo_x86", "x86_model_id");
        have_layout   = true;
    } catch (...) { /* fall back to heuristic */ }
    if (!have_layout) {
        // Approximate 6.14 layout; values will be off on bespoke kernels.
        // Best-effort — we still emit something useful.
        off_family    = 0;
        off_vendor    = 1;
        off_model     = 2;
        off_step      = 3;
        off_vendor_id = 0x28;
        off_model_id  = 0x60;
    }
    u8 family = 0, vendor = 0, model = 0, step = 0;
    int cachesz = 0;
    kva_read_pod(eng, bcd + off_family, family);
    kva_read_pod(eng, bcd + off_vendor, vendor);
    kva_read_pod(eng, bcd + off_model,  model);
    kva_read_pod(eng, bcd + off_step,   step);
    if (off_cachesz) kva_read_pod(eng, bcd + off_cachesz, cachesz);
    char vendor_id[17] = {0}, model_id[65] = {0};
    kva_read(eng, bcd + off_vendor_id, vendor_id, 16);
    kva_read(eng, bcd + off_model_id,  model_id, 64);
    // Sanitize — these can contain trailing garbage if uninitialised.
    for (char& c : vendor_id) if (c && (c < 0x20 || c >= 0x7F)) c = 0;
    for (char& c : model_id ) if (c && (c < 0x20 || c >= 0x7F)) c = 0;

    auto out = fmt::format(
        "# /sys/cpuinfo — boot CPU summary (read from `boot_cpu_data`)\n"
        "# Identical content to /proc/cpuinfo's first \"processor\" block on\n"
        "# SMP systems where all cores share the same model. Per-CPU walks\n"
        "# (`per_cpu_offset[]` + `cpuinfo_x86`) are not currently extracted.\n"
        "\n"
        "vendor_id\t: {}\n"
        "cpu family\t: {}\n"
        "model\t\t: {}\n"
        "model name\t: {}\n"
        "stepping\t: {}\n"
        "cache size\t: {} KB\n"
        "x86_vendor_enum\t: {}\n",
        *vendor_id ? vendor_id : "(unknown)",
        (unsigned)family, (unsigned)model,
        *model_id ? model_id : "(unknown)",
        (unsigned)step,
        cachesz,
        (unsigned)vendor);
    return ByteBuf(out.begin(), out.end());
}

// =========================================================================
//   /sys/meminfo  — minimal /proc/meminfo (MemTotal + a couple of stats)
// =========================================================================
//
// totalram_pages is an atomic_long_t (recently switched from atomic_long).
// Multiplied by PAGE_SIZE (4096 on x86_64) gives bytes. The full
// /proc/meminfo (MemFree, Buffers, Cached, etc.) needs enumeration of
// per-zone + per-node vm_stat counters where index ordering changes
// across kernel versions; for now we ship MemTotal + a note.
ByteBuf format_meminfo(const Engine& eng) {
    VAddr addr = 0;
    if (auto* s = eng.isf().find_symbol("_totalram_pages")) addr = s->address;
    if (!addr) addr = resolve_kallsym(eng, "_totalram_pages");
    if (!addr) {
        if (auto* s = eng.isf().find_symbol("totalram_pages")) addr = s->address;
        if (!addr) addr = resolve_kallsym(eng, "totalram_pages");
    }
    if (!addr) {
        const char msg[] = "(unknown — neither `_totalram_pages` nor `totalram_pages`"
                            " in ISF/kallsyms)\n";
        return ByteBuf(msg, msg + sizeof(msg) - 1);
    }
    i64 pages = 0;
    kva_read_pod(eng, addr, pages);
    u64 bytes = static_cast<u64>(pages) * 4096ULL;
    auto out = fmt::format(
        "# /sys/meminfo — minimal counters from kernel state\n"
        "# Full /proc/meminfo (Buffers / Cached / Slab / etc.) requires\n"
        "# enumeration of per-zone vm_stat counters whose index ordering\n"
        "# changes across kernel versions. We ship MemTotal today; expand\n"
        "# later if a per-stat reader is worth the maintenance burden.\n"
        "\n"
        "MemTotal:       {:>10} kB     ({} pages × 4 KiB)\n",
        bytes / 1024, pages);
    return ByteBuf(out.begin(), out.end());
}

// =========================================================================
//   /sys/iomem  — /proc/iomem tree walk via iomem_resource
// =========================================================================
//
// struct resource {
//     u64 start, end;
//     const char *name;
//     unsigned long flags, desc;
//     struct resource *parent, *sibling, *child;
// };
//
// Walk: print self, recurse into child, advance to sibling. The top-level
// resource is the global `iomem_resource` symbol (a real struct, not a
// pointer — its `.child` holds the actual list).
ByteBuf format_iomem(const Engine& eng) {
    VAddr iores = 0;
    if (auto* s = eng.isf().find_symbol("iomem_resource")) iores = s->address;
    if (!iores) iores = resolve_kallsym(eng, "iomem_resource");
    if (!iores) {
        const char msg[] = "(unknown — `iomem_resource` not in ISF/kallsyms)\n";
        return ByteBuf(msg, msg + sizeof(msg) - 1);
    }
    // struct resource layout on 6.x x86_64:
    //   start@0, end@8, name@16, flags@24, desc@32, parent@40, sibling@48, child@56
    u64 off_start=0, off_end=8, off_name=16, off_child=56, off_sibling=48;
    try {
        off_start   = eng.isf().field_offset("resource", "start");
        off_end     = eng.isf().field_offset("resource", "end");
        off_name    = eng.isf().field_offset("resource", "name");
        off_child   = eng.isf().field_offset("resource", "child");
        off_sibling = eng.isf().field_offset("resource", "sibling");
    } catch (...) { /* use defaults */ }

    std::string out;
    out.reserve(8 * 1024);
    out += "# /sys/iomem — iomem_resource tree walk\n#\n";

    // Iterative DFS with depth tracking — DFS keeps siblings adjacent and
    // children indented under their parent (matches /proc/iomem output).
    struct Frame { VAddr va; int depth; };
    std::vector<Frame> stk;
    VAddr first_child = 0;
    kva_read_pod(eng, iores + off_child, first_child);
    if (first_child) stk.push_back({ first_child, 0 });
    int rendered = 0;
    while (!stk.empty() && rendered < 4096) {
        Frame f = stk.back(); stk.pop_back();
        u64 s = 0, e = 0;
        VAddr name_va = 0;
        bool r1 = kva_read_pod(eng, f.va + off_start,   s);
        bool r2 = kva_read_pod(eng, f.va + off_end,     e);
        kva_read_pod(eng, f.va + off_name, name_va);
        // Sanity: a valid resource has end >= start. Reject reads that
        // failed entirely (kernel-VA unmapped) or violate the invariant.
        if (!r1 || !r2) continue;
        if (e < s) continue;
        // Sanitize the name: read up to 64 bytes; replace non-printable
        // chars with '?'. Some resources have name pointers into rodata
        // that we can't always reach reliably across translation paths.
        std::string nm;
        if (name_va >= 0xffff800000000000ULL) {
            nm = kva_read_cstr(eng, name_va, 64);
            for (char& c : nm) if (c && (c < 0x20 || c >= 0x7F)) c = '?';
        }
        out += fmt::format("{:>{}}{:#018x}-{:#018x} : {}\n",
                            "", f.depth * 2, s, e, nm);
        ++rendered;

        // Always push child/sibling — losing a branch because of a name
        // read failure would silently drop big sub-trees.
        VAddr sib = 0, child = 0;
        kva_read_pod(eng, f.va + off_sibling, sib);
        kva_read_pod(eng, f.va + off_child,   child);
        if (sib   && sib != f.va && sib   >= 0xffff800000000000ULL)
            stk.push_back({ sib,   f.depth     });
        if (child && child != f.va && child >= 0xffff800000000000ULL)
            stk.push_back({ child, f.depth + 1 });
    }
    if (rendered == 0) out += "(no iomem resources recovered — kernel "
                              "resource-tree offsets may not match this kernel)\n";
    return ByteBuf(out.begin(), out.end());
}

// =========================================================================
//   /sys/boottime  — wall-clock at boot
// =========================================================================
//
// Computed as `wall_now - uptime`. We don't have a robust wall-now
// reader (would require walking `tk_core.timekeeper.xtime_sec` plus
// CLOCK_TAI offset), so for now we report uptime in seconds (same as
// /sys/uptime) PLUS a comment explaining the calc. Operators can use
// the dump file's mtime as wall-now to compute boot wall-time.
ByteBuf format_boottime(const Engine& eng) {
    VAddr jaddr = 0;
    if (auto* s = eng.isf().find_symbol("jiffies_64")) jaddr = s->address;
    if (!jaddr) jaddr = resolve_kallsym(eng, "jiffies_64");
    u64 jiffies = 0;
    if (jaddr) kva_read_pod(eng, jaddr, jiffies);
    // Same INITIAL_JIFFIES correction as /sys/uptime — jiffies_64 starts at
    // (unsigned int)(-300*HZ), not 0, so subtract it before dividing by HZ.
    const u64 kInitialJiffies = static_cast<u64>(static_cast<u32>(-300 * 1000));
    const u64 uptime_ticks =
        (jiffies >= kInitialJiffies) ? (jiffies - kInitialJiffies) : jiffies;
    const u64 uptime_s = uptime_ticks / 1000;
    auto out = fmt::format(
        "# /sys/boottime — system boot time\n"
        "# We compute uptime exactly ((jiffies_64 - INITIAL_JIFFIES) / HZ).\n"
        "# The absolute wall-clock boot epoch is derived from the kernel\n"
        "# timekeeper by the forensic timeline — see /forensic/timeline/ for\n"
        "# boot-anchored UTC timestamps. You can also derive it manually below.\n"
        "\n"
        "uptime_seconds      = {} ({} jiffies @ HZ=1000)\n"
        "uptime_days_approx  = {:.2f}\n"
        "\n"
        "To derive boot wall-clock yourself: take the dump file's modify-\n"
        "time, subtract uptime_seconds — that's the system's boot epoch in\n"
        "wall-clock time.\n",
        uptime_s, jiffies, uptime_s / 86400.0);
    return ByteBuf(out.begin(), out.end());
}

} // namespace lmpfs::linux
