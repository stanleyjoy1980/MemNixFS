// sys_module.cpp — see header.
#include "vfs/sys_module.h"
#include "app/engine.h"
#include "arch/x86_64/paging.h"
#include "os/linux/kernel_resolver.h"
#include "os/linux/banner_scan.h"
#include "os/linux/btf_probe.h"
#include "os/linux/dmesg.h"
#include "os/linux/crash_journal.h"
#include "os/linux/modules.h"
#include "os/linux/pagecache.h"
#include "os/linux/mountinfo.h"
#include "os/linux/netstat.h"
#include "os/linux/findevil.h"
#include "os/linux/av_edr.h"
#include "os/linux/tracepoints.h"
#include "os/linux/sysinfo.h"
#include "os/linux/users.h"
#include "os/linux/json_export.h"
#include "os/linux/check_syscall.h"
#include "os/linux/integrity_checks.h"
#include "os/linux/ebpf.h"
#include "os/linux/entropy.h"
#include "os/linux/csv_export.h"
#include "os/linux/tracing.h"
#include "os/linux/process_views.h"
#include "os/linux/bash_history.h"
#include "os/linux/threads.h"
#include "symbols/isf_symbols.h"
#include "formats/physical_layer.h"
#include <fmt/format.h>

namespace lmpfs::vfs {

namespace {

// Read a NUL-terminated string from a kernel VA via the kernel page table.
// Returns empty string if the read fails or the area is unmapped.
std::string read_kernel_string(const Engine& eng, VAddr va, std::size_t maxlen) {
    if (!eng.kernel().dtb_validated) return {};
    std::vector<char> buf(maxlen, 0);
    eng.kernel_pt().read(va, buf.data(), maxlen);
    std::size_t n = 0;
    while (n < maxlen && buf[n]) ++n;
    return std::string(buf.data(), n);
}

ByteBuf gen_banner_via_kernel_pt(const Engine& eng) {
    const auto* sym = eng.isf().find_symbol("linux_banner");
    if (!sym) {
        // No `linux_banner` symbol (e.g. a BTF-only / types-only dump). The
        // banner is still in physical memory: the kernel resolver scans for it
        // during KASLR resolution and stores the winner in kernel().banner.
        // Reuse that; fall back to a fresh physical scan if it wasn't kept.
        std::string s = eng.kernel().banner;
        if (s.empty()) s = linux::find_banner_in_dump(eng.phys());
        if (s.empty()) {
            const char msg[] =
                "; no linux_banner symbol, and no 'Linux version' banner found "
                "by physical scan\n";
            return ByteBuf(msg, msg + sizeof(msg) - 1);
        }
        if (s.empty() || s.back() != '\n') s.push_back('\n');
        return ByteBuf(s.begin(), s.end());
    }
    if (!eng.kernel().dtb_validated) {
        std::string banner = eng.kernel().banner;
        if (banner.empty()) banner = linux::find_banner_in_dump(eng.phys());
        std::string s;
        if (!banner.empty()) {
            s = banner;
            if (s.back() != '\n') s.push_back('\n');
            s += fmt::format(
                "# note: kernel-VA linux_banner read unavailable; DTB did not "
                "validate (strategy={}). Banner above was recovered by "
                "physical scan.\n",
                eng.kernel().dtb_strategy);
        } else {
            s = fmt::format(
                "unavailable: kernel-VA linux_banner read unavailable; DTB "
                "did not validate (strategy={}), and no physical banner was "
                "recovered.\n",
                eng.kernel().dtb_strategy);
        }
        return ByteBuf(s.begin(), s.end());
    }
    VAddr va = sym->address + eng.kernel().kaslr_virt_shift;
    auto s = read_kernel_string(eng, va, 512);
    if (s.empty()) s = "(empty / unmapped)";
    s.push_back('\n');
    return ByteBuf(s.begin(), s.end());
}

ByteBuf gen_dtb_info(const Engine& eng) {
    const auto& k = eng.kernel();
    auto s = fmt::format(
        "dtb_pa:        {:#018x}\n"
        "validated:     {}\n"
        "strategy:      {}\n"
        "kaslr_phys:    {:#x}\n"
        "kaslr_virt:    {:#x}\n"
        "init_task_pa:  {:#018x}\n"
        "init_task_va:  {:#018x}\n"
        "direct_map_base:{:#018x}\n",
        k.dtb, k.dtb_validated, k.dtb_strategy,
        k.kaslr_phys_shift, k.kaslr_virt_shift,
        k.init_task_pa, k.init_task_va, k.direct_map_base);
    return ByteBuf(s.begin(), s.end());
}

ByteBuf gen_physical_ranges(const Engine& eng) {
    const auto ranges = eng.phys().ranges();
    std::string out;
    out += "# /sys/mem_ranges.txt - captured physical dump ranges\n";
    out += "# Bytes outside these ranges may be zero-filled by sparse stream views such as /mem/phys.raw.\n";
    out += fmt::format("format: {}\n", eng.phys().format_name());
    out += fmt::format("source: {}\n", eng.phys().source_name());
    out += fmt::format("max_address: {:#x}\n", eng.phys().max_address());
    if (ranges.empty()) {
        out += "ranges: unavailable: this physical layer did not expose captured ranges\n";
        return ByteBuf(out.begin(), out.end());
    }
    u64 captured = 0;
    for (const auto& r : ranges) captured += r.length;
    out += fmt::format("ranges: {}\n", ranges.size());
    out += fmt::format("captured_bytes: {}\n", captured);
    out += "# start end_exclusive length\n";
    for (const auto& r : ranges) {
        out += fmt::format("{:#018x} {:#018x} {:#x}\n",
                           r.start, r.start + r.length, r.length);
    }
    return ByteBuf(out.begin(), out.end());
}

} // anonymous

NodePtr build_sys_tree(const Engine& eng) {
    auto root = std::make_shared<DirNode>("sys");
    const Engine* engp = &eng;

    // Trivial-to-produce scalar files: a few struct reads, tiny output. Tagging
    // them Trivial lets the directory listing show their REAL size (instead of
    // 0) without the lag that running heavier producers per-listing would cause.
    constexpr FileCost kTrivial{ FileCost::Compute::Trivial, FileCost::Mem::Small };

    // banner.txt — kernel banner read via the kernel PGD walker. If this
    // matches the dump's actual banner, kernel-VA reads work.
    root->add(std::make_shared<LazyFileNode>("banner.txt",
        [engp]() { return gen_banner_via_kernel_pt(*engp); }, kTrivial));

    // dtb.txt — diagnostics: which DTB strategy won, validation status,
    // KASLR shifts, init_task PA/VA, direct_map_base.
    root->add(std::make_shared<LazyFileNode>("dtb.txt",
        [engp]() { return gen_dtb_info(*engp); }, kTrivial));

    root->add(std::make_shared<LazyFileNode>("mem_ranges.txt",
        [engp]() { return gen_physical_ranges(*engp); }, kTrivial));

    // dmesg — printk ring buffer, formatted as /var/log/kern.log-style text.
    // Walks `prb` (struct printk_ringbuffer *) on modern (≥ 5.10) kernels.
    root->add(std::make_shared<LazyFileNode>("dmesg",
        [engp]() { return linux::format_dmesg(*engp); },
        FileCost{ FileCost::Compute::Expensive, FileCost::Mem::Small,
                  FileCost::Category::SystemInfo }));

    // modules/ — loaded kernel modules. A summary file at the top
    // (modules.txt) and one directory per module with info.txt inside.
    auto modules_dir = std::make_shared<DirNode>("modules");
    modules_dir->add(std::make_shared<LazyFileNode>("modules.txt",
        [engp]() { return linux::format_modules_summary(*engp); }));
    // Enumerate once here; results are evaluated lazily but the
    // per-module nodes are added now to avoid re-walking on every list.
    for (const auto& m : linux::enumerate_modules(eng)) {
        auto md = std::make_shared<DirNode>(m.name);
        md->add(std::make_shared<LazyFileNode>("info.txt",
            [m]() { return linux::format_module_info(m); }));
        modules_dir->add(md);
    }
    root->add(modules_dir);

    // pagecache/ — every inode the kernel has in memory across every
    // mounted filesystem. index.txt is the catalog; this is the natural
    // companion to the /files tree that the engine adds at root level.
    auto pc_dir = std::make_shared<DirNode>("pagecache");
    pc_dir->add(std::make_shared<LazyFileNode>("index.txt",
        [engp]() { return linux::format_pagecache_index(*engp); }));
    pc_dir->add(std::make_shared<LazyFileNode>("recovery.txt",
        [engp]() { return linux::format_pagecache_recovery(*engp); },
        FileCost{ FileCost::Compute::Expensive, FileCost::Mem::Small,
                  FileCost::Category::SystemInfo }));
    pc_dir->add(std::make_shared<LazyFileNode>("path_quality.txt",
        [engp]() { return linux::format_pagecache_path_quality(*engp); },
        FileCost{ FileCost::Compute::Expensive, FileCost::Mem::Small,
                  FileCost::Category::SystemInfo }));
    root->add(pc_dir);

    // mountinfo — /proc/mountinfo-style listing of every mount in the
    // init namespace, with composed global paths. Same cost class as `mounts`
    // (a bounded mount-tree walk, tiny output) → Trivial so Explorer shows a
    // real size instead of 0.
    root->add(std::make_shared<LazyFileNode>("mountinfo",
        [engp]() { return linux::format_mountinfo(*engp); }, kTrivial));
    // v0.27 — Tier 2 close-out: system-info trio + users
    root->add(std::make_shared<LazyFileNode>("hostname",
        [engp]() { return linux::format_hostname(*engp); }, kTrivial));
    root->add(std::make_shared<LazyFileNode>("uptime",
        [engp]() { return linux::format_uptime(*engp); }, kTrivial));
    root->add(std::make_shared<LazyFileNode>("mounts",
        [engp]() { return linux::format_mounts(*engp); }, kTrivial));
    root->add(std::make_shared<LazyFileNode>("users.txt",
        [engp]() { return linux::format_users(*engp); }, kTrivial));
    // v0.28 — Tier 2 wider close-out
    root->add(std::make_shared<LazyFileNode>("cpuinfo",
        [engp]() { return linux::format_cpuinfo(*engp); }, kTrivial));
    root->add(std::make_shared<LazyFileNode>("meminfo",
        [engp]() { return linux::format_meminfo(*engp); }, kTrivial));
    root->add(std::make_shared<LazyFileNode>("iomem",
        [engp]() { return linux::format_iomem(*engp); }, kTrivial));
    root->add(std::make_shared<LazyFileNode>("boottime",
        [engp]() { return linux::format_boottime(*engp); }, kTrivial));
    root->add(std::make_shared<LazyFileNode>("dns.txt",
        [engp]() { return linux::format_dns(*engp); }, kTrivial));
    // pidhashtable — bounded walk of the PID hash (processes already
    // enumerated at mount), tiny output → Trivial so Explorer shows its size.
    root->add(std::make_shared<LazyFileNode>("pidhashtable",
        [engp]() { return linux::format_pidhashtable(*engp); }, kTrivial));

    // shell_history.txt — aggregate shell-history recovery across shell
    // processes and cached history files.
    auto shell_history = std::make_shared<LazyFileNode>("shell_history.txt",
        [engp]() { return linux::format_global_shell_history(*engp); },
        FileCost{ FileCost::Compute::Expensive, FileCost::Mem::Small,
                  FileCost::Category::SystemInfo });
    root->add(shell_history);

    // crash/ — explicit crash/failure evidence triage. Reports source
    // availability separately from findings so missing logs are never
    // misread as proof that a crash did not happen.
    auto crash_dir = std::make_shared<DirNode>("crash");
    crash_dir->add(std::make_shared<LazyFileNode>("summary.txt",
        [engp]() { return linux::format_crash_summary(*engp); },
        FileCost{ FileCost::Compute::Expensive, FileCost::Mem::Small,
                  FileCost::Category::SystemInfo }));
    crash_dir->add(std::make_shared<LazyFileNode>("events.txt",
        [engp]() { return linux::format_crash_events(*engp); },
        FileCost{ FileCost::Compute::Expensive, FileCost::Mem::Small,
                  FileCost::Category::SystemInfo }));
    crash_dir->add(std::make_shared<LazyFileNode>("call_traces.txt",
        [engp]() { return linux::format_crash_call_traces(*engp); },
        FileCost{ FileCost::Compute::Expensive, FileCost::Mem::Small,
                  FileCost::Category::SystemInfo }));
    root->add(crash_dir);

    // journal/ — cached syslog/journald candidates plus conservative
    // filesystem-consistency status. This is evidence discovery, not
    // filesystem journal replay.
    auto journal_dir = std::make_shared<DirNode>("journal");
    journal_dir->add(std::make_shared<LazyFileNode>("index.txt",
        [engp]() { return linux::format_journal_index(*engp); },
        FileCost{ FileCost::Compute::Expensive, FileCost::Mem::Small,
                  FileCost::Category::SystemInfo }));
    journal_dir->add(std::make_shared<LazyFileNode>("text_logs.txt",
        [engp]() { return linux::format_journal_text_logs(*engp); },
        FileCost{ FileCost::Compute::Expensive, FileCost::Mem::Small,
                  FileCost::Category::SystemInfo }));
    journal_dir->add(std::make_shared<LazyFileNode>("journald.txt",
        [engp]() { return linux::format_journald_entries(*engp); },
        FileCost{ FileCost::Compute::Expensive, FileCost::Mem::Small,
                  FileCost::Category::SystemInfo }));
    root->add(journal_dir);

    // /sys/net/ — network state. Mirrors MemProcFS's `/sys/net/` layout.
    auto net_dir = std::make_shared<DirNode>("net");
    net_dir->add(std::make_shared<LazyFileNode>("tcp",
        [engp]() { return linux::format_proc_net_tcp(*engp); }));
    net_dir->add(std::make_shared<LazyFileNode>("udp",
        [engp]() { return linux::format_proc_net_udp(*engp); }));
    net_dir->add(std::make_shared<LazyFileNode>("interfaces",
        [engp]() { return linux::format_interfaces(*engp); }));
    net_dir->add(std::make_shared<LazyFileNode>("summary.txt",
        [engp]() { return linux::format_netstat_summary(*engp); }));
    // v0.27 — Tier 2: listening sockets cross-view
    net_dir->add(std::make_shared<LazyFileNode>("listening",
        [engp]() { return linux::format_listening(*engp); }));
    // v0.28 — best-effort ARP + UNIX socket views (full walks are
    // deferred; see file content for the technical reasons)
    net_dir->add(std::make_shared<LazyFileNode>("arp",
        [engp]() { return linux::format_arp(*engp); }));
    net_dir->add(std::make_shared<LazyFileNode>("unix",
        [engp]() { return linux::format_unix_sockets(*engp); }));
    // v0.29 — routes + netfilter (anchor-only with documented follow-ups
    // for full rule / route trie decoding)
    net_dir->add(std::make_shared<LazyFileNode>("routes",
        [engp]() { return linux::format_routes(*engp); }));
    net_dir->add(std::make_shared<LazyFileNode>("netfilter",
        [engp]() { return linux::format_netfilter(*engp); }));
    // v0.15 — CSV siblings
    net_dir->add(std::make_shared<LazyFileNode>("tcp.csv",
        [engp]() { return linux::format_tcp_csv(*engp); }));
    net_dir->add(std::make_shared<LazyFileNode>("udp.csv",
        [engp]() { return linux::format_udp_csv(*engp); }));
    // v0.20 — JSON siblings (jq-friendly, escape-safe)
    net_dir->add(std::make_shared<LazyFileNode>("tcp.json",
        [engp]() { return linux::format_tcp_json(*engp); }));
    net_dir->add(std::make_shared<LazyFileNode>("udp.json",
        [engp]() { return linux::format_udp_json(*engp); }));
    root->add(net_dir);

    // /sys/processes/ — text views over the canonical process list (the
    // same data /proc/<pid>-<comm>/ exposes individually). Useful for
    // grep / triage / "show me a pstree".
    auto procs_dir = std::make_shared<DirNode>("processes");
    procs_dir->add(std::make_shared<LazyFileNode>("pslist.txt",
        [engp]() { return linux::format_pslist(*engp); }));
    procs_dir->add(std::make_shared<LazyFileNode>("pstree.txt",
        [engp]() { return linux::format_pstree(*engp); }));
    procs_dir->add(std::make_shared<LazyFileNode>("psaux.txt",
        [engp]() { return linux::format_psaux(*engp); }));
    procs_dir->add(std::make_shared<LazyFileNode>("threads.txt",
        [engp]() { return linux::format_global_threads(*engp); }));
    // v0.15 — CSV export for SIEM / scripting (RFC 4180)
    procs_dir->add(std::make_shared<LazyFileNode>("pslist.csv",
        [engp]() { return linux::format_pslist_csv(*engp); }));
    // v0.20 — JSON sibling
    procs_dir->add(std::make_shared<LazyFileNode>("pslist.json",
        [engp]() { return linux::format_pslist_json(*engp); }));
    // Tag the process views so EVERY forensic mode (quick/smart/full) pre-warms
    // them in the background: pslist/pstree/psaux/threads are core triage
    // artefacts, so they should be ready the moment you open /sys/processes.
    // SystemInfo (always-on in any mode) + Small keeps them in the warm set;
    // their producers just format the already-enumerated process list, so
    // warming is fast.
    for (auto& e : procs_dir->list())
        e.node->set_cost({ FileCost::Compute::Expensive, FileCost::Mem::Small,
                           FileCost::Category::SystemInfo });
    root->add(procs_dir);

    // /sys/findevil/ — threat-hunt heuristics (malfind, psscan, hidden_modules).
    // MemProcFS-style aggregated "is this box compromised?" answer.
    auto fe_dir = std::make_shared<DirNode>("findevil");
    fe_dir->add(std::make_shared<LazyFileNode>("triage.txt",
        [engp]() { return linux::format_findevil_triage(*engp); }));
    fe_dir->add(std::make_shared<LazyFileNode>("indicators.txt",
        [engp]() { return linux::format_findevil_indicators_txt(*engp); }));
    fe_dir->add(std::make_shared<LazyFileNode>("indicators.csv",
        [engp]() { return linux::format_findevil_indicators_csv(*engp); }));
    fe_dir->add(std::make_shared<LazyFileNode>("indicators.json",
        [engp]() { return linux::format_findevil_indicators_json(*engp); }));
    fe_dir->add(std::make_shared<LazyFileNode>("findevil.txt",
        [engp]() { return linux::format_findevil_summary(*engp); }));
    fe_dir->add(std::make_shared<LazyFileNode>("malfind.txt",
        [engp]() { return linux::format_findevil_malfind(*engp); }));
    fe_dir->add(std::make_shared<LazyFileNode>("psscan.txt",
        [engp]() { return linux::format_findevil_psscan(*engp); }));
    fe_dir->add(std::make_shared<LazyFileNode>("hidden_modules.txt",
        [engp]() { return linux::format_findevil_hidden_modules(*engp); }));
    fe_dir->add(std::make_shared<LazyFileNode>("check_syscall.txt",
        [engp]() { return linux::format_check_syscall(*engp); }));
    fe_dir->add(std::make_shared<LazyFileNode>("tty_check.txt",
        [engp]() { return linux::format_tty_check(*engp); }));
    fe_dir->add(std::make_shared<LazyFileNode>("keyboard_notifiers.txt",
        [engp]() { return linux::format_keyboard_notifiers(*engp); }));
    // v0.13 — kernel integrity checks bundle
    fe_dir->add(std::make_shared<LazyFileNode>("check_idt.txt",
        [engp]() { return linux::format_check_idt(*engp); }));
    fe_dir->add(std::make_shared<LazyFileNode>("check_afinfo.txt",
        [engp]() { return linux::format_check_afinfo(*engp); }));
    fe_dir->add(std::make_shared<LazyFileNode>("check_creds.txt",
        [engp]() { return linux::format_check_creds(*engp); }));
    fe_dir->add(std::make_shared<LazyFileNode>("check_modules.txt",
        [engp]() { return linux::format_check_modules(*engp); }));
    // v0.14 — eBPF program enumeration (modern rootkit attack surface)
    fe_dir->add(std::make_shared<LazyFileNode>("ebpf.txt",
        [engp]() { return linux::format_ebpf_programs(*engp); }));
    // v0.14 — entropy-based packer/encryption detection
    fe_dir->add(std::make_shared<LazyFileNode>("entropy.txt",
        [engp]() { return linux::format_findevil_entropy(*engp); }));
    // v0.15 — modxview (three-source: list × mod_tree × kallsyms)
    fe_dir->add(std::make_shared<LazyFileNode>("modxview.txt",
        [engp]() { return linux::format_modxview(*engp); }));
    // v0.15 — CSV siblings (SIEM-friendly: RFC 4180)
    fe_dir->add(std::make_shared<LazyFileNode>("malfind.csv",
        [engp]() { return linux::format_malfind_csv(*engp); }));
    fe_dir->add(std::make_shared<LazyFileNode>("findevil.csv",
        [engp]() { return linux::format_findevil_csv(*engp); }));
    // v0.20 — JSON siblings (jq / pandas / SIEM-friendly)
    fe_dir->add(std::make_shared<LazyFileNode>("malfind.json",
        [engp]() { return linux::format_malfind_json(*engp); }));
    fe_dir->add(std::make_shared<LazyFileNode>("findevil.json",
        [engp]() { return linux::format_findevil_json(*engp); }));
    // v0.16 — kprobe enumeration (closes Tier-5 rootkit-detection set)
    fe_dir->add(std::make_shared<LazyFileNode>("kprobes.txt",
        [engp]() { return linux::format_kprobes(*engp); }));
    // v0.20 — AV / EDR fingerprinting (process + module signature scan)
    fe_dir->add(std::make_shared<LazyFileNode>("av_edr.txt",
        [engp]() { return linux::format_av_edr(*engp); }));
    // v0.26 — tracepoints with active handlers (Tier 5 close-out)
    fe_dir->add(std::make_shared<LazyFileNode>("tracepoints.txt",
        [engp]() { return linux::format_tracepoints(*engp); }));
    // Every findevil check is expensive to compute (walks kernel structures)
    // but tiny in memory — exactly the profile forensic mode warms. Bulk-tag
    // the whole subtree (ThreatHunt category) rather than annotating each.
    for (auto& e : fe_dir->list())
        e.node->set_cost({ FileCost::Compute::Expensive, FileCost::Mem::Small,
                           FileCost::Category::ThreatHunt });
    root->add(fe_dir);

    // kallsyms — /proc/kallsyms-style listing of every kernel symbol
    // extracted by `lmpfs::linux::extract_kallsyms()`. Same layout as
    // the running kernel's /proc/kallsyms so tools that parse that file
    // (perf, drgn, BCC, custom scripts) can ingest it unchanged.
    root->add(std::make_shared<LazyFileNode>("kallsyms", [engp]() -> ByteBuf {
        const auto& k = engp->kallsyms();
        if (!k.ok) {
            const char msg[] =
                "; kallsyms extraction failed (no CONFIG_KALLSYMS, or scan miss).\n"
                "; This file would normally be a /proc/kallsyms clone.\n";
            return ByteBuf(msg, msg + sizeof(msg) - 1);
        }
        std::string out;
        out.reserve(k.symbols.size() * 48);
        for (const auto& e : k.symbols) {
            // /proc/kallsyms format: "<16-hex-addr> <type> <name>\n"
            fmt::format_to(std::back_inserter(out), "{:016x} {} {}\n",
                           e.address, e.type, e.name);
        }
        return ByteBuf(out.begin(), out.end());
    }));

    // btf.txt — probe for embedded BTF (offline-capable symbol generation).
    root->add(std::make_shared<LazyFileNode>("btf.txt", [engp]() -> ByteBuf {
        auto info = linux::probe_btf(engp->phys());
        std::string s;
        if (!info) {
            s = "; no BTF detected in dump\n"
                "; (kernel was likely built without CONFIG_DEBUG_INFO_BTF=y, OR\n"
                ";  the BTF blob is past our scan range)\n";
        } else {
            s = fmt::format(
                "available:   yes\n"
                "offset_pa:   {:#018x}\n"
                "size_bytes:  {}\n"
                "version:     {:#x}\n"
                "; Offline symbol generation from this BTF is on the roadmap.\n"
                "; Today this file is informational only.\n",
                info->offset_pa, info->size, info->version);
        }
        return ByteBuf(s.begin(), s.end());
    }));

    return root;
}

} // namespace lmpfs::vfs
