// forensic_snapshot.cpp — see header.
#include "os/linux/forensic_snapshot.h"
#include "os/linux/findevil.h"
#include "os/linux/av_edr.h"
#include "os/linux/netstat.h"
#include "os/linux/integrity_checks.h"
#include "os/linux/check_syscall.h"
#include "os/linux/ebpf.h"
#include "os/linux/entropy.h"
#include "os/linux/tracing.h"
#include "os/linux/modules.h"
#include "os/linux/kernel_resolver.h"
#include "app/engine.h"
#include "core/log.h"
#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <unordered_map>

namespace lmpfs::linux {

namespace {

using json = nlohmann::json;

// Collect every counter we display, so txt and json share one
// computation pass. Doing the work twice would be wasteful given that
// some of these checks (malfind, scan_for_tasks, entropy) are
// individually multi-second.
struct Counters {
    // env
    std::string banner;
    u64         direct_map_base = 0;
    u64         kaslr_phys_shift = 0;
    // process
    std::size_t proc_total = 0;
    std::size_t proc_kernel = 0;       // mm == 0
    std::size_t proc_user   = 0;
    std::unordered_map<u32, std::size_t> by_uid;
    // network
    std::size_t tcp_total = 0, tcp_listen = 0, tcp_estab = 0;
    std::size_t udp_total = 0;
    // threat-hunt
    std::size_t mal_total = 0, mal_high = 0, mal_pids = 0;
    std::size_t ps_total = 0, ps_hidden = 0;
    std::size_t hm_total = 0, hm_hidden = 0;
    std::size_t syscall_n = 0, syscall_hooked = 0;
    std::size_t idt_hooked = 0;
    std::size_t afi_hooked = 0;
    std::size_t cred_susp = 0;
    std::size_t modx_total = 0, modx_asym = 0;
    std::size_t bpf_total = 0, bpf_tracing = 0;
    std::size_t entropy_pids = 0, entropy_hits = 0;
    std::size_t kp_total = 0, kp_hooked = 0;
    // av/edr
    std::size_t ae_proc = 0, ae_mod = 0;
    std::vector<std::string> ae_products;   // unique product names
};

Counters compute_counters(const Engine& eng) {
    Counters c;
    const auto& k = eng.kernel();
    c.banner            = k.banner;
    c.direct_map_base   = k.direct_map_base;
    c.kaslr_phys_shift  = static_cast<u64>(k.kaslr_phys_shift);

    for (const auto& p : eng.processes()) {
        ++c.proc_total;
        if (p.mm == 0) ++c.proc_kernel;
        else           ++c.proc_user;
        ++c.by_uid[p.uid];
    }

    // Sockets — single enumerate call serves both protocols.
    auto tcp = enumerate_tcp_sockets(eng);
    c.tcp_total = tcp.size();
    for (const auto& s : tcp) {
        if (s.state == 10) ++c.tcp_listen;       // LISTEN
        else if (s.state == 1) ++c.tcp_estab;    // ESTABLISHED
    }
    auto udp = enumerate_udp_sockets(eng);
    c.udp_total = udp.size();

    // malfind
    for (const auto& p : eng.processes()) {
        std::vector<MalfindHit> h;
        try { h = find_malfind(eng, p); } catch (...) { continue; }
        if (h.empty()) continue;
        ++c.mal_pids;
        c.mal_total += h.size();
        for (const auto& x : h) if (x.high_severity) ++c.mal_high;
    }

    // psscan
    auto ps = scan_for_tasks(eng);
    c.ps_total = ps.size();
    for (const auto& h : ps) if (!h.on_official_list) ++c.ps_hidden;

    // hidden_modules
    auto hm = scan_for_modules(eng);
    c.hm_total = hm.size();
    for (const auto& h : hm) if (!h.on_official_list) ++c.hm_hidden;

    // check_syscall
    auto sy = check_syscall_table(eng);
    c.syscall_n = sy.size();
    for (const auto& s : sy) if (s.status == SyscallEntry::HOOKED) ++c.syscall_hooked;

    // idt
    auto idt = audit_idt(eng);
    for (const auto& e : idt) if (e.audit.status == PtrAudit::HOOKED) ++c.idt_hooked;

    // afinfo
    auto afi = audit_afinfo(eng);
    for (const auto& a : afi)
        for (const auto& s : a.slots)
            if (s.status == PtrAudit::HOOKED) ++c.afi_hooked;

    // creds
    auto creds = audit_creds(eng);
    for (const auto& cr : creds) if (cr.suspicious) ++c.cred_susp;

    // module cross
    auto modx = audit_modules_cross(eng);
    c.modx_total = modx.size();
    for (const auto& m : modx) if (m.in_list_walk != m.in_mod_tree) ++c.modx_asym;

    // ebpf
    auto bpf = enumerate_bpf_programs(eng);
    c.bpf_total = bpf.size();
    for (const auto& b : bpf) {
        if (b.type == 2 || b.type == 5 || b.type == 17 ||
            b.type == 26 || b.type == 29) ++c.bpf_tracing;
    }

    // entropy
    for (const auto& p : eng.processes()) {
        if (p.mm == 0) continue;
        std::vector<EntropyHit> hs;
        try { hs = scan_entropy(eng, p); } catch (...) { continue; }
        bool any = false;
        for (const auto& h : hs) if (h.entropy >= 7.0) { ++c.entropy_hits; any = true; }
        if (any) ++c.entropy_pids;
    }

    // kprobes
    auto kps = enumerate_kprobes(eng);
    c.kp_total = kps.size();
    for (const auto& kp : kps)
        if (kp.pre_audit.status == PtrAudit::HOOKED ||
            kp.post_audit.status == PtrAudit::HOOKED) ++c.kp_hooked;

    // av/edr
    auto ae = scan_av_edr(eng);
    std::unordered_map<std::string, int> uniq;
    for (const auto& h : ae) {
        if (h.source == AvEdrHit::Source::Process) ++c.ae_proc;
        else                                       ++c.ae_mod;
        ++uniq[h.product];
    }
    for (const auto& [name, _] : uniq) c.ae_products.push_back(name);
    return c;
}

} // anonymous

ByteBuf format_forensic_snapshot_txt(const Engine& eng) {
    Counters c = compute_counters(eng);
    std::string out;
    out.reserve(8 * 1024);

    out += "# /forensic/snapshot.txt — one-stop dump triage report\n";
    out += "# Sections: ENVIRONMENT · PROCESSES · NETWORK · THREAT HUNT · AV/EDR\n";
    out += "# All counts are computed at the time the file is read (single pass).\n\n";

    // --- environment ---
    out += "[ENVIRONMENT]\n";
    out += fmt::format("  Kernel banner   : {}\n",
                       c.banner.empty() ? "(unknown)" : c.banner);
    out += fmt::format("  direct_map_base : {:#x}\n",   c.direct_map_base);
    out += fmt::format("  kaslr_phys_shift: {:#x}\n\n", c.kaslr_phys_shift);

    // --- processes ---
    out += "[PROCESSES]\n";
    out += fmt::format("  total           : {} ({} user, {} kernel)\n",
                       c.proc_total, c.proc_user, c.proc_kernel);
    // Top UIDs by count.
    std::vector<std::pair<u32, std::size_t>> uids(c.by_uid.begin(), c.by_uid.end());
    std::sort(uids.begin(), uids.end(),
              [](auto& a, auto& b) { return a.second > b.second; });
    out += "  by uid (top 5)  : ";
    for (std::size_t i = 0; i < std::min<std::size_t>(5, uids.size()); ++i) {
        if (i) out += ", ";
        out += fmt::format("uid={}:{}", uids[i].first, uids[i].second);
    }
    out += "\n\n";

    // --- network ---
    out += "[NETWORK]\n";
    out += fmt::format("  TCP sockets     : {} ({} LISTEN, {} ESTABLISHED)\n",
                       c.tcp_total, c.tcp_listen, c.tcp_estab);
    out += fmt::format("  UDP sockets     : {}\n\n", c.udp_total);

    // --- threat hunt ---
    out += "[THREAT HUNT]\n";
    out += fmt::format("  malfind         : {} hits across {} process(es); "
                       "{} HIGH-SEVERITY\n",
                       c.mal_total, c.mal_pids, c.mal_high);
    out += fmt::format("  psscan          : {} candidates by phys scan; "
                       "{} HIDDEN (not in visible list)\n",
                       c.ps_total, c.ps_hidden);
    out += fmt::format("  hidden_modules  : {} records; {} HIDDEN\n",
                       c.hm_total, c.hm_hidden);
    out += fmt::format("  check_syscall   : {} syscalls; {} HOOKED\n",
                       c.syscall_n, c.syscall_hooked);
    out += fmt::format("  check_idt       : 256 IDT entries; {} HOOKED\n",
                       c.idt_hooked);
    out += fmt::format("  check_afinfo    : /proc/net seq_ops; {} HOOKED\n",
                       c.afi_hooked);
    out += fmt::format("  check_creds     : {} suspicious cred-sharing entries\n",
                       c.cred_susp);
    out += fmt::format("  check_modules   : {} module records cross-viewed; "
                       "{} ★ ASYMMETRIC\n",
                       c.modx_total, c.modx_asym);
    out += fmt::format("  ebpf            : {} programs; {} of TRACING/KPROBE/LSM type\n",
                       c.bpf_total, c.bpf_tracing);
    out += fmt::format("  entropy         : {} process(es) with high-entropy VMA(s); "
                       "{} hits\n",
                       c.entropy_pids, c.entropy_hits);
    out += fmt::format("  kprobes         : {} registered; {} with HOOKED handler\n\n",
                       c.kp_total, c.kp_hooked);

    // --- av/edr ---
    out += "[AV / EDR]\n";
    out += fmt::format("  userspace agents: {}\n", c.ae_proc);
    out += fmt::format("  LKM agents      : {}\n", c.ae_mod);
    if (!c.ae_products.empty()) {
        out += "  products        : ";
        for (std::size_t i = 0; i < c.ae_products.size(); ++i) {
            if (i) out += ", ";
            out += c.ae_products[i];
        }
        out += "\n";
    }
    out += "\n";

    // --- verdict ---
    const bool truly_bad = (c.mal_high > 0) || (c.ps_hidden > 0) ||
                            (c.hm_hidden > 0) || (c.syscall_hooked > 0) ||
                            (c.idt_hooked > 0) || (c.afi_hooked > 0) ||
                            (c.cred_susp > 0) || (c.modx_asym > 0) ||
                            (c.kp_hooked > 0);
    if (!truly_bad) {
        out += "VERDICT: no high-severity findings.\n"
               "         The box looks clean by these heuristics (NOT a clean\n"
               "         bill of health — confirm by manual inspection of\n"
               "         /sys/findevil/*.txt).\n";
    } else {
        out += "VERDICT: ★ SUSPICIOUS — at least one high-severity threat-hunt\n"
               "         signal fired. Inspect the per-check files in\n"
               "         /sys/findevil/.\n";
    }
    return ByteBuf(out.begin(), out.end());
}

ByteBuf format_forensic_snapshot_json(const Engine& eng) {
    Counters c = compute_counters(eng);
    json o;
    o["env"] = {
        { "banner",            c.banner },
        { "direct_map_base",   fmt::format("{:#x}", c.direct_map_base) },
        { "kaslr_phys_shift",  fmt::format("{:#x}", c.kaslr_phys_shift) },
    };
    json by_uid = json::object();
    for (const auto& [uid, n] : c.by_uid) by_uid[std::to_string(uid)] = n;
    o["processes"] = {
        { "total",   c.proc_total },
        { "user",    c.proc_user },
        { "kernel",  c.proc_kernel },
        { "by_uid",  by_uid },
    };
    o["network"] = {
        { "tcp_total",  c.tcp_total },
        { "tcp_listen", c.tcp_listen },
        { "tcp_estab",  c.tcp_estab },
        { "udp_total",  c.udp_total },
    };
    o["threat_hunt"] = {
        { "malfind_total",      c.mal_total },
        { "malfind_high",       c.mal_high },
        { "malfind_pids",       c.mal_pids },
        { "psscan_total",       c.ps_total },
        { "psscan_hidden",      c.ps_hidden },
        { "hidden_modules",     c.hm_hidden },
        { "syscall_hooked",     c.syscall_hooked },
        { "idt_hooked",         c.idt_hooked },
        { "afinfo_hooked",      c.afi_hooked },
        { "creds_suspicious",   c.cred_susp },
        { "modules_asymmetric", c.modx_asym },
        { "ebpf_total",         c.bpf_total },
        { "ebpf_tracing",       c.bpf_tracing },
        { "entropy_pids",       c.entropy_pids },
        { "entropy_hits",       c.entropy_hits },
        { "kprobes_total",      c.kp_total },
        { "kprobes_hooked",     c.kp_hooked },
    };
    o["av_edr"] = {
        { "userspace_agents", c.ae_proc },
        { "lkm_agents",       c.ae_mod },
        { "products",         c.ae_products },
    };
    const bool truly_bad = (c.mal_high > 0) || (c.ps_hidden > 0) ||
                            (c.hm_hidden > 0) || (c.syscall_hooked > 0) ||
                            (c.idt_hooked > 0) || (c.afi_hooked > 0) ||
                            (c.cred_susp > 0) || (c.modx_asym > 0) ||
                            (c.kp_hooked > 0);
    o["verdict"] = truly_bad ? "SUSPICIOUS" : "clean-by-heuristics";

    // error_handler_t::replace — comm / banner / cmdline may include
    // non-UTF-8 bytes (kernel doesn't enforce encoding). Without this,
    // dump() throws the moment it sees one bad byte.
    std::string s = o.dump(2, ' ', /*ensure_ascii=*/false,
                            json::error_handler_t::replace);
    s.push_back('\n');
    return ByteBuf(s.begin(), s.end());
}

} // namespace lmpfs::linux
