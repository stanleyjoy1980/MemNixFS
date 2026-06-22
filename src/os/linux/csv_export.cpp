// csv_export.cpp — see header.
#include "os/linux/csv_export.h"
#include "os/linux/netstat.h"
#include "os/linux/findevil.h"
#include "os/linux/integrity_checks.h"
#include "os/linux/check_syscall.h"
#include "os/linux/task_files.h"
#include "app/engine.h"
#include "symbols/isf_symbols.h"
#include "core/log.h"
#include <fmt/format.h>
#include <array>

namespace lmpfs::linux {

std::string csv_quote(std::string s) {
    bool needs = false;
    for (char c : s)
        if (c == ',' || c == '"' || c == '\r' || c == '\n') { needs = true; break; }
    if (!needs) return s;
    std::string out;
    out.reserve(s.size() + 2);
    out.push_back('"');
    for (char c : s) {
        if (c == '"') out.push_back('"');
        out.push_back(c);
    }
    out.push_back('"');
    return out;
}

namespace {

// Internal helper to read cmdline as a single-line string (NULs → spaces).
std::string read_cmdline_oneline(const Engine& eng, const Process& p) {
    if (p.mm == 0) return fmt::format("[{}]", p.comm);
    ByteBuf raw;
    try { raw = gen_cmdline(eng.phys(), eng.isf(), eng.kernel(), p); }
    catch (...) { return ""; }
    if (raw.empty()) return "";
    std::string s;
    s.reserve(raw.size());
    for (u8 c : raw) {
        if (c == 0) s.push_back(' ');
        else if (c < 0x20 || c == 0x7F) s.push_back('?');
        else s.push_back((char)c);
    }
    while (!s.empty() && s.back() == ' ') s.pop_back();
    return s;
}

inline u16 be16(u16 x) { return (u16)((x >> 8) | (x << 8)); }

std::string fmt_addr(const SocketInfo& s, const std::array<u8,16>& a) {
    if (s.family == SocketInfo::AF_INET6)
        return fmt::format(
            "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:"
            "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
            a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7],
            a[8],a[9],a[10],a[11],a[12],a[13],a[14],a[15]);
    return fmt::format("{}.{}.{}.{}", a[0], a[1], a[2], a[3]);
}

const char* tcp_state_name(u32 s) {
    static const char* names[] = {
        "UNKNOWN","ESTABLISHED","SYN_SENT","SYN_RECV","FIN_WAIT1","FIN_WAIT2",
        "TIME_WAIT","CLOSE","CLOSE_WAIT","LAST_ACK","LISTEN","CLOSING","NEW_SYN_RECV"
    };
    return s < std::size(names) ? names[s] : "?";
}

} // anonymous

ByteBuf format_pslist_csv(const Engine& eng) {
    std::string out;
    out.reserve(64 * 1024);
    out += "pid,ppid,tgid,uid,comm,cmdline\r\n";
    for (const auto& p : eng.processes()) {
        out += fmt::format("{},{},{},{},{},{}\r\n",
                           p.pid, p.ppid, p.tgid, p.uid,
                           csv_quote(p.comm),
                           csv_quote(read_cmdline_oneline(eng, p)));
    }
    return ByteBuf(out.begin(), out.end());
}

namespace {

ByteBuf format_socket_csv(const Engine& eng, SocketInfo::Proto only,
                           const char* proto_name)
{
    auto socks = (only == SocketInfo::P_UDP)
                   ? enumerate_udp_sockets(eng)
                   : enumerate_tcp_sockets(eng);
    std::string out;
    out.reserve(8 * 1024);
    // Emit the header even when empty so SIEM ingesters that schema-
    // detect from the first row don't blow up. Append a comment line
    // explaining the empty result (CSV technically allows #-prefix
    // lines; jq/pandas typically skip rows starting with #).
    out += "proto,state,family,local_ip,local_port,remote_ip,remote_port,sock_va\r\n";
    if (socks.empty()) {
        out += "# (no sockets enumerated — likely missing tcp_hashinfo / "
               "udp_table symbol in the dump's ISF)\r\n";
        return ByteBuf(out.begin(), out.end());
    }
    for (const auto& s : socks) {
        if (s.proto != only) continue;
        const char* fam = s.family == SocketInfo::AF_INET6 ? "INET6"
                       : s.family == SocketInfo::AF_INET4 ? "INET"  : "?";
        out += fmt::format("{},{},{},{},{},{},{},{:#x}\r\n",
                           proto_name,
                           tcp_state_name(s.state),
                           fam,
                           csv_quote(fmt_addr(s, s.local_addr)),  s.local_port,
                           csv_quote(fmt_addr(s, s.remote_addr)), s.remote_port,
                           s.sock_va);
    }
    return ByteBuf(out.begin(), out.end());
}

} // anonymous

ByteBuf format_tcp_csv(const Engine& eng) { return format_socket_csv(eng, SocketInfo::P_TCP, "TCP"); }
ByteBuf format_udp_csv(const Engine& eng) { return format_socket_csv(eng, SocketInfo::P_UDP, "UDP"); }

ByteBuf format_malfind_csv(const Engine& eng) {
    std::string out;
    out.reserve(16 * 1024);
    out += "pid,comm,vm_start,vm_end,size,perms,severity,reason\r\n";
    for (const auto& p : eng.processes()) {
        std::vector<MalfindHit> hits;
        try { hits = find_malfind(eng, p); } catch (...) { continue; }
        for (const auto& h : hits) {
            char perm[4] = {
                (h.vm_flags & 1) ? 'r' : '-',
                (h.vm_flags & 2) ? 'w' : '-',
                (h.vm_flags & 4) ? 'x' : '-',
                0
            };
            out += fmt::format("{},{},{:#x},{:#x},{},{},{},{}\r\n",
                               p.pid,
                               csv_quote(p.comm),
                               h.vm_start, h.vm_end,
                               h.vm_end - h.vm_start,
                               perm,
                               h.high_severity ? "HIGH" : "INFO",
                               csv_quote(h.reason));
        }
    }
    return ByteBuf(out.begin(), out.end());
}

ByteBuf format_findevil_csv(const Engine& eng) {
    // Single-row CSV: per-check counts. Wide schema for SIEM ingest —
    // one event per dump.
    std::size_t mal_total = 0, mal_high_total = 0;
    for (const auto& p : eng.processes()) {
        std::vector<MalfindHit> h;
        try { h = find_malfind(eng, p); } catch (...) { continue; }
        for (const auto& x : h) {
            ++mal_total;
            if (x.high_severity) ++mal_high_total;
        }
    }
    auto ps = scan_for_tasks(eng);
    std::size_t hidden_tasks = 0;
    for (const auto& h : ps) if (!h.on_official_list) ++hidden_tasks;
    auto syscalls = check_syscall_table(eng);
    std::size_t syscall_hooked = 0;
    for (const auto& s : syscalls)
        if (s.status == SyscallEntry::HOOKED) ++syscall_hooked;
    auto idt = audit_idt(eng);
    std::size_t idt_hooked = 0;
    for (const auto& e : idt)
        if (e.audit.status == PtrAudit::HOOKED) ++idt_hooked;
    auto modx = audit_modules_cross(eng);
    std::size_t mod_asym = 0;
    for (const auto& m : modx)
        if (!(m.in_list_walk && m.in_mod_tree && m.in_kallsyms)) ++mod_asym;

    std::string out;
    out += "malfind_total,malfind_high,psscan_hidden,syscall_hooked,"
           "idt_hooked,modules_asymmetric\r\n";
    out += fmt::format("{},{},{},{},{},{}\r\n",
                       mal_total, mal_high_total, hidden_tasks,
                       syscall_hooked, idt_hooked, mod_asym);
    return ByteBuf(out.begin(), out.end());
}

} // namespace lmpfs::linux
