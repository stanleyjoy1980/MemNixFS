// json_export.cpp — see header.
#include "os/linux/json_export.h"
#include "os/linux/netstat.h"
#include "os/linux/findevil.h"
#include "os/linux/integrity_checks.h"
#include "os/linux/check_syscall.h"
#include "os/linux/task_files.h"
#include "app/engine.h"
#include "symbols/isf_symbols.h"
#include "core/log.h"
#include <nlohmann/json.hpp>
#include <fmt/format.h>
#include <array>

namespace lmpfs::linux {

namespace {

using json = nlohmann::json;

// Same cmdline-as-string reader as csv_export.cpp. Could be hoisted to
// task_files.h, but keeping it local avoids cross-file coupling for a
// 12-line helper.
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

// Render a top-level array, 2-space indent. nlohmann::json's `.dump(2)`
// emits JSON-pretty output that's compatible with jq's parser.
//
// `error_handler_t::replace` substitutes U+FFFD for any non-UTF-8 byte —
// essential because Linux kernel `comm` (16 chars) and cmdline strings
// can carry arbitrary bytes (truncated multi-byte codepoints, locale-
// dependent binary, kernel-thread names containing slashes etc.).
// Without this, dump() throws json.exception.type_error.316 the moment
// it sees one bad byte and the whole pslist.json fails.
ByteBuf dump_json(const json& j) {
    std::string s = j.dump(2, ' ', /*ensure_ascii=*/false,
                            json::error_handler_t::replace);
    s.push_back('\n');
    return ByteBuf(s.begin(), s.end());
}

ByteBuf format_sockets_json(const Engine& eng, SocketInfo::Proto only,
                            const char* proto_name)
{
    auto socks = (only == SocketInfo::P_UDP)
                   ? enumerate_udp_sockets(eng)
                   : enumerate_tcp_sockets(eng);
    json arr = json::array();
    for (const auto& s : socks) {
        if (s.proto != only) continue;
        const char* fam = s.family == SocketInfo::AF_INET6 ? "INET6"
                       : s.family == SocketInfo::AF_INET4 ? "INET"  : "?";
        json o;
        o["proto"]       = proto_name;
        o["state"]       = tcp_state_name(s.state);
        o["family"]      = fam;
        o["local_ip"]    = fmt_addr(s, s.local_addr);
        o["local_port"]  = s.local_port;
        o["remote_ip"]   = fmt_addr(s, s.remote_addr);
        o["remote_port"] = s.remote_port;
        o["sock_va"]     = fmt::format("{:#x}", s.sock_va);
        arr.push_back(std::move(o));
    }
    return dump_json(arr);
}

} // anonymous

ByteBuf format_pslist_json(const Engine& eng) {
    json arr = json::array();
    for (const auto& p : eng.processes()) {
        json o;
        o["pid"]     = p.pid;
        o["ppid"]    = p.ppid;
        o["tgid"]    = p.tgid;
        o["uid"]     = p.uid;
        o["comm"]    = p.comm;
        o["cmdline"] = read_cmdline_oneline(eng, p);
        arr.push_back(std::move(o));
    }
    return dump_json(arr);
}

ByteBuf format_tcp_json(const Engine& eng) { return format_sockets_json(eng, SocketInfo::P_TCP, "TCP"); }
ByteBuf format_udp_json(const Engine& eng) { return format_sockets_json(eng, SocketInfo::P_UDP, "UDP"); }

ByteBuf format_malfind_json(const Engine& eng) {
    json arr = json::array();
    for (const auto& p : eng.processes()) {
        std::vector<MalfindHit> hits;
        try { hits = find_malfind(eng, p); } catch (...) { continue; }
        for (const auto& h : hits) {
            json o;
            o["pid"]      = p.pid;
            o["comm"]     = p.comm;
            o["vm_start"] = fmt::format("{:#x}", h.vm_start);
            o["vm_end"]   = fmt::format("{:#x}", h.vm_end);
            o["size"]     = h.vm_end - h.vm_start;
            o["perms"]    = {
                { "r", (h.vm_flags & 1) != 0 },
                { "w", (h.vm_flags & 2) != 0 },
                { "x", (h.vm_flags & 4) != 0 },
            };
            o["severity"] = h.high_severity ? "HIGH" : "INFO";
            o["reason"]   = h.reason;
            arr.push_back(std::move(o));
        }
    }
    return dump_json(arr);
}

ByteBuf format_findevil_json(const Engine& eng) {
    // Recompute the same per-check counters as format_findevil_csv. Single
    // object — emit as the only element of a single-row array so downstream
    // SIEM ingesters that always expect "one event per file" still work.
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

    json o;
    o["malfind_total"]       = mal_total;
    o["malfind_high"]        = mal_high_total;
    o["psscan_hidden"]       = hidden_tasks;
    o["syscall_hooked"]      = syscall_hooked;
    o["idt_hooked"]          = idt_hooked;
    o["modules_asymmetric"]  = mod_asym;

    json arr = json::array();
    arr.push_back(std::move(o));
    return dump_json(arr);
}

} // namespace lmpfs::linux
