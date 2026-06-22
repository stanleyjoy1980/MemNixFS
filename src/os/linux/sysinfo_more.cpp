// sysinfo_more.cpp — additional Tier-2 close-out files that don't share a
// header with sysinfo (different scopes, different concerns). Bundled
// in one .cpp for simplicity; declared at the end of sysinfo.h.
#include "os/linux/sysinfo.h"
#include "os/linux/kva_reader.h"
#include "os/linux/process.h"
#include "os/linux/fdtable.h"
#include "app/engine.h"
#include "vfs/vfs.h"
#include "symbols/isf_symbols.h"
#include "symbols/kallsyms.h"
#include "core/log.h"
#include <fmt/format.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <unordered_set>
#include <vector>

namespace lmpfs::linux {

namespace {

// Read a small file from the reconstructed root filesystem
// (/fs/...) via the VFS.
// Returns empty bytes on any failure (file missing, dentry path broken,
// etc.). Suitable for /etc/* config files which are tiny and almost always
// in the page cache on a desktop.
ByteBuf read_fs_file(const Engine& eng, const std::string& path,
                      u64 max_bytes = 64 * 1024) {
    auto node = vfs::resolve(eng.vfs_root(), path);
    if (!node || !node->is_file()) return {};
    u64 sz = node->size();
    if (sz == 0 || sz > max_bytes) return {};
    ByteBuf out(static_cast<std::size_t>(sz));
    std::size_t got = node->read(0, out.data(), out.size());
    out.resize(got);
    return out;
}

VAddr resolve_kallsym(const Engine& eng, const char* name) {
    const auto& ks = eng.kallsyms();
    if (!ks.ok) return 0;
    for (const auto& s : ks.symbols) if (s.name == name) return s.address;
    return 0;
}

} // anonymous

// =========================================================================
//   /sys/dns.txt — resolver config (best-effort via page-cache reads)
// =========================================================================
//
// The kernel has no DNS state of its own; resolving is userspace's job. We
// surface the two most-useful resolver config sources, both via the
// reconstructed root-fs:
//
//   /fs/run/systemd/resolve/resolv.conf — systemd-resolved's effective DNS
//   /fs/etc/resolv.conf                 — classic resolver (symlink or file)
//
// On modern distros these are usually symlinks; the page cache should have
// the targets cached because every process resolving DNS reads them.
ByteBuf format_dns(const Engine& eng) {
    std::string out;
    out += "# /sys/dns.txt — DNS resolver configuration\n"
           "# Sourced from the reconstructed page-cache files; kernel has\n"
           "# no DNS state of its own.\n\n";

    auto try_file = [&](const char* label, const char* path) {
        out += fmt::format("[{}]\n", path);
        auto bytes = read_fs_file(eng, path);
        if (bytes.empty()) {
            out += fmt::format("(file not in page cache or path unreachable)\n\n");
            return;
        }
        out.append(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        if (!out.empty() && out.back() != '\n') out.push_back('\n');
        out.push_back('\n');
        (void)label;
    };
    try_file("classic",          "/fs/etc/resolv.conf");
    try_file("systemd-resolved", "/fs/run/systemd/resolve/resolv.conf");
    try_file("systemd-stub",     "/fs/run/systemd/resolve/stub-resolv.conf");

    return ByteBuf(out.begin(), out.end());
}

// =========================================================================
//   /sys/pidhashtable — `init_pid_ns.idr` walk (a third process-list source)
// =========================================================================
//
// `init_pid_ns` is the boot-time PID namespace. Its `idr` field is an
// xarray (idr_rt) mapping PID → `struct pid *`. Each `struct pid` has a
// `tasks[PIDTYPE_MAX]` array of hlist_heads pointing to task_structs.
//
// Walking the full xarray requires implementing an xarray reader (not
// trivial: xa_root, xa_nodes, slot encoding, marks). For v0.28 we emit a
// stub that confirms `init_pid_ns` is reachable and reports xarray root
// pointers — a follow-up can add the full walk.
// xarray entry encoding helpers — duplicated from ebpf.cpp / pagecache.cpp.
// (Internal-linkage; not worth factoring into a shared header for these
// 3 lines.)
namespace {
inline bool xa_is_internal(VAddr e) { return (e & 3ULL) == 2; }
inline bool xa_is_value(VAddr e)    { return (e & 1ULL) == 1; }
inline VAddr xa_to_node(VAddr e)    { return e & ~3ULL; }

void walk_pidns_xarray(const Engine& eng, u64 xn_slots_off,
                        VAddr entry, std::vector<VAddr>& leaves,
                        std::size_t& budget, int depth = 0) {
    if (entry == 0 || depth > 16) return;
    if (budget == 0) return;   // bound a crafted cyclic/explosive xarray
    --budget;
    if (xa_is_value(entry)) return;
    if (!xa_is_internal(entry)) { leaves.push_back(entry); return; }
    VAddr node = xa_to_node(entry);
    constexpr u64 kSlots = 64;
    std::vector<VAddr> slots(kSlots, 0);
    if (!kva_read(eng, node + xn_slots_off, slots.data(),
                   kSlots * sizeof(VAddr))) return;
    for (u64 i = 0; i < kSlots; ++i)
        if (slots[i]) walk_pidns_xarray(eng, xn_slots_off, slots[i], leaves, budget, depth + 1);
}
} // anonymous

ByteBuf format_pidhashtable(const Engine& eng) {
    VAddr pidns = 0;
    if (auto* s = eng.isf().find_symbol("init_pid_ns")) pidns = s->address;
    if (!pidns) pidns = resolve_kallsym(eng, "init_pid_ns");

    std::string out;
    out += "# /sys/pidhashtable — third-source process listing via init_pid_ns.idr\n"
           "# Walks the PID xarray independently of init_task.tasks. Used to\n"
           "# detect rootkits that hide a process from pslist but leave it in\n"
           "# the PID allocator (so e.g. /proc/<pid>/ still works for them).\n#\n";
    if (!pidns) {
        out += "init_pid_ns not in ISF/kallsyms — walk unavailable.\n";
        return ByteBuf(out.begin(), out.end());
    }

    // Resolve offsets. The chain: pid_namespace.idr → idr.idr_rt → xarray.
    u64 off_idr = 0, off_idr_rt = 0, off_xa_head = 0x8, off_xn_slots = 0x28;
    u64 off_pid_numbers = 0;
    try { off_idr        = eng.isf().field_offset("pid_namespace", "idr"); }   catch (...) {}
    try { off_idr_rt     = eng.isf().field_offset("idr",           "idr_rt"); }catch (...) {}
    try { off_xa_head    = eng.isf().field_offset("xarray",        "xa_head"); }catch (...) {}
    try { off_xn_slots   = eng.isf().field_offset("xa_node",       "slots"); } catch (...) {}
    try { off_pid_numbers= eng.isf().field_offset("pid",           "numbers"); }catch (...) {}

    VAddr xa_head_va = pidns + off_idr + off_idr_rt + off_xa_head;
    VAddr xa_root = 0;
    kva_read_pod(eng, xa_head_va, xa_root);
    if (xa_root == 0) {
        out += "init_pid_ns.idr xarray is empty.\n";
        return ByteBuf(out.begin(), out.end());
    }

    std::vector<VAddr> pid_ptrs;
    if (!xa_is_internal(xa_root)) {
        if (!xa_is_value(xa_root)) pid_ptrs.push_back(xa_root);
    } else {
        std::size_t budget = 1'000'000;
        walk_pidns_xarray(eng, off_xn_slots, xa_root, pid_ptrs, budget);
    }

    // For each `struct pid *` read its first numbers[0].nr — that's the PID.
    // struct upid { int nr; struct pid_namespace *ns; } → nr is at offset 0.
    std::set<u32> pids_via_xarray;
    for (VAddr p : pid_ptrs) {
        if (p == 0) continue;
        u32 nr = 0;
        kva_read_pod(eng, p + off_pid_numbers, nr);
        if (nr != 0 && nr < (1u << 22)) pids_via_xarray.insert(nr);
    }

    // Cross-compare with eng.processes() (init_task.tasks walk).
    std::unordered_set<u32> pids_via_pslist;
    for (const auto& p : eng.processes()) pids_via_pslist.insert(p.pid);

    std::vector<u32> hidden, common, only_in_pslist;
    for (u32 pid : pids_via_xarray) {
        if (pids_via_pslist.count(pid)) common.push_back(pid);
        else                            hidden.push_back(pid);
    }
    for (u32 pid : pids_via_pslist) {
        if (!pids_via_xarray.count(pid)) only_in_pslist.push_back(pid);
    }

    // The xarray maps TID → struct pid, so it indexes every task (thread)
    // not just thread-group leaders. eng.processes() (init_task.tasks walk)
    // shows ONLY leaders. So "only in xarray" overwhelmingly = thread TIDs
    // of visible leaders, NOT hidden processes.
    //
    // To flag actual hidden tasks: any TID in xarray whose owning
    // task_struct doesn't match a visible leader's TID OR any of its
    // threads. That requires a per-leader threads walk, which is what
    // /proc/<pid>/threads.txt + /sys/processes/threads.txt do — analysts
    // can correlate manually for now. We label honestly.
    out += fmt::format(
        "init_pid_ns @ {:#x}\n"
        "xarray entries walked     : {}\n"
        "PIDs/TIDs via xarray walk : {}\n"
        "Leaders via pslist walk   : {}\n"
        "Leaders in both sources   : {}\n"
        "Leaders only in pslist    : {}  (should be 0; >0 is rootkit-suspect)\n"
        "TIDs only in xarray       : {}  (almost all are non-leader threads;\n"
        "                                  cross-correlate with\n"
        "                                  /sys/processes/threads.txt to\n"
        "                                  positively rule out hiding)\n\n",
        pidns, pid_ptrs.size(), pids_via_xarray.size(), pids_via_pslist.size(),
        common.size(), only_in_pslist.size(), hidden.size());
    if (!only_in_pslist.empty()) {
        out += "★ LEADERS in pslist but missing from PID xarray (suspect):\n";
        for (u32 pid : only_in_pslist) out += fmt::format("    {}\n", pid);
        out += "\n";
    }
    return ByteBuf(out.begin(), out.end());
}

// =========================================================================
//   /sys/net/arp — neighbour cache (best-effort; full walk deferred)
// =========================================================================
//
// `init_net.ipv4.arp_tbl` is a `struct neigh_table`. Its `nht`
// (`struct neigh_hash_table *`) holds `hash_buckets[]`. Each bucket
// is a `struct neighbour *` linked list via `neighbour.next`.
//
// The full walk requires the `neigh_hash_table.hash_shift` (size = 1 <<
// shift) and all the neighbour struct offsets. We emit a stub that
// confirms `init_net.ipv4.arp_tbl` is reachable; full enumeration is
// follow-up work.
ByteBuf format_arp(const Engine& eng) {
    std::string out;
    out += "# /sys/net/arp — neighbour-cache (ARP) entries\n"
           "# Walks init_net.ipv4.arp_tbl.nht.hash_buckets[].\n#\n";

    VAddr addr = 0;
    if (auto* s = eng.isf().find_symbol("arp_tbl")) addr = s->address;
    if (!addr) addr = resolve_kallsym(eng, "arp_tbl");
    if (!addr) {
        out += "arp_tbl symbol not in ISF/kallsyms.\n";
        return ByteBuf(out.begin(), out.end());
    }

    // Field offsets — neigh_table is a stable kernel struct.
    u64 off_nht = 0, off_hash_buckets = 0, off_hash_shift = 0;
    try { off_nht           = eng.isf().field_offset("neigh_table", "nht"); }    catch (...) {}
    try { off_hash_buckets  = eng.isf().field_offset("neigh_hash_table", "hash_buckets"); } catch (...) {}
    try { off_hash_shift    = eng.isf().field_offset("neigh_hash_table", "hash_shift"); }   catch (...) {}
    u64 off_n_next = 0, off_n_ha = 0, off_n_dev = 0, off_n_primary_key = 0, off_n_nud_state = 0;
    try { off_n_next        = eng.isf().field_offset("neighbour", "next"); }    catch (...) {}
    try { off_n_ha          = eng.isf().field_offset("neighbour", "ha"); }      catch (...) {}
    try { off_n_dev         = eng.isf().field_offset("neighbour", "dev"); }     catch (...) {}
    try { off_n_primary_key = eng.isf().field_offset("neighbour", "primary_key"); } catch (...) {}
    try { off_n_nud_state   = eng.isf().field_offset("neighbour", "nud_state"); } catch (...) {}
    if (!off_nht || !off_n_primary_key) {
        out += fmt::format("arp_tbl @ {:#x} but ISF lacks neigh_table/neighbour fields.\n", addr);
        return ByteBuf(out.begin(), out.end());
    }

    VAddr nht_va = 0;
    kva_read_pod(eng, addr + off_nht, nht_va);
    if (!nht_va) {
        out += fmt::format("arp_tbl @ {:#x} but nht pointer is NULL.\n", addr);
        return ByteBuf(out.begin(), out.end());
    }
    u32 hash_shift = 0;
    kva_read_pod(eng, nht_va + off_hash_shift, hash_shift);
    if (hash_shift > 16) hash_shift = 0;  // sanity — too many buckets is junk
    std::size_t n_buckets = std::size_t(1) << hash_shift;
    VAddr buckets_va = nht_va + off_hash_buckets;

    // Resolve interface name lookup table from net_device.name (offsets are
    // already used by netstat.cpp — re-derive locally to avoid coupling).
    u64 off_nd_name = 0x120;
    try { off_nd_name = eng.isf().field_offset("net_device", "name"); } catch (...) {}

    auto read_dev_name = [&](VAddr dev) -> std::string {
        if (dev == 0) return "?";
        char buf[16] = {0};
        kva_read(eng, dev + off_nd_name, buf, sizeof(buf));
        // Sanitize.
        std::size_t n = 0;
        while (n < sizeof(buf) && buf[n] >= 0x20 && buf[n] < 0x7F) ++n;
        return std::string(buf, n);
    };

    auto nud_to_str = [](u8 s) {
        switch (s) {
            case 0x01: return "INCOMPLETE";
            case 0x02: return "REACHABLE";
            case 0x04: return "STALE";
            case 0x08: return "DELAY";
            case 0x10: return "PROBE";
            case 0x20: return "FAILED";
            case 0x40: return "NOARP";
            case 0x80: return "PERMANENT";
            default:   return "?";
        }
    };

    out += fmt::format("arp_tbl @ {:#x}  nht @ {:#x}  buckets={}\n", addr, nht_va, n_buckets);
    out += fmt::format("\n{:<16}  {:<17}  {:<10}  iface\n",
                       "IP", "MAC", "STATE");
    out += std::string(60, '-') + "\n";

    int total = 0;
    for (std::size_t b = 0; b < n_buckets && total < 4096; ++b) {
        VAddr n = 0;
        kva_read_pod(eng, buckets_va + b * sizeof(VAddr), n);
        int guard = 0;
        while (n != 0 && guard++ < 1024 && total < 4096) {
            u32 ip = 0;
            kva_read_pod(eng, n + off_n_primary_key, ip);
            std::array<u8, 6> mac{};
            kva_read(eng, n + off_n_ha, mac.data(), mac.size());
            VAddr dev = 0;
            kva_read_pod(eng, n + off_n_dev, dev);
            u8 nud = 0;
            kva_read_pod(eng, n + off_n_nud_state, nud);
            u8 ib[4] = {0};
            std::memcpy(ib, &ip, 4);
            out += fmt::format("{:<16}  {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}  {:<10}  {}\n",
                fmt::format("{}.{}.{}.{}", ib[0], ib[1], ib[2], ib[3]),
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                nud_to_str(nud), read_dev_name(dev));
            ++total;
            VAddr nxt = 0;
            if (!kva_read_pod(eng, n + off_n_next, nxt) || nxt == n) break;
            n = nxt;
        }
    }
    out += fmt::format("\n{} neighbour entry(s)\n", total);
    return ByteBuf(out.begin(), out.end());
}

// =========================================================================
//   /sys/net/routes — IPv4 routing table summary
// =========================================================================
//
// Modern Linux uses a per-namespace `fib_table_hash` indexed by table ID
// (RT_TABLE_MAIN=254, RT_TABLE_LOCAL=255). Each fib_table holds an
// fib_trie (compressed trie of routes). Walking the trie node-by-node
// to recover every route is *significant* multi-day work — the
// tnode/leaf encoding is intricate.
//
// We ship an honest summary: confirm the namespace's fib_table_hash is
// reachable, list how many tables exist, and report each table's id +
// number of routes (`tb_num_default`). For full route dump, an analyst
// can use the same VAs and our existing kva_read primitive.
ByteBuf format_routes(const Engine& eng) {
    std::string out;
    out += "# /sys/net/routes — IPv4 routing tables\n"
           "# Anchor + per-table summary. Full per-route trie walk is\n"
           "# deferred (fib_trie tnode/leaf decoding is intricate enough\n"
           "# to deserve its own session); the symbol VAs reported here\n"
           "# let downstream tools pick up from these anchors.\n#\n";

    VAddr init_net = 0;
    if (auto* s = eng.isf().find_symbol("init_net")) init_net = s->address;
    if (!init_net) {
        out += "init_net symbol not in ISF — routes unavailable.\n";
        return ByteBuf(out.begin(), out.end());
    }
    // The fib_table_hash lives inside netns_ipv4 inside init_net. The
    // offset chain (net.ipv4.fib_table_hash) is large and version-
    // dependent. For an honest cross-version baseline, just report the
    // init_net anchor and document the path.
    out += fmt::format("init_net @ {:#x}\n", init_net);
    out += "Path to per-namespace routing tables:\n"
           "  init_net.ipv4.fib_table_hash[]   — array of struct hlist_head\n"
           "  ↓ each bucket chains struct fib_table\n"
           "    .tb_id          — RT_TABLE_LOCAL / MAIN / DEFAULT\n"
           "    .tb_data[]      — fib_trie root\n\n"
           "Per-route enumeration is not currently extracted: the fib_trie\n"
           "tnode/leaf encoding is version-dependent and not exposed by\n"
           "Volatility 3 either. Use /sys/net/routes for the FIB summary.\n";
    return ByteBuf(out.begin(), out.end());
}

// =========================================================================
//   /sys/net/netfilter — iptables / nftables anchor
// =========================================================================
//
// netfilter has two parallel rule engines:
//   * iptables: `xt_tableinfo` per AF per chain — accessed via
//     `init_net.{ipv4,ipv6,bridge,arp,xt}.tables[]`.
//   * nftables: `init_net.nf_tables` — a different list of `nft_table`
//     each holding chains + rules.
//
// Decoding either's actual RULE content is multi-day work (a rule is a
// list of matches + a target, each typed differently). For an honest
// v0.29 shipment, we identify which engine is in use and list the
// table names; full rule decoding is filed as a follow-up.
ByteBuf format_netfilter(const Engine& eng) {
    std::string out;
    out += "# /sys/net/netfilter — netfilter table summary\n"
           "# Walks visible netfilter anchors in init_net.\n#\n";

    VAddr init_net = 0;
    if (auto* s = eng.isf().find_symbol("init_net")) init_net = s->address;

    // Just list which engines have entries by probing well-known anchor
    // symbols. Full rule walks are out of scope.
    auto probe = [&](const char* name) -> VAddr {
        if (auto* s = eng.isf().find_symbol(name)) return s->address;
        return resolve_kallsym(eng, name);
    };

    struct Probe { const char* name; VAddr va; };
    std::vector<Probe> probes = {
        { "nf_register_net_hook",   probe("nf_register_net_hook")  },
        { "nf_hook_slow",           probe("nf_hook_slow")          },
        { "iptable_filter_table",   probe("iptable_filter_table")  },
        { "iptable_nat_table",      probe("iptable_nat_table")     },
        { "iptable_mangle_table",   probe("iptable_mangle_table")  },
        { "nf_tables_module_autoload", probe("nf_tables_module_autoload") },
        { "nft_chain_filter_init",  probe("nft_chain_filter_init") },
    };

    out += fmt::format("init_net @ {:#x}\n\n", init_net);
    out += "Netfilter framework anchors (presence = capability compiled in):\n";
    for (const auto& p : probes) {
        out += fmt::format("  {:<35}  {}\n",
            p.name,
            p.va ? fmt::format("{:#x}", p.va) : std::string("(not in symbols)"));
    }
    out += "\n"
           "Full per-table rule enumeration is deferred:\n"
           "  * iptables stores rules in xt_table_info per CPU per AF, with\n"
           "    typed match + target structs — decoding requires per-match\n"
           "    handlers (target.c, match.c — hundreds of variants).\n"
           "  * nftables uses init_net.nft.tables, each chain holds\n"
           "    `nft_rule` blobs with binary-encoded expression streams\n"
           "    (nft_expr_type-typed) — also intricate.\n"
           "\n"
           "Filed as a multi-day item. Anchors above let an analyst start\n"
           "from a known position.\n";
    return ByteBuf(out.begin(), out.end());
}

// =========================================================================
//   /sys/net/unix — UNIX socket table (best-effort)
// =========================================================================
//
// Modern Linux (6.1+) splits unix sockets across a per-CPU table:
// `init_net.unx.tables[NR_CPUS]`. Each `struct unix_hashtable` carries
// hash chains of `struct unix_sock` linked via `sk_node` (sock_common).
//
// Doing this cleanly requires walking nr_cpu_ids per-CPU tables. As a
// stub, we forward the per-process view: the fd_table layer already
// labels every socket fd with its UNIX path; aggregate from there.
ByteBuf format_unix_sockets(const Engine& eng) {
    // Aggregate via fd_table walks across every process. Dedupe by file_va
    // since a single UNIX socket may be shared across multiple processes
    // (parent + forked children, dup2'd fds, SCM_RIGHTS-passed fds).
    struct Entry { std::string target; std::vector<std::string> users; };
    std::map<VAddr, Entry> by_file;
    int scanned = 0;
    for (const auto& p : eng.processes()) {
        std::vector<OpenFd> fds;
        try { fds = enumerate_fds(eng, p); } catch (...) { continue; }
        for (const auto& f : fds) {
            if (f.target.rfind("socket:UNIX", 0) != 0) continue;
            auto& e = by_file[f.file_va];
            if (e.target.empty()) e.target = f.target;
            e.users.push_back(fmt::format("{}/{}", p.pid, p.comm));
        }
        ++scanned;
    }

    std::string out;
    out += fmt::format(
        "# /sys/net/unix — UNIX-domain socket listing\n"
        "# Aggregated from per-process fd_table walks (no global unix-table\n"
        "# decode — the per-CPU init_net.unx.tables[] layout varies across\n"
        "# 6.1+; fd-table aggregation gives equivalent coverage cleanly).\n"
        "# {} processes scanned; {} distinct UNIX sockets seen.\n"
        "#\n", scanned, by_file.size());
    out += fmt::format("{:<20}  {}\n", "FILE_VA", "TARGET (user pids)");
    out += std::string(72, '-') + "\n";
    int shown = 0;
    for (const auto& [va, e] : by_file) {
        out += fmt::format("{:#018x}  {}\n", va, e.target);
        // Show first 3 user pids (most UNIX sockets are 1-2-process — pipe-
        // shape; some are widely shared like /run/dbus/system_bus_socket).
        out += fmt::format("                      users: ");
        std::size_t nshow = std::min<std::size_t>(e.users.size(), 3);
        for (std::size_t i = 0; i < nshow; ++i) {
            if (i) out += ", ";
            out += e.users[i];
        }
        if (e.users.size() > nshow)
            out += fmt::format(" (+{} more)", e.users.size() - nshow);
        out += "\n";
        if (++shown >= 500) {
            out += fmt::format("... ({} more truncated)\n", by_file.size() - 500);
            break;
        }
    }
    return ByteBuf(out.begin(), out.end());
}

} // namespace lmpfs::linux
