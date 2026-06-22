// netstat.cpp — see header for layout notes.
#include "os/linux/netstat.h"
#include "os/linux/kva_reader.h"
#include "app/engine.h"
#include "symbols/isf_symbols.h"
#include "core/log.h"
#include <fmt/format.h>
#include <algorithm>
#include <cstring>

namespace lmpfs::linux {

namespace {

// Offsets cache, resolved once per call site. Failures → ok=false.
struct Off {
    // sock_common (= first 0x88 bytes of struct sock)
    u64 skc_daddr     = 0x00;
    u64 skc_rcv_saddr = 0x04;
    u64 skc_dport     = 0x0c;
    u64 skc_num       = 0x0e;
    u64 skc_family    = 0x10;
    u64 skc_state     = 0x12;
    u64 skc_net       = 0x30;
    u64 skc_v6_daddr  = 0x38;
    u64 skc_v6_rcv    = 0x48;
    u64 skc_nulls     = 0x68;     // skc_nulls_node
    // sock
    u64 sk_protocol   = 0x23e;
    // inet_hashinfo
    u64 ih_ehash      = 0x00;
    u64 ih_ehash_mask = 0x10;
    u64 ih_lhash2     = 0x40;
    u64 ih_lhash2_mask= 0x3c;
    // udp_table
    u64 ut_hash       = 0x00;
    u64 ut_mask       = 0x18;
    // udp_hslot / inet_ehash_bucket / inet_listen_hashbucket — head at fixed offset
    u64 ehash_chain   = 0x00;     // inet_ehash_bucket.chain
    u64 listen_nulls  = 0x08;     // inet_listen_hashbucket.nulls_head
    u64 udp_hslot_head= 0x00;     // udp_hslot.head/nulls_head
    // net_device
    u64 nd_name       = 0x120;
    u64 nd_ifindex    = 0xe0;
    u64 nd_flags      = 0xb0;
    u64 nd_mtu        = 0x38;
    u64 nd_dev_list   = 0x158;
    u64 nd_ip_ptr     = 0x3d0;
    u64 nd_ip6_ptr    = 0x3d8;     // net_device.ip6_ptr (struct inet6_dev*)
    u64 nd_addr_len   = 0x340;
    u64 nd_dev_addr   = 0x428;
    // in_device → in_ifaddr
    u64 in_dev_ifa_list = 0x10;
    u64 ifa_next      = 0x10;
    u64 ifa_local     = 0x30;
    u64 ifa_prefixlen = 0x45;
    u64 ifa_label     = 0x4c;
    // inet6_dev → inet6_ifaddr (v0.28)
    u64 inet6_dev_addr_list   = 0x00;   // struct list_head at offset 0
    u64 inet6_ifaddr_addr     = 0x00;   // struct in6_addr first
    u64 inet6_ifaddr_prefixlen= 0x14;
    u64 inet6_ifaddr_if_list  = 0x60;   // links via list_head
    // net (network namespace)
    u64 net_dev_base  = 0x90;
    bool ok = true;
};

Off resolve_off(const IsfSymbols& isf) {
    Off o{};
    auto tryf = [&](u64& dst, const char* t, const char* f) {
        try { dst = isf.field_offset(t, f); }
        catch (...) { /* keep default */ }
    };
    tryf(o.skc_daddr,     "sock_common", "skc_daddr");
    tryf(o.skc_rcv_saddr, "sock_common", "skc_rcv_saddr");
    tryf(o.skc_dport,     "sock_common", "skc_dport");
    tryf(o.skc_num,       "sock_common", "skc_num");
    tryf(o.skc_family,    "sock_common", "skc_family");
    tryf(o.skc_state,     "sock_common", "skc_state");
    tryf(o.skc_net,       "sock_common", "skc_net");
    tryf(o.skc_v6_daddr,  "sock_common", "skc_v6_daddr");
    tryf(o.skc_v6_rcv,    "sock_common", "skc_v6_rcv_saddr");
    tryf(o.skc_nulls,     "sock_common", "skc_nulls_node");
    tryf(o.sk_protocol,   "sock",        "sk_protocol");

    tryf(o.ih_ehash,      "inet_hashinfo", "ehash");
    tryf(o.ih_ehash_mask, "inet_hashinfo", "ehash_mask");
    tryf(o.ih_lhash2,     "inet_hashinfo", "lhash2");
    tryf(o.ih_lhash2_mask,"inet_hashinfo", "lhash2_mask");

    tryf(o.ut_hash,       "udp_table",   "hash");
    tryf(o.ut_mask,       "udp_table",   "mask");

    tryf(o.ehash_chain,   "inet_ehash_bucket",      "chain");
    tryf(o.listen_nulls,  "inet_listen_hashbucket", "nulls_head");
    tryf(o.udp_hslot_head,"udp_hslot",              "head");

    tryf(o.nd_name,       "net_device", "name");
    tryf(o.nd_ifindex,    "net_device", "ifindex");
    tryf(o.nd_flags,      "net_device", "flags");
    tryf(o.nd_mtu,        "net_device", "mtu");
    tryf(o.nd_dev_list,   "net_device", "dev_list");
    tryf(o.nd_ip_ptr,     "net_device", "ip_ptr");
    tryf(o.nd_ip6_ptr,    "net_device", "ip6_ptr");
    tryf(o.nd_addr_len,   "net_device", "addr_len");
    tryf(o.nd_dev_addr,   "net_device", "dev_addr");
    tryf(o.in_dev_ifa_list, "in_device", "ifa_list");
    tryf(o.ifa_next,      "in_ifaddr",  "ifa_next");
    tryf(o.ifa_local,     "in_ifaddr",  "ifa_local");
    tryf(o.ifa_prefixlen, "in_ifaddr",  "ifa_prefixlen");
    tryf(o.ifa_label,     "in_ifaddr",  "ifa_label");
    tryf(o.inet6_dev_addr_list,   "inet6_dev",    "addr_list");
    tryf(o.inet6_ifaddr_addr,     "inet6_ifaddr", "addr");
    tryf(o.inet6_ifaddr_prefixlen,"inet6_ifaddr", "prefix_len");
    tryf(o.inet6_ifaddr_if_list,  "inet6_ifaddr", "if_list");

    tryf(o.net_dev_base,  "net",        "dev_base_head");
    return o;
}

// hlist_nulls terminator: the kernel uses values with bit 0 set to mark the
// end of a nulls-list. Valid sock pointers are at least 8-byte aligned, so
// `(p & 1) != 0` reliably detects the terminator.
inline bool is_nulls_end(VAddr p) { return (p & 1) != 0; }

// Network-byte-order helpers (kernel stores be16/be32 in BE).
inline u16 be16(u16 x) { return (u16)((x >> 8) | (x << 8)); }

void parse_sock(const Engine& eng, const Off& o, VAddr sock_va,
                SocketInfo::Proto proto,
                std::vector<SocketInfo>& out)
{
    if (sock_va == 0) return;
    SocketInfo s{};
    s.sock_va = sock_va;
    s.proto   = proto;

    // sock_common fields
    u32 daddr = 0, saddr = 0;
    u16 dport_be = 0, sport_host = 0;
    u8  state = 0;
    u16 family = 0;
    kva_read_pod(eng, sock_va + o.skc_daddr,     daddr);
    kva_read_pod(eng, sock_va + o.skc_rcv_saddr, saddr);
    kva_read_pod(eng, sock_va + o.skc_dport,     dport_be);
    kva_read_pod(eng, sock_va + o.skc_num,       sport_host);
    kva_read_pod(eng, sock_va + o.skc_family,    family);
    kva_read_pod(eng, sock_va + o.skc_state,     state);

    s.family      = family;
    s.state       = state;
    s.local_port  = sport_host;                  // already host order
    s.remote_port = be16(dport_be);

    // IPv4: top 4 bytes of the 16-byte slot
    std::memcpy(s.local_addr.data(),  &saddr, 4);
    std::memcpy(s.remote_addr.data(), &daddr, 4);

    if (family == SocketInfo::AF_INET6) {
        // Overwrite with IPv6 contents (overlap with IPv4 IS valid — same field)
        kva_read(eng, sock_va + o.skc_v6_rcv,   s.local_addr.data(),  16);
        kva_read(eng, sock_va + o.skc_v6_daddr, s.remote_addr.data(), 16);
    }
    out.push_back(s);
}

// Walk an hlist_nulls chain starting at `head_va` (a hlist_nulls_head, i.e.
// 8 bytes pointing at the first node). For each node found, container_of
// via the offset of skc_nulls_node within sock to yield a sock pointer.
void walk_nulls_chain(const Engine& eng, const Off& o,
                      VAddr head_va, SocketInfo::Proto proto,
                      std::vector<SocketInfo>& out, std::size_t hard_cap)
{
    VAddr node = 0;
    if (!kva_read_pod(eng, head_va, node)) return;
    int guard = 0;
    while (!is_nulls_end(node) && node != 0 &&
           guard++ < 100'000 && out.size() < hard_cap)
    {
        VAddr sock_va = node - o.skc_nulls;
        parse_sock(eng, o, sock_va, proto, out);
        VAddr nxt = 0;
        if (!kva_read_pod(eng, node, nxt) || nxt == node) break;
        node = nxt;
    }
}

void walk_hlist_chain(const Engine& eng, const Off& o,
                      VAddr head_va, SocketInfo::Proto proto,
                      std::vector<SocketInfo>& out, std::size_t hard_cap)
{
    // Same as walk_nulls_chain but terminator is NULL, not bit-0 marker.
    VAddr node = 0;
    if (!kva_read_pod(eng, head_va, node)) return;
    int guard = 0;
    while (node != 0 && guard++ < 100'000 && out.size() < hard_cap) {
        VAddr sock_va = node - o.skc_nulls;
        parse_sock(eng, o, sock_va, proto, out);
        VAddr nxt = 0;
        if (!kva_read_pod(eng, node, nxt) || nxt == node) break;
        node = nxt;
    }
}

} // anonymous

// ---------------- TCP ----------------

std::vector<SocketInfo> enumerate_tcp_sockets(const Engine& eng) {
    std::vector<SocketInfo> out;
    const auto& isf = eng.isf();
    auto* sym = isf.find_symbol("tcp_hashinfo");
    if (!sym) {
        log::warn("netstat: ISF lacks tcp_hashinfo");
        return out;
    }
    Off o = resolve_off(isf);

    // Read hashinfo header.
    VAddr hi = sym->address;
    VAddr ehash = 0, lhash2 = 0;
    u32   ehash_mask = 0, lhash2_mask = 0;
    kva_read_pod(eng, hi + o.ih_ehash,       ehash);
    kva_read_pod(eng, hi + o.ih_ehash_mask,  ehash_mask);
    kva_read_pod(eng, hi + o.ih_lhash2,      lhash2);
    kva_read_pod(eng, hi + o.ih_lhash2_mask, lhash2_mask);

    log::info("tcp_hashinfo: ehash={:#x} mask={:#x} lhash2={:#x} mask={:#x}",
              ehash, ehash_mask, lhash2, lhash2_mask);
    constexpr std::size_t kMax = 200'000;

    // Established hash table (most TCP sockets live here).
    if (ehash != 0 && ehash_mask < 0x10000000) {
        const std::size_t buckets = std::size_t(ehash_mask) + 1;
        // Each bucket is inet_ehash_bucket (8 bytes — just chain pointer)
        for (std::size_t i = 0; i < buckets && out.size() < kMax; ++i) {
            VAddr bucket_va = ehash + i * 8;
            walk_nulls_chain(eng, o, bucket_va + o.ehash_chain,
                             SocketInfo::P_TCP, out, kMax);
        }
    }

    // Listener hash table (TCP_LISTEN sockets).
    if (lhash2 != 0 && lhash2_mask < 0x100000) {
        const std::size_t buckets = std::size_t(lhash2_mask) + 1;
        // Each bucket is inet_listen_hashbucket (16 bytes — lock @0, nulls @8)
        for (std::size_t i = 0; i < buckets && out.size() < kMax; ++i) {
            VAddr bucket_va = lhash2 + i * 16;
            walk_nulls_chain(eng, o, bucket_va + o.listen_nulls,
                             SocketInfo::P_TCP, out, kMax);
        }
    }
    log::info("netstat: enumerated {} TCP sockets", out.size());
    return out;
}

// ---------------- UDP ----------------

std::vector<SocketInfo> enumerate_udp_sockets(const Engine& eng) {
    std::vector<SocketInfo> out;
    const auto& isf = eng.isf();
    auto* sym = isf.find_symbol("udp_table");
    if (!sym) {
        log::warn("netstat: ISF lacks udp_table");
        return out;
    }
    Off o = resolve_off(isf);
    VAddr ut = sym->address;
    VAddr hash = 0;
    u32   mask = 0;
    kva_read_pod(eng, ut + o.ut_hash, hash);
    kva_read_pod(eng, ut + o.ut_mask, mask);
    log::info("udp_table: hash={:#x} mask={:#x}", hash, mask);

    constexpr std::size_t kMax = 100'000;
    if (hash != 0 && mask < 0x100000) {
        const std::size_t buckets = std::size_t(mask) + 1;
        // udp_hslot is 16 bytes (head @0, count @8, lock @c).
        for (std::size_t i = 0; i < buckets && out.size() < kMax; ++i) {
            VAddr bucket_va = hash + i * 16;
            // UDP buckets are hlist (NULL-terminated), not hlist_nulls —
            // but on modern kernels (≥ 4.x) they're nulls. Be safe and
            // also handle NULL terminator.
            walk_nulls_chain(eng, o, bucket_va + o.udp_hslot_head,
                             SocketInfo::P_UDP, out, kMax);
        }
    }
    log::info("netstat: enumerated {} UDP sockets", out.size());
    return out;
}

std::vector<SocketInfo> enumerate_all_sockets(const Engine& eng) {
    auto t = enumerate_tcp_sockets(eng);
    auto u = enumerate_udp_sockets(eng);
    // Listeners first within TCP, then established, then UDP.
    std::stable_sort(t.begin(), t.end(), [](const SocketInfo& a, const SocketInfo& b) {
        if (a.state == SocketInfo::S_LISTEN && b.state != SocketInfo::S_LISTEN)
            return true;
        if (b.state == SocketInfo::S_LISTEN && a.state != SocketInfo::S_LISTEN)
            return false;
        return false;
    });
    t.insert(t.end(), u.begin(), u.end());
    return t;
}

SocketIndex build_socket_index(const Engine& eng) {
    return SocketIndex{ enumerate_all_sockets(eng) };
}
const SocketInfo* find_socket_by_va(const SocketIndex& idx, VAddr sock_va) {
    for (const auto& s : idx.all) if (s.sock_va == sock_va) return &s;
    return nullptr;
}

// ---------------- Formatting ----------------

namespace {

const char* tcp_state_name(u32 s) {
    static const char* names[] = {
        "UNKNOWN", "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1",
        "FIN_WAIT2", "TIME_WAIT", "CLOSE", "CLOSE_WAIT", "LAST_ACK",
        "LISTEN", "CLOSING", "NEW_SYN_RECV"
    };
    return s < std::size(names) ? names[s] : "?";
}

std::string ipv4_str(const std::array<u8,16>& a) {
    return fmt::format("{}.{}.{}.{}", a[0], a[1], a[2], a[3]);
}
std::string ipv6_str(const std::array<u8,16>& a) {
    // Naive — full :: collapsing would be nicer but this is parseable
    return fmt::format(
        "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:"
        "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
        a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7],
        a[8],a[9],a[10],a[11],a[12],a[13],a[14],a[15]);
}
std::string fmt_addr(const SocketInfo& s, const std::array<u8,16>& a, u16 port) {
    if (s.family == SocketInfo::AF_INET6)
        return fmt::format("[{}]:{}", ipv6_str(a), port);
    return fmt::format("{}:{}", ipv4_str(a), port);
}

ByteBuf format_one(const std::vector<SocketInfo>& s,
                   const char* header, SocketInfo::Proto only)
{
    std::string out;
    out.reserve(8 * 1024);
    std::size_t n = 0;
    for (const auto& x : s) if (x.proto == only) ++n;
    out += fmt::format("# {} {} sockets\n", n, header);
    out += "# state         local                              "
           "remote                             family  sock_va\n";
    out += "#-------------+----------------------------------+"
           "----------------------------------+-------+----------\n";
    for (const auto& x : s) {
        if (x.proto != only) continue;
        out += fmt::format("  {:<13}  {:<33}  {:<33}  {:<6}  {:#x}\n",
                           tcp_state_name(x.state),
                           fmt_addr(x, x.local_addr, x.local_port),
                           fmt_addr(x, x.remote_addr, x.remote_port),
                           x.family == SocketInfo::AF_INET6 ? "INET6" :
                           x.family == SocketInfo::AF_INET4 ? "INET"  :
                           x.family == SocketInfo::AF_UNIX_FAM ? "UNIX" : "?",
                           x.sock_va);
    }
    return ByteBuf(out.begin(), out.end());
}

} // anonymous

ByteBuf format_proc_net_tcp(const Engine& eng) {
    return format_one(enumerate_tcp_sockets(eng), "TCP", SocketInfo::P_TCP);
}
ByteBuf format_proc_net_udp(const Engine& eng) {
    return format_one(enumerate_udp_sockets(eng), "UDP", SocketInfo::P_UDP);
}
ByteBuf format_netstat_summary(const Engine& eng) {
    auto all = enumerate_all_sockets(eng);
    std::size_t tcp_l = 0, tcp_e = 0, udp = 0;
    for (const auto& s : all) {
        if (s.proto == SocketInfo::P_UDP) ++udp;
        else if (s.state == SocketInfo::S_LISTEN) ++tcp_l;
        else ++tcp_e;
    }
    std::string out;
    out.reserve(16 * 1024);
    out += fmt::format("# Network state summary\n"
                       "# {} TCP listeners, {} TCP non-listeners, {} UDP\n#\n",
                       tcp_l, tcp_e, udp);
    out += "# proto state         local                              "
           "remote                             family\n";
    out += "#-----+-------------+----------------------------------+"
           "----------------------------------+-------\n";
    for (const auto& x : all) {
        const char* proto = (x.proto == SocketInfo::P_UDP) ? "UDP" : "TCP";
        out += fmt::format("  {:<5} {:<13}  {:<33}  {:<33}  {}\n",
                           proto, tcp_state_name(x.state),
                           fmt_addr(x, x.local_addr, x.local_port),
                           fmt_addr(x, x.remote_addr, x.remote_port),
                           x.family == SocketInfo::AF_INET6 ? "INET6" :
                           x.family == SocketInfo::AF_INET4 ? "INET" : "?");
    }
    return ByteBuf(out.begin(), out.end());
}

// ---------------- Interfaces ----------------

std::vector<NetInterface> enumerate_interfaces(const Engine& eng) {
    std::vector<NetInterface> out;
    const auto& isf = eng.isf();
    auto* sym = isf.find_symbol("init_net");
    if (!sym) { log::warn("netstat: ISF lacks init_net"); return out; }
    Off o = resolve_off(isf);

    VAddr head_va = sym->address + o.net_dev_base;
    VAddr cur = 0;
    if (!kva_read_pod(eng, head_va, cur)) return out;
    int guard = 0;
    while (cur != 0 && cur != head_va && guard++ < 1024) {
        VAddr dev = cur - o.nd_dev_list;
        NetInterface nf{};
        nf.dev_va = dev;
        kva_read_pod(eng, dev + o.nd_ifindex, nf.ifindex);
        kva_read_pod(eng, dev + o.nd_flags,   nf.flags);
        kva_read_pod(eng, dev + o.nd_mtu,     nf.mtu);
        std::string name(16, 0);
        kva_read(eng, dev + o.nd_name, name.data(), 16);
        std::size_t n = 0;
        while (n < name.size() && name[n] >= 0x20 && name[n] < 0x7F) ++n;
        nf.name.assign(name.data(), n);

        // Sanity: skip entries with implausible ifindex/mtu — we've walked
        // off the end of the dev_base_head list into uninitialised memory.
        if (nf.ifindex <= 0 || nf.ifindex > 100000 ||
            nf.mtu > (1u << 24) || nf.name.empty()) {
            VAddr nxt2 = 0;
            if (!kva_read_pod(eng, cur, nxt2) || nxt2 == cur) break;
            cur = nxt2;
            continue;
        }

        // IPv4 addresses: walk net_device.ip_ptr → in_device.ifa_list →
        // in_ifaddr.ifa_next.
        VAddr in_dev = 0;
        if (kva_read_pod(eng, dev + o.nd_ip_ptr, in_dev) && in_dev != 0) {
            VAddr ifa = 0;
            kva_read_pod(eng, in_dev + o.in_dev_ifa_list, ifa);
            int ifa_guard = 0;
            while (ifa != 0 && ifa_guard++ < 64) {
                u32 ipv4 = 0;
                u8  plen = 0;
                kva_read_pod(eng, ifa + o.ifa_local,     ipv4);
                kva_read_pod(eng, ifa + o.ifa_prefixlen, plen);
                if (ipv4 != 0) {
                    u8* b = reinterpret_cast<u8*>(&ipv4);
                    nf.ipv4_addrs.push_back(
                        fmt::format("{}.{}.{}.{}/{}", b[0], b[1], b[2], b[3], plen));
                }
                VAddr nxt_ifa = 0;
                if (!kva_read_pod(eng, ifa + o.ifa_next, nxt_ifa) ||
                    nxt_ifa == ifa) break;
                ifa = nxt_ifa;
            }
        }

        // IPv6 addresses (v0.28): walk net_device.ip6_ptr → inet6_dev.addr_list
        // (list_head; each entry's `if_list` links it; container_of for
        // inet6_ifaddr → read .addr / .prefix_len).
        VAddr in6 = 0;
        if (kva_read_pod(eng, dev + o.nd_ip6_ptr, in6) && in6 != 0) {
            VAddr head_va = in6 + o.inet6_dev_addr_list;
            VAddr node    = 0;
            kva_read_pod(eng, head_va, node);
            int g = 0;
            while (node != 0 && node != head_va && g++ < 64) {
                VAddr ifa6_va = node - o.inet6_ifaddr_if_list;
                std::array<u8, 16> v6{};
                u8  plen6 = 0;
                kva_read(eng, ifa6_va + o.inet6_ifaddr_addr,     v6.data(), v6.size());
                kva_read_pod(eng, ifa6_va + o.inet6_ifaddr_prefixlen, plen6);
                nf.ipv6_addrs.push_back(fmt::format(
                    "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:"
                    "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}/{}",
                    v6[0],v6[1],v6[2],v6[3],v6[4],v6[5],v6[6],v6[7],
                    v6[8],v6[9],v6[10],v6[11],v6[12],v6[13],v6[14],v6[15],
                    plen6));
                VAddr nxt = 0;
                if (!kva_read_pod(eng, node, nxt) || nxt == node) break;
                node = nxt;
            }
        }
        out.push_back(std::move(nf));

        VAddr nxt = 0;
        if (!kva_read_pod(eng, cur, nxt) || nxt == cur) break;
        cur = nxt;
    }
    log::info("netstat: {} network interface(s)", out.size());
    return out;
}

ByteBuf format_listening(const Engine& eng) {
    auto socks = enumerate_all_sockets(eng);
    // Filter: TCP LISTEN, plus UDP entries that have a local port and no
    // remote (canonical UDP "listener" — bound, never connected).
    std::vector<const SocketInfo*> listeners;
    for (const auto& s : socks) {
        if (s.proto == SocketInfo::P_TCP && s.state == SocketInfo::S_LISTEN) {
            listeners.push_back(&s);
        } else if (s.proto == SocketInfo::P_UDP && s.local_port != 0 &&
                    s.remote_port == 0) {
            listeners.push_back(&s);
        }
    }
    std::string out;
    out.reserve(4 * 1024);
    out += fmt::format(
        "# /sys/net/listening — bound + listening sockets\n"
        "# {} TCP LISTEN sockets + {} UDP-bound sockets.\n"
        "# Cross-process attribution (PID/COMM) requires walking every\n"
        "# task's fd_table, which is expensive — for now we emit the\n"
        "# raw socket data + ino; correlate via /proc/<pid>/fd_table.txt.\n"
        "#\n"
        "# proto  family  local                          ino          sock_va\n"
        "# -----+-------+------------------------------+------------+---------\n",
        std::count_if(listeners.begin(), listeners.end(),
                       [](const SocketInfo* s) { return s->proto == SocketInfo::P_TCP; }),
        std::count_if(listeners.begin(), listeners.end(),
                       [](const SocketInfo* s) { return s->proto == SocketInfo::P_UDP; }));
    if (listeners.empty()) {
        out += "(no listeners — host is fully passive)\n";
        return ByteBuf(out.begin(), out.end());
    }
    for (const auto* s : listeners) {
        const char* p = s->proto == SocketInfo::P_TCP ? "TCP" : "UDP";
        const char* f = s->family == SocketInfo::AF_INET6 ? "INET6"
                       : s->family == SocketInfo::AF_INET4 ? "INET" : "?";
        out += fmt::format("  {:<4}   {:<5}   {:<30}   {:<10}   {:#x}\n",
                           p, f,
                           fmt_addr(*s, s->local_addr, s->local_port),
                           s->ino,
                           s->sock_va);
    }
    return ByteBuf(out.begin(), out.end());
}

ByteBuf format_interfaces(const Engine& eng) {
    auto ifs = enumerate_interfaces(eng);
    if (ifs.empty()) {
        const char msg[] = "; no interfaces enumerated (init_net unreadable or ISF lacks fields)\n";
        return ByteBuf(msg, msg + sizeof(msg) - 1);
    }
    std::string out;
    out.reserve(2 * 1024);
    out += fmt::format("# {} network interfaces (init namespace)\n", ifs.size());
    for (const auto& f : ifs) {
        // Decode common flags (subset).
        std::string fl;
        if (f.flags & 0x0001) fl += "UP,";
        if (f.flags & 0x0002) fl += "BROADCAST,";
        if (f.flags & 0x0008) fl += "LOOPBACK,";
        if (f.flags & 0x0040) fl += "RUNNING,";
        if (f.flags & 0x1000) fl += "MULTICAST,";
        if (!fl.empty()) fl.pop_back();
        out += fmt::format("\n{:>3}: {} <{}> mtu {}\n",
                           f.ifindex, f.name, fl, f.mtu);
        for (const auto& a : f.ipv4_addrs)
            out += fmt::format("     inet  {}\n", a);
        for (const auto& a : f.ipv6_addrs)
            out += fmt::format("     inet6 {}\n", a);
    }
    return ByteBuf(out.begin(), out.end());
}

} // namespace lmpfs::linux
