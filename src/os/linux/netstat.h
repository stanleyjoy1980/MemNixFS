// netstat.h — Linux network-state enumeration (sockets + interfaces).
//
// This is the missing piece that turns `/proc/<pid>/fd_table.txt`'s
// `socket:[N]` placeholders into actionable forensic data: protocol,
// addresses, ports, state.
//
// Anchor symbols & structures (kernel 6.x):
//
//   tcp_hashinfo  (struct inet_hashinfo)
//     .ehash         struct inet_ehash_bucket *      @0x00
//     .ehash_mask    unsigned int                     @0x10
//     .lhash2        struct inet_listen_hashbucket * @0x40
//     .lhash2_mask   unsigned int                     @0x3c
//
//   udp_table       (struct udp_table)
//     .hash          struct udp_hslot *               @0x00
//     .mask          unsigned int                     @0x18
//
//   inet_ehash_bucket
//     .chain         struct hlist_nulls_head          @0x00  (8 bytes)
//
//   udp_hslot
//     .head/.nulls_head                                @0x00
//
//   sock (offset 0 = sock_common):
//     skc_daddr      __be32                           @0x00
//     skc_rcv_saddr  __be32                           @0x04
//     skc_dport      __be16                           @0x0c
//     skc_num        __u16                            @0x0e   (host order!)
//     skc_family     unsigned short                   @0x10
//     skc_state      unsigned char                    @0x12
//     skc_net        struct net *                     @0x30
//     skc_v6_daddr   in6_addr                         @0x38
//     skc_v6_rcv_saddr in6_addr                       @0x48
//     skc_node       hlist_node                       @0x68
//     skc_nulls_node hlist_nulls_node                 @0x68 (union)
//   sock.sk_protocol                                  @0x23e
//
// hlist_nulls terminator: the chain ends with a value where bit 0 is set.
// (Valid sock pointers are 8-byte aligned, so any odd value is the marker.)
#pragma once
#include "core/types.h"
#include "core/stream.h"
#include <array>
#include <string>
#include <vector>

namespace lmpfs { class Engine; }

namespace lmpfs::linux {

struct SocketInfo {
    enum Family { AF_UNKNOWN = 0, AF_INET4 = 2, AF_INET6 = 10, AF_UNIX_FAM = 1 };
    enum Proto  { P_TCP, P_UDP, P_RAW, P_UNIX };
    enum State {
        S_UNKNOWN     = 0,
        S_ESTABLISHED = 1,
        S_SYN_SENT    = 2,
        S_SYN_RECV    = 3,
        S_FIN_WAIT1   = 4,
        S_FIN_WAIT2   = 5,
        S_TIME_WAIT   = 6,
        S_CLOSE       = 7,
        S_CLOSE_WAIT  = 8,
        S_LAST_ACK    = 9,
        S_LISTEN      = 10,
        S_CLOSING     = 11,
        S_NEW_SYN_RECV= 12,
    };

    VAddr sock_va     = 0;
    Proto proto       = P_TCP;
    u16   family      = AF_UNKNOWN;
    u32   state       = S_UNKNOWN;
    std::array<u8,16> local_addr{};   // first 4 bytes for IPv4
    std::array<u8,16> remote_addr{};
    u16   local_port  = 0;
    u16   remote_port = 0;
    u64   ino         = 0;    // socket inode number
    u32   uid         = 0;
};

// Walk tcp_hashinfo's established + listener hashtables.
std::vector<SocketInfo> enumerate_tcp_sockets(const Engine& eng);

// Walk udp_table's hash[].
std::vector<SocketInfo> enumerate_udp_sockets(const Engine& eng);

// All of the above. Sorted: TCP listeners first, then TCP established,
// then UDP. Same ordering vol3 `linux.sockstat` uses.
std::vector<SocketInfo> enumerate_all_sockets(const Engine& eng);

// Map sock_va → SocketInfo, for cross-linking with fd_table (file→inode→
// socket). Built from the same data as enumerate_all_sockets.
struct SocketIndex {
    std::vector<SocketInfo> all;
};
SocketIndex build_socket_index(const Engine& eng);
const SocketInfo* find_socket_by_va(const SocketIndex& idx, VAddr sock_va);

// /sys/net/tcp — /proc/net/tcp-compatible (parseable by `ss` / `netstat`).
ByteBuf format_proc_net_tcp(const Engine& eng);
ByteBuf format_proc_net_udp(const Engine& eng);

// A nicer human-readable summary across all protocols.
ByteBuf format_netstat_summary(const Engine& eng);

// -------- Interfaces --------

struct NetInterface {
    int         ifindex = 0;
    std::string name;
    u32         flags   = 0;
    u32         mtu     = 0;
    std::vector<std::string> ipv4_addrs;  // "192.168.1.10/24"
    std::vector<std::string> ipv6_addrs;  // "fe80::1/64"
    VAddr       dev_va  = 0;
};

// Walk init_net.dev_base_head — every netdev in the host's namespace.
std::vector<NetInterface> enumerate_interfaces(const Engine& eng);

// /sys/net/interfaces — `ip addr` / `ifconfig` style listing.
ByteBuf format_interfaces(const Engine& eng);

// /sys/net/listening (v0.27) — every socket currently in LISTEN state
// (TCP) or bound + unconnected (UDP "pseudo-listener"). Cross-linked
// with per-process fd_tables when the engine has a socket_index, so
// each row gets a (pid, comm) attribution where possible.
ByteBuf format_listening(const Engine& eng);

} // namespace lmpfs::linux
