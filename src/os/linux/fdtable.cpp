// fdtable.cpp — see header.
//
// Layout of relevant kernel structs (kernel 6.x, x86_64):
//
//   task_struct.files          (struct files_struct *)
//     ↓
//   files_struct
//     .fdt              @0x20  (struct fdtable *)  ← preferred
//     .fdtab            @0x28  (struct fdtable, inline default)
//     .fd_array[]       @0xA0  (struct file *, inline small fds)
//
//   fdtable
//     .max_fds          @0x00  (unsigned int)
//     .fd               @0x08  (struct file ** — array of file*)
//
//   file
//     .f_mode           @0x0C
//     .f_flags          @0x30
//     .f_path           @0x40  (struct path; .mnt @0, .dentry @8)
//     .f_pos            @0x70
//     .f_inode          @0x28  (struct inode *)
//
//   dentry
//     .d_parent         @0x18
//     .d_name           @0x20  (struct qstr; .len @4, .name @8)
//     .d_iname          @0x38  (inline 32-byte name)
//
#include "os/linux/fdtable.h"
#include "app/engine.h"
#include "symbols/isf_symbols.h"
#include "os/linux/kva_reader.h"
#include "os/linux/dentry_path.h"
#include "os/linux/netstat.h"
#include "core/log.h"
#include <fmt/format.h>
#include <cstring>

namespace lmpfs::linux {

namespace {

inline bool kread(const Engine& eng, VAddr va, void* dst, std::size_t n) {
    return kva_read(eng, va, dst, n);
}
template <typename T>
inline bool kread_pod(const Engine& eng, VAddr va, T& out) {
    return kva_read_pod(eng, va, out);
}

// Path resolution moved to dentry_path.{h,cpp} for reuse across fdtable,
// pagecache, mountinfo, etc.

// Format a socket as a one-line summary, ready to drop into the `target`
// column of /proc/<pid>/fd_table.txt. Returns "" if the inode isn't a
// socket or if the socket isn't in our index.
std::string format_socket_for_fd(const Engine& eng, VAddr inode_va,
                                  const SocketIndex& idx)
{
    if (inode_va == 0) return {};
    const auto& isf = eng.isf();

    // Read inode.i_mode and check S_IFMT == S_IFSOCK.
    u64 i_mode_off = 0;
    try { i_mode_off = isf.field_offset("inode", "i_mode"); }
    catch (...) { return {}; }
    u16 i_mode = 0;
    if (!kva_read_pod(eng, inode_va + i_mode_off, i_mode)) return {};
    if ((i_mode & 0170000) != 0140000) return {};  // S_IFSOCK

    // inode is embedded inside socket_alloc at offset 0x80 (= sizeof(struct
    // socket) on x86_64 6.x). socket_alloc.socket is at offset 0.
    u64 sa_vfs_inode_off = 0x80;
    try { sa_vfs_inode_off = isf.field_offset("socket_alloc", "vfs_inode"); }
    catch (...) {}
    VAddr socket_va = inode_va - sa_vfs_inode_off;

    // socket.sk is at offset 0x18.
    u64 sock_off_in_socket = 0x18;
    try { sock_off_in_socket = isf.field_offset("socket", "sk"); }
    catch (...) {}
    VAddr sock_va = 0;
    if (!kva_read_pod(eng, socket_va + sock_off_in_socket, sock_va) ||
        sock_va == 0)
        return fmt::format("socket:[<unread> sk @ {:#x}]", socket_va);

    auto* s = find_socket_by_va(idx, sock_va);
    if (!s) {
        // Not in TCP/UDP index — could be Unix, netlink, packet, raw, etc.
        // Read sock_common.skc_family + sock.sk_protocol directly so we can
        // at least say what KIND of socket this is, even if we can't show
        // an endpoint.
        u64 skc_family_off = 0x10, sk_protocol_off = 0x23e;
        try { skc_family_off  = isf.field_offset("sock_common", "skc_family"); } catch (...) {}
        try { sk_protocol_off = isf.field_offset("sock",        "sk_protocol"); } catch (...) {}
        u16 fam = 0; u16 proto = 0;
        kva_read_pod(eng, sock_va + skc_family_off,  fam);
        kva_read_pod(eng, sock_va + sk_protocol_off, proto);

        const char* fname = "?";
        switch (fam) {
        case  1: fname = "UNIX";    break;
        case  2: fname = "INET";    break;
        case 10: fname = "INET6";   break;
        case 16: fname = "NETLINK"; break;
        case 17: fname = "PACKET";  break;
        case 40: fname = "VSOCK";   break;
        default: break;
        }

        // For AF_UNIX, try to read the bound path from unix_sock.addr.name.
        if (fam == 1) {
            // unix_sock embeds sock at offset 0, so sock_va == unix_sock_va.
            u64 unix_addr_off = 0, unix_addr_name_off = 0;
            try {
                unix_addr_off       = isf.field_offset("unix_sock",  "addr");
                unix_addr_name_off  = isf.field_offset("unix_address", "name");
            } catch (...) {}
            if (unix_addr_off) {
                VAddr addr_p = 0;
                kva_read_pod(eng, sock_va + unix_addr_off, addr_p);
                if (addr_p) {
                    // unix_address.name is an array of sockaddr_un. The
                    // first sockaddr_un.sun_path immediately follows
                    // sun_family (2 bytes). Read up to 108 bytes.
                    char buf[110] = {};
                    if (kva_read(eng, addr_p + unix_addr_name_off + 2,
                                 buf, 108)) {
                        std::string p(buf, strnlen(buf, 108));
                        if (!p.empty())
                            return fmt::format("socket:UNIX path={}", p);
                        // Abstract-namespace sockets (sun_path[0]==\0)
                        std::string a(buf+1, strnlen(buf+1, 107));
                        if (!a.empty())
                            return fmt::format("socket:UNIX abstract=@{}", a);
                    }
                }
            }
            return "socket:UNIX (no path)";
        }
        return fmt::format("socket:{} proto={}", fname, proto);
    }

    static const char* states[] = {
        "UNKNOWN","ESTABLISHED","SYN_SENT","SYN_RECV","FIN_WAIT1","FIN_WAIT2",
        "TIME_WAIT","CLOSE","CLOSE_WAIT","LAST_ACK","LISTEN","CLOSING","NEW_SYN_RECV"
    };
    const char* state = s->state < std::size(states) ? states[s->state] : "?";
    const char* proto = (s->proto == SocketInfo::P_UDP) ? "UDP" : "TCP";
    auto fmt_addr = [&](const std::array<u8,16>& a, u16 port) -> std::string {
        if (s->family == SocketInfo::AF_INET6)
            return fmt::format("[{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:"
                               "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}]:{}",
                a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7],
                a[8],a[9],a[10],a[11],a[12],a[13],a[14],a[15], port);
        return fmt::format("{}.{}.{}.{}:{}", a[0], a[1], a[2], a[3], port);
    };
    return fmt::format("socket:{} {} -> {} {}",
                       proto,
                       fmt_addr(s->local_addr,  s->local_port),
                       fmt_addr(s->remote_addr, s->remote_port),
                       state);
}

} // anon

std::vector<OpenFd> enumerate_fds(const Engine& eng, const Process& p) {
    std::vector<OpenFd> out;
    if (p.task_va == 0) return out;
    const auto& isf = eng.isf();

    u64 ts_files_off;
    u64 fs_fdt_off;
    u64 fdt_max_off, fdt_fd_off;
    u64 file_mode_off, file_flags_off, file_path_off, file_pos_off, file_inode_off;
    u64 path_dentry_off, path_mnt_off;
    DentryOffsets dop = resolve_dentry_offsets(isf);
    try {
        ts_files_off    = isf.field_offset("task_struct",   "files");
        fs_fdt_off      = isf.field_offset("files_struct",  "fdt");
        fdt_max_off     = isf.field_offset("fdtable",       "max_fds");
        fdt_fd_off      = isf.field_offset("fdtable",       "fd");
        file_mode_off   = isf.field_offset("file",          "f_mode");
        file_flags_off  = isf.field_offset("file",          "f_flags");
        file_path_off   = isf.field_offset("file",          "f_path");
        file_pos_off    = isf.field_offset("file",          "f_pos");
        file_inode_off  = isf.field_offset("file",          "f_inode");
        path_dentry_off = isf.field_offset("path",          "dentry");
        path_mnt_off    = isf.field_offset("path",          "mnt");
    } catch (const std::exception& e) {
        log::debug("fds: ISF missing field — {}", e.what());
        return out;
    }

    // Walk task->files → files_struct.fdt → fdtable.{max_fds, fd[]}.
    VAddr files_va = 0;
    if (!kread_pod(eng, p.task_va + ts_files_off, files_va) || files_va == 0)
        return out;
    VAddr fdt_va = 0;
    if (!kread_pod(eng, files_va + fs_fdt_off, fdt_va) || fdt_va == 0)
        return out;
    u32   max_fds = 0;
    VAddr fd_array_va = 0;
    if (!kread_pod(eng, fdt_va + fdt_max_off, max_fds))    return out;
    if (!kread_pod(eng, fdt_va + fdt_fd_off,  fd_array_va)) return out;
    if (max_fds == 0 || max_fds > 65536 || fd_array_va == 0) return out;

    // Read all max_fds pointers in one shot.
    std::vector<VAddr> file_ptrs(max_fds, 0);
    if (!kread(eng, fd_array_va, file_ptrs.data(),
               max_fds * sizeof(VAddr)))
        return out;

    // Socket index — cached on the engine; building it walks the global
    // TCP/UDP hash tables once per session.
    const auto& sock_idx = eng.socket_index();

    for (u32 i = 0; i < max_fds; ++i) {
        VAddr file_va = file_ptrs[i];
        if (file_va == 0) continue;

        OpenFd o{};
        o.fd      = static_cast<int>(i);
        o.file_va = file_va;
        kread_pod(eng, file_va + file_mode_off,  o.mode);
        kread_pod(eng, file_va + file_flags_off, o.flags);
        kread_pod(eng, file_va + file_pos_off,   o.pos);

        VAddr dentry_va = 0, vfsmount_va = 0, inode_va = 0;
        kread_pod(eng, file_va + file_path_off + path_dentry_off, dentry_va);
        kread_pod(eng, file_va + file_path_off + path_mnt_off,    vfsmount_va);
        kread_pod(eng, file_va + file_inode_off, inode_va);

        // Step 1: socket fd? Sockets have inode.i_mode S_IFSOCK and a real
        // dentry that walks back to sockfs's root (so we'd get "/" via
        // dentry_to_path). Check the socket case FIRST so we replace the
        // useless "/" with concrete protocol+endpoint info.
        std::string sock_label = format_socket_for_fd(eng, inode_va, sock_idx);
        if (!sock_label.empty()) {
            o.target = std::move(sock_label);
        } else if (dentry_va != 0) {
            o.target = dentry_to_path(eng, dentry_va, vfsmount_va, dop);
        } else {
            // Anonymous file (pipe / anon_inode / event_poll / ...).
            o.target = fmt::format("anon:[{:#x}]", inode_va);
        }

        out.push_back(std::move(o));
    }
    return out;
}

namespace {

std::string diagnose_fdtable_empty(const Engine& eng, const Process& p) {
    if (p.task_va == 0)
        return "task_struct address is zero";

    const auto& isf = eng.isf();
    u64 ts_files_off = 0, fs_fdt_off = 0, fdt_max_off = 0, fdt_fd_off = 0;
    try {
        ts_files_off = isf.field_offset("task_struct",  "files");
        fs_fdt_off   = isf.field_offset("files_struct", "fdt");
        fdt_max_off  = isf.field_offset("fdtable",      "max_fds");
        fdt_fd_off   = isf.field_offset("fdtable",      "fd");
    } catch (const std::exception& e) {
        return fmt::format("ISF missing fdtable field offsets: {}", e.what());
    }

    VAddr files_va = 0;
    if (!kread_pod(eng, p.task_va + ts_files_off, files_va))
        return fmt::format("cannot read task->files at {:#x}",
                           p.task_va + ts_files_off);
    if (files_va == 0)
        return "task->files is NULL (common for kernel threads and zombies)";

    VAddr fdt_va = 0;
    if (!kread_pod(eng, files_va + fs_fdt_off, fdt_va))
        return fmt::format("cannot read files_struct.fdt at {:#x}",
                           files_va + fs_fdt_off);
    if (fdt_va == 0)
        return "files_struct.fdt is NULL";

    u32 max_fds = 0;
    VAddr fd_array_va = 0;
    if (!kread_pod(eng, fdt_va + fdt_max_off, max_fds))
        return fmt::format("cannot read fdtable.max_fds at {:#x}",
                           fdt_va + fdt_max_off);
    if (!kread_pod(eng, fdt_va + fdt_fd_off, fd_array_va))
        return fmt::format("cannot read fdtable.fd at {:#x}",
                           fdt_va + fdt_fd_off);
    if (max_fds == 0)
        return "fdtable.max_fds is zero";
    if (max_fds > 65536)
        return fmt::format("fdtable.max_fds is implausible: {}", max_fds);
    if (fd_array_va == 0)
        return "fdtable.fd pointer array is NULL";

    std::vector<VAddr> file_ptrs(max_fds, 0);
    if (!kread(eng, fd_array_va, file_ptrs.data(), max_fds * sizeof(VAddr)))
        return fmt::format("cannot read fd pointer array at {:#x} ({} fds)",
                           fd_array_va, max_fds);

    return fmt::format("fdtable is readable at {:#x} but all {} fd slots are NULL",
                       fdt_va, max_fds);
}

} // anon

ByteBuf format_fd_table(const Engine& eng, const Process& p) {
    auto fds = enumerate_fds(eng, p);
    if (fds.empty()) {
        auto reason = diagnose_fdtable_empty(eng, p);
        std::string s = fmt::format(
            "; pid {} ({}) has no recoverable open fds.\n"
            "; reason: {}\n",
            p.pid, p.comm, reason);
        return ByteBuf(s.begin(), s.end());
    }
    std::string out;
    out.reserve(8 * 1024);
    out += fmt::format(
        "# /proc/{}/fd — {} open file descriptors\n"
        "# fd | mode  flags     pos  | target\n"
        "#----+--------------------- +--------------------------------------------\n",
        p.pid, fds.size());
    for (const auto& o : fds) {
        // Decode f_mode bits: 1=READ, 2=WRITE, 4=EXEC, 0x10=PREAD, ...
        char m_r = (o.mode & 0x1) ? 'r' : '-';
        char m_w = (o.mode & 0x2) ? 'w' : '-';
        char m_x = (o.mode & 0x4) ? 'x' : '-';
        out += fmt::format("{:>4}  {}{}{}   {:#06x}  {:>8}  {}\n",
                           o.fd, m_r, m_w, m_x,
                           o.flags & 0xFFFF, o.pos, o.target);
    }
    return ByteBuf(out.begin(), out.end());
}

} // namespace lmpfs::linux
