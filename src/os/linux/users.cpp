// users.cpp — see header.
#include "os/linux/users.h"
#include "app/engine.h"
#include "vfs/vfs.h"
#include "core/log.h"
#include <fmt/format.h>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace lmpfs::linux {

namespace {

// Try to read the entire `/fs/etc/passwd` content via the VFS. Returns
// empty on any failure (file missing from page cache, dentry path not
// resolvable, etc.).
std::string read_passwd_file(const Engine& eng) {
    auto node = vfs::resolve(eng.vfs_root(), "/fs/etc/passwd");
    if (!node || !node->is_file()) return {};
    u64 sz = node->size();
    if (sz == 0 || sz > 4 * 1024 * 1024) return {};   // /etc/passwd is small
    std::string out;
    out.resize(static_cast<std::size_t>(sz));
    std::size_t got = node->read(0, out.data(), out.size());
    out.resize(got);
    return out;
}

struct PasswdEntry {
    std::string name;
    u32         uid  = 0;
    u32         gid  = 0;
    std::string gecos;
    std::string home;
    std::string shell;
};

// Parse a /etc/passwd line: name:x:uid:gid:gecos:home:shell
bool parse_line(const std::string& line, PasswdEntry& e) {
    if (line.empty() || line[0] == '#') return false;
    std::vector<std::string> f;
    std::string acc;
    for (char c : line) {
        if (c == ':') { f.push_back(std::move(acc)); acc.clear(); }
        else if (c != '\r' && c != '\n') acc.push_back(c);
    }
    f.push_back(std::move(acc));
    if (f.size() < 7) return false;
    e.name  = f[0];
    try {
        e.uid = static_cast<u32>(std::stoul(f[2]));
        e.gid = static_cast<u32>(std::stoul(f[3]));
    } catch (...) { return false; }
    e.gecos = f[4];
    e.home  = f[5];
    e.shell = f[6];
    return true;
}

} // anonymous

ByteBuf format_users(const Engine& eng) {
    std::string passwd = read_passwd_file(eng);
    // Parse /etc/passwd into uid → entry map.
    std::map<u32, PasswdEntry> by_uid;
    if (!passwd.empty()) {
        std::string line;
        for (char c : passwd) {
            if (c == '\n') {
                PasswdEntry e;
                if (parse_line(line, e)) by_uid.emplace(e.uid, std::move(e));
                line.clear();
            } else line.push_back(c);
        }
        if (!line.empty()) {
            PasswdEntry e;
            if (parse_line(line, e)) by_uid.emplace(e.uid, std::move(e));
        }
    }
    // Collect UIDs seen in live tasks; cross-tag against /etc/passwd.
    std::map<u32, std::size_t> proc_count_by_uid;
    for (const auto& p : eng.processes()) ++proc_count_by_uid[p.uid];

    std::string out;
    out.reserve(8 * 1024);
    out += fmt::format(
        "# /sys/users.txt — UID → name table\n"
        "# /etc/passwd source: {}\n"
        "# {} entries parsed; {} unique UIDs seen across {} live tasks.\n"
        "#\n",
        passwd.empty() ? "/fs/etc/passwd MISSING from page cache (file uncached at snapshot)"
                       : "/fs/etc/passwd (reconstructed via inode page-cache walk)",
        by_uid.size(), proc_count_by_uid.size(), eng.processes().size());

    // Union of UIDs from passwd ∪ live tasks.
    std::set<u32> all_uids;
    for (auto& [uid, _] : by_uid)           all_uids.insert(uid);
    for (auto& [uid, _] : proc_count_by_uid) all_uids.insert(uid);

    out += fmt::format("{:>6}  {:<16}  {:>5}  {:>5}  {:<24}  {}\n",
                       "UID", "NAME", "PROCS", "GID", "HOME", "SHELL");
    out += std::string(96, '-') + "\n";
    for (u32 uid : all_uids) {
        std::size_t nproc = proc_count_by_uid.count(uid) ? proc_count_by_uid.at(uid) : 0;
        auto it = by_uid.find(uid);
        if (it != by_uid.end()) {
            const auto& e = it->second;
            out += fmt::format("{:>6}  {:<16}  {:>5}  {:>5}  {:<24}  {}\n",
                               uid, e.name.substr(0, 16), nproc, e.gid,
                               e.home.substr(0, 24), e.shell);
        } else {
            // UID present in live tasks but not in /etc/passwd (LDAP /
            // SSSD / nss-resolve / system uid not in the file / container
            // uid_map remap).
            out += fmt::format("{:>6}  {:<16}  {:>5}  {:>5}  {:<24}  {}\n",
                               uid, "(unresolved)", nproc, "?",
                               "?", "(not in /etc/passwd)");
        }
    }
    return ByteBuf(out.begin(), out.end());
}

} // namespace lmpfs::linux
