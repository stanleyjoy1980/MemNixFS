// users.cpp — see header.
#include "os/linux/users.h"
#include "os/linux/pagecache.h"
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
// resolvable, etc.). Used only as a fallback when the inode walk finds
// no /etc/passwd candidates.
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

// Parse a whole /etc/passwd blob into a uid → entry map.
std::map<u32, PasswdEntry> parse_passwd(const std::string& passwd) {
    std::map<u32, PasswdEntry> by_uid;
    std::string line;
    auto flush = [&] {
        PasswdEntry e;
        if (parse_line(line, e)) by_uid.emplace(e.uid, std::move(e));
        line.clear();
    };
    for (char c : passwd) {
        if (c == '\n') flush();
        else           line.push_back(c);
    }
    if (!line.empty()) flush();
    return by_uid;
}

bool path_is_etc_passwd(const std::string& p) {
    // Match the canonical "/etc/passwd" plus any namespaced / container /
    // overlay root that still ends in "/etc/passwd".
    static constexpr char suffix[] = "/etc/passwd";
    constexpr std::size_t n = sizeof(suffix) - 1;
    return p.size() >= n && p.compare(p.size() - n, n, suffix) == 0;
}

struct PasswdSource {
    std::map<u32, PasswdEntry> by_uid;
    std::string origin;            // human description for the header
    std::size_t candidates = 0;    // how many cached /etc/passwd inodes existed
};

// A snapshot can hold several /etc/passwd inodes — overlayfs upper/lower
// layers, per-container roots, or an old + rewritten copy. Trusting the
// first one the VFS resolves picks the wrong table on those systems. Instead
// enumerate every cached /etc/passwd and keep the copy that best explains the
// UIDs actually running on this machine.
PasswdSource select_passwd(const Engine& eng,
                           const std::map<u32, std::size_t>& live_uids) {
    struct Cand { std::string content; u64 ino; bool complete; };
    std::vector<Cand> cands;
    for (const auto& ci : enumerate_cached_inodes(eng)) {
        if (!path_is_etc_passwd(ci.path))                  continue;
        if ((ci.i_mode & 0xF000) != 0x8000)                continue; // regular files only
        if (ci.i_size == 0 || ci.i_size > 4 * 1024 * 1024) continue; // passwd is small
        auto rf = recover_file_with_stats(eng, ci);
        if (rf.bytes.empty()) continue;
        cands.push_back({std::string(rf.bytes.begin(), rf.bytes.end()),
                         ci.i_ino, rf.stats.complete()});
    }

    PasswdSource best;
    best.candidates = cands.size();

    if (cands.empty()) {
        // No cached inode resolved to /etc/passwd — fall back to the VFS path.
        std::string p = read_passwd_file(eng);
        if (!p.empty()) {
            best.by_uid = parse_passwd(p);
            best.origin = "/fs/etc/passwd (single resolved copy)";
        } else {
            best.origin = "/etc/passwd MISSING from page cache (file uncached at snapshot)";
        }
        return best;
    }

    // Score each copy: first by how many *live* UIDs it resolves (the whole
    // point of the table), then by total entries, then prefer a complete
    // (no missing pages) recovery as a tie-break.
    long best_score = -1;
    for (auto& c : cands) {
        auto m = parse_passwd(c.content);
        std::size_t covered = 0;
        for (const auto& kv : live_uids) if (m.count(kv.first)) ++covered;
        long score = static_cast<long>(covered) * 1'000'000
                   + static_cast<long>(m.size()) * 4
                   + (c.complete ? 2 : 0);
        if (score > best_score) {
            best_score  = score;
            best.origin = fmt::format(
                "/etc/passwd (inode {}, {}; resolves {}/{} live UIDs; "
                "{} cached cop{} found)",
                c.ino, c.complete ? "complete" : "partial",
                covered, live_uids.size(), cands.size(),
                cands.size() == 1 ? "y" : "ies");
            best.by_uid = std::move(m);
        }
    }
    return best;
}

} // anonymous

ByteBuf format_users(const Engine& eng) {
    // Live-task UIDs first — they drive which /etc/passwd copy is "correct".
    std::map<u32, std::size_t> proc_count_by_uid;
    for (const auto& p : eng.processes()) ++proc_count_by_uid[p.uid];

    PasswdSource src = select_passwd(eng, proc_count_by_uid);
    const auto& by_uid = src.by_uid;

    std::string out;
    out.reserve(8 * 1024);
    out += fmt::format(
        "# /sys/users.txt — UID → name table\n"
        "# /etc/passwd source: {}\n"
        "# {} entries parsed; {} unique UIDs seen across {} live tasks.\n"
        "#\n",
        src.origin, by_uid.size(), proc_count_by_uid.size(), eng.processes().size());

    // Union of UIDs from passwd ∪ live tasks.
    std::set<u32> all_uids;
    for (auto& [uid, _] : by_uid)            all_uids.insert(uid);
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
