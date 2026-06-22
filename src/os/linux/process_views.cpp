// process_views.cpp — see header.
#include "os/linux/process_views.h"
#include "os/linux/task_files.h"
#include "os/linux/vma.h"
#include "app/engine.h"
#include "core/log.h"
#include <fmt/format.h>
#include <algorithm>
#include <string>
#include <unordered_map>
#include <vector>

namespace lmpfs::linux {

namespace {

// Read a process's cmdline. NUL-separated argv → spaces. Empty for kernel
// threads (no mm). Falls back to `[comm]` (bracketed, like `ps` does for
// kernel threads) if the read fails.
std::string read_cmdline(const Engine& eng, const Process& p) {
    if (p.mm == 0) return fmt::format("[{}]", p.comm);
    ByteBuf raw;
    try { raw = gen_cmdline(eng.phys(), eng.isf(), eng.kernel(), p); }
    catch (...) { return fmt::format("[{}]", p.comm); }
    if (raw.empty()) return fmt::format("[{}]", p.comm);
    std::string s;
    s.reserve(raw.size());
    for (u8 c : raw) {
        if (c == 0) s.push_back(' ');
        else if (c == '\n' || c == '\r' || c == '\t') s.push_back(' ');
        else if (c < 0x20 || c >= 0x7F) s.push_back('?');
        else s.push_back((char)c);
    }
    // Trim trailing spaces.
    while (!s.empty() && s.back() == ' ') s.pop_back();
    return s;
}

// Sum of VMA sizes — equivalent to `ps`'s VSZ column (in KiB).
u64 read_vsz_kb(const Engine& eng, const Process& p) {
    if (p.mm == 0) return 0;
    std::vector<Vma> vmas;
    try { vmas = enumerate_vmas(eng.phys(), eng.isf(), eng.kernel(), p); }
    catch (...) { return 0; }
    u64 total = 0;
    for (const auto& v : vmas) total += v.size();
    return total / 1024;
}

} // anonymous

// -------------------- pslist --------------------

ByteBuf format_pslist(const Engine& eng) {
    const auto& procs = eng.processes();
    std::string out;
    out.reserve(64 * 1024);
    out += fmt::format(
        "# /sys/processes/pslist.txt — flat `ps -ef`-style listing\n"
        "# Walks init_task.tasks (the same source as /proc/<pid>-<comm>/).\n"
        "# Only thread-group leaders (pid == tgid) appear here; per-thread\n"
        "# enumeration is on the roadmap.\n"
        "#\n"
        "# Total: {} processes\n"
        "#\n"
        "# {:>6} {:>6} {:>6} {:>6}  {:<16}  CMD\n"
        "# {:->6} {:->6} {:->6} {:->6}  {:-<16}  {:->24}\n",
        procs.size(),
        "PID", "PPID", "TGID", "UID", "COMM", "", "", "", "", "", "");
    for (const auto& p : procs) {
        out += fmt::format("{:>8} {:>6} {:>6} {:>6}  {:<16}  {}\n",
                           p.pid, p.ppid, p.tgid, p.uid, p.comm,
                           read_cmdline(eng, p));
    }
    return ByteBuf(out.begin(), out.end());
}

// -------------------- pstree --------------------

namespace {

void render_node(const std::unordered_map<u32, std::vector<const Process*>>& children,
                 const Process* root, std::string prefix, bool last,
                 std::string& out, int depth)
{
    if (depth > 64) return;     // sanity guard against ppid cycles
    // Tree connector for this node.
    out += prefix;
    out += last ? "\\-- " : "+-- ";
    out += fmt::format("{} {}\n", root->pid, root->comm);

    auto it = children.find(root->pid);
    if (it == children.end()) return;
    const auto& kids = it->second;
    for (std::size_t i = 0; i < kids.size(); ++i) {
        std::string next_prefix = prefix + (last ? "    " : "|   ");
        render_node(children, kids[i], std::move(next_prefix),
                    i + 1 == kids.size(), out, depth + 1);
    }
}

} // anonymous

ByteBuf format_pstree(const Engine& eng) {
    const auto& procs = eng.processes();
    std::unordered_map<u32, std::vector<const Process*>> children;
    std::unordered_map<u32, const Process*>              by_pid;
    for (const auto& p : procs) by_pid[p.pid] = &p;
    for (const auto& p : procs) children[p.ppid].push_back(&p);

    // Find roots — processes whose ppid isn't another visible process.
    std::vector<const Process*> roots;
    for (const auto& p : procs)
        if (by_pid.find(p.ppid) == by_pid.end() || p.ppid == p.pid)
            roots.push_back(&p);
    // Stable order by PID.
    std::sort(roots.begin(), roots.end(),
        [](const Process* a, const Process* b) { return a->pid < b->pid; });
    for (auto& [ppid, vec] : children)
        std::sort(vec.begin(), vec.end(),
            [](const Process* a, const Process* b) { return a->pid < b->pid; });

    std::string out;
    out.reserve(64 * 1024);
    out += fmt::format(
        "# /sys/processes/pstree.txt — process tree by ppid\n"
        "# Drawn with ASCII connectors (+--, \\--, |) so the output stays\n"
        "# readable in classic cmd.exe and copy-pastes cleanly.\n"
        "# Roots = pid 0/1/2 + any process whose ppid isn't in the listing.\n"
        "#\n"
        "# Total: {} processes, {} root(s)\n#\n",
        procs.size(), roots.size());
    for (std::size_t i = 0; i < roots.size(); ++i) {
        render_node(children, roots[i], "", i + 1 == roots.size(), out, 0);
    }
    return ByteBuf(out.begin(), out.end());
}

// -------------------- psaux --------------------

ByteBuf format_psaux(const Engine& eng) {
    const auto& procs = eng.processes();
    std::string out;
    out.reserve(64 * 1024);
    out += fmt::format(
        "# /sys/processes/psaux.txt — `ps aux`-style with VSZ + cmdline\n"
        "# %CPU and %MEM aren't snapshot-derivable; shown as `-`.\n"
        "#\n"
        "# Total: {} processes\n"
        "#\n"
        "# {:>6} {:>6}  {:>5}  {:>11}  {:<16}  {:<16}  CMD\n"
        "# {:->6} {:->6}  {:->5}  {:->11}  {:-<16}  {:-<16}  ----\n",
        procs.size(),
        "PID", "PPID", "UID", "VSZ_KB", "COMM", "USER", "", "", "", "", "", "");
    for (const auto& p : procs) {
        u64 vsz = read_vsz_kb(eng, p);
        // We don't resolve UID → name (would need /etc/passwd from pagecache);
        // print numeric uid in the USER column. TODO: tier-2 user-resolution.
        out += fmt::format("{:>8} {:>6}  {:>5}  {:>11}  {:<16}  {:<16}  {}\n",
                           p.pid, p.ppid, p.uid, vsz, p.comm,
                           fmt::format("uid={}", p.uid),
                           read_cmdline(eng, p));
    }
    return ByteBuf(out.begin(), out.end());
}

} // namespace lmpfs::linux
