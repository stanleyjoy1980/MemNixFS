// threads.cpp — see header.
#include "os/linux/threads.h"
#include "os/linux/kva_reader.h"
#include "app/engine.h"
#include "symbols/isf_symbols.h"
#include "core/log.h"
#include <fmt/format.h>
#include <algorithm>

namespace lmpfs::linux {

namespace {

const char* state_name(u32 s) {
    // Linux task states (bitmask; lowest-bit-priority for display).
    if (s == 0)         return "R (running)";
    if (s & 0x0001)     return "S (sleeping)";
    if (s & 0x0002)     return "D (uninterruptible)";
    if (s & 0x0004)     return "T (stopped)";
    if (s & 0x0008)     return "t (traced)";
    if (s & 0x0010)     return "X (dead)";
    if (s & 0x0020)     return "Z (zombie)";
    if (s & 0x0040)     return "P (parked)";
    return "?";
}

} // anonymous

std::vector<ThreadInfo> enumerate_threads(const Engine& eng,
                                          const Process& leader)
{
    std::vector<ThreadInfo> out;
    if (leader.task_va == 0) return out;
    const auto& isf = eng.isf();

    u64 ts_signal_off, ts_thread_node_off, ts_pid_off, ts_tgid_off,
        ts_state_off, ts_comm_off, sig_thread_head_off;
    try {
        ts_signal_off       = isf.field_offset("task_struct",   "signal");
        ts_thread_node_off  = isf.field_offset("task_struct",   "thread_node");
        ts_pid_off          = isf.field_offset("task_struct",   "pid");
        ts_tgid_off         = isf.field_offset("task_struct",   "tgid");
        ts_comm_off         = isf.field_offset("task_struct",   "comm");
        sig_thread_head_off = isf.field_offset("signal_struct", "thread_head");
    } catch (const std::exception& e) {
        log::debug("threads: ISF lacks field — {}", e.what());
        return out;
    }
    // __state offset varies; optional.
    try { ts_state_off = isf.field_offset("task_struct", "__state"); }
    catch (...) {
        try { ts_state_off = isf.field_offset("task_struct", "state"); }
        catch (...) { ts_state_off = 0; }
    }

    VAddr signal_va = 0;
    if (!kva_read_pod(eng, leader.task_va + ts_signal_off, signal_va) ||
        signal_va == 0)
    {
        // No signal_struct → single-threaded; return just the leader.
        ThreadInfo t{};
        t.pid     = leader.pid;
        t.tgid    = leader.tgid;
        t.comm    = leader.comm;
        t.task_va = leader.task_va;
        out.push_back(std::move(t));
        return out;
    }

    VAddr head_va = signal_va + sig_thread_head_off;
    VAddr cur = 0;
    if (!kva_read_pod(eng, head_va, cur)) return out;
    int guard = 0;
    while (cur != 0 && cur != head_va && guard++ < 0x10000) {
        VAddr task_va = cur - ts_thread_node_off;

        ThreadInfo t{};
        t.task_va = task_va;
        kva_read_pod(eng, task_va + ts_pid_off,  t.pid);
        kva_read_pod(eng, task_va + ts_tgid_off, t.tgid);
        if (ts_state_off) {
            u32 s = 0;
            kva_read_pod(eng, task_va + ts_state_off, s);
            t.state = s;
        }
        char comm[17] = {};
        kva_read(eng, task_va + ts_comm_off, comm, 16);
        std::size_t n = 0;
        while (n < 16 && comm[n]) ++n;
        t.comm.assign(comm, n);

        // Sanity: reject obvious garbage (we just walked into bad memory).
        if (t.pid > 0x400000 || t.tgid > 0x400000) break;

        out.push_back(std::move(t));

        VAddr nxt = 0;
        if (!kva_read_pod(eng, cur, nxt) || nxt == cur) break;
        cur = nxt;
    }
    return out;
}

ByteBuf format_proc_threads(const Engine& eng, const Process& leader) {
    auto threads = enumerate_threads(eng, leader);
    std::string out;
    out.reserve(2 * 1024);
    out += fmt::format(
        "# /proc/{}/threads.txt — threads of pid {} ({})\n"
        "# Walks leader.signal->thread_head; tgid for all entries == {}.\n"
        "# {} thread(s) total (incl. leader).\n"
        "#\n"
        "#    TID       state                 comm              task_va\n"
        "# ------- --------------------- --------------------- -------------------\n",
        leader.pid, leader.pid, leader.comm, leader.tgid, threads.size());
    for (const auto& t : threads) {
        out += fmt::format("  {:>6}  {:<22}  {:<22}  {:#018x}\n",
                           t.pid, state_name(t.state), t.comm, t.task_va);
    }
    return ByteBuf(out.begin(), out.end());
}

ByteBuf format_global_threads(const Engine& eng) {
    std::string out;
    out.reserve(64 * 1024);
    std::size_t total = 0;
    for (const auto& p : eng.processes()) total += 1;   // upper bound only

    out += "# /sys/processes/threads.txt — every thread of every visible process\n"
           "# Walks each leader's signal->thread_head. \"TID\" is the kernel's\n"
           "# per-thread pid; TGID is the leader's pid.\n"
           "#\n"
           "#    TID    TGID    state                 comm\n"
           "# ------- ------- --------------------- ----------------\n";
    std::size_t real_threads = 0;
    for (const auto& leader : eng.processes()) {
        std::vector<ThreadInfo> ts;
        try { ts = enumerate_threads(eng, leader); }
        catch (...) { continue; }
        real_threads += ts.size();
        for (const auto& t : ts) {
            out += fmt::format("  {:>6}  {:>6}  {:<22}  {}\n",
                               t.pid, t.tgid, state_name(t.state), t.comm);
        }
    }
    // Prepend the real total now that we know it.
    std::string hdr = fmt::format(
        "# Total: {} threads across {} thread-group leaders\n#\n",
        real_threads, eng.processes().size());
    std::string combined = hdr + out;
    return ByteBuf(combined.begin(), combined.end());
}

} // namespace lmpfs::linux
