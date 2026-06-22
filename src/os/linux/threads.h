// threads.h — enumerate threads belonging to a thread-group leader.
//
// Our canonical process list (`Engine::processes()`) shows thread-group
// LEADERS only — every entry has `pid == tgid`. The other threads of
// each multi-threaded process live in the kernel via:
//
//   leader_task->signal           struct signal_struct*
//                  .thread_head   list_head             (chain head)
//                  ↑
//   each thread's task->thread_node is linked into that list.
//
// We walk that list, read each thread's pid + comm + state, and expose
// the result both per-leader at `/proc/<pid>/threads.txt` and globally
// at `/sys/processes/threads.txt`.
//
// Cross-ref: vol3 `linux.pslist --threads`, `linux.kthreads`.
#pragma once
#include "core/types.h"
#include "core/stream.h"
#include "os/linux/process.h"
#include <string>
#include <vector>

namespace lmpfs { class Engine; }

namespace lmpfs::linux {

struct ThreadInfo {
    u32         pid       = 0;   // TID (kernel's "pid" for the thread)
    u32         tgid      = 0;   // leader pid
    u32         state     = 0;
    std::string comm;
    VAddr       task_va   = 0;
};

// Walk `leader.signal->thread_head`; returns every thread of the group
// (INCLUDING the leader). Returns just {leader} for kernel threads /
// single-threaded procs.
std::vector<ThreadInfo> enumerate_threads(const Engine& eng,
                                          const Process& leader);

// /proc/<pid>/threads.txt — per-leader text listing.
ByteBuf format_proc_threads(const Engine& eng, const Process& leader);

// /sys/processes/threads.txt — every thread of every process. Useful for
// a "real total task count" view (vol3 `pslist --threads` equivalent).
ByteBuf format_global_threads(const Engine& eng);

} // namespace lmpfs::linux
