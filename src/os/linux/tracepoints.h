// tracepoints.h — enumerate active kernel tracepoints + their handlers.
//
// Earlier (v0.20) we punted on tracepoints citing "section markers stripped
// from kallsyms" — that turned out to be wrong. The MODERN kernel emits a
// `__tracepoint_<event_name>` global for every DEFINE_TRACE(event), and
// these ARE in kallsyms on stock distro builds (1167 of them on the test
// dump). v0.26 walks every one.
//
// Each `struct tracepoint` carries a `funcs` pointer; when non-NULL it
// points at a NULL-terminated array of `struct tracepoint_func { func,
// data, prio }`. A non-empty funcs list means SOMEONE attached a handler
// at that tracepoint — exactly the modern-rootkit attack surface (eBPF
// TRACEPOINT/RAW_TRACEPOINT programs, perf attachments, ftrace
// instrumentation). Each handler address is classify_ptr-audited
// against kernel-text + kallsyms conventions.
//
// Output: /sys/findevil/tracepoints.txt — one row per tracepoint that
// has at least one handler registered.
//
// References:
//   Kernel:    include/linux/tracepoint-defs.h, kernel/tracepoint.c
//   vol3:      no direct equivalent (tracing/ framework only)
//   MemProcFS: no Windows analog
#pragma once
#include "core/types.h"
#include "core/stream.h"
#include "os/linux/integrity_checks.h"   // PtrAudit
#include <string>
#include <vector>

namespace lmpfs { class Engine; }

namespace lmpfs::linux {

struct TracepointHandler {
    VAddr     func    = 0;
    VAddr     data    = 0;
    PtrAudit  audit;        // classify_ptr verdict on `func`
};

struct TracepointInfo {
    std::string  name;          // e.g. "probe_module_cb"
    VAddr        tracepoint_va = 0;
    VAddr        funcs_va      = 0;
    std::vector<TracepointHandler> handlers;
};

// Walks kallsyms for every `__tracepoint_*` symbol and reads its
// `struct tracepoint`. Only tracepoints with at least one handler
// attached are returned (most kernel tracepoints have funcs==NULL on
// a clean system).
std::vector<TracepointInfo> enumerate_active_tracepoints(const Engine& eng);

// /sys/findevil/tracepoints.txt
ByteBuf format_tracepoints(const Engine& eng);

} // namespace lmpfs::linux
