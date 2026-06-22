// tracing.h — enumerate kernel kprobes (and, future: tracepoints + uprobes).
//
// kprobe_table is a 64-slot hash table of `hlist_head`. Each chain holds
// `struct kprobe`s instrumenting a specific kernel address. For each kprobe
// we surface:
//   * addr           — the kernel address being probed
//   * symbol         — the kernel symbol nearest to addr (via kallsyms)
//   * pre_handler    — function called BEFORE the probed instruction
//   * post_handler   — function called AFTER (NULL is normal — most probes
//                       only set pre_handler)
//   * flags          — KPROBE_FLAG_GONE / DISABLED / OPTIMIZED / REENTER bits
//
// Forensic value: rootkits register kprobes at the entry of sensitive
// syscalls (e.g. sys_getdents to hide files, sys_kill to hide processes,
// sys_socket to filter connections). Each kprobe's pre_handler is
// classify_ptr-validated against kernel text — a handler in module memory
// is potentially malicious.
//
// kprobes registered via eBPF (program type KPROBE) ALSO show up here,
// PLUS in /sys/findevil/ebpf.txt — cross-referencing the two sets is the
// modern way to spot eBPF kprobe rootkits.
//
// Cross-ref: vol3 has no direct linux.kprobes plugin yet (open issue);
//            this matches the spirit of `vol3 tracing/` framework support.
#pragma once
#include "core/types.h"
#include "core/stream.h"
#include "os/linux/integrity_checks.h"   // PtrAudit
#include <string>
#include <vector>

namespace lmpfs { class Engine; }

namespace lmpfs::linux {

struct KprobeInfo {
    u32         bucket   = 0;
    VAddr       kprobe_va = 0;
    VAddr       addr     = 0;       // address being probed
    std::string symbol;             // nearest kallsyms symbol to addr
    u64         distance = 0;       // bytes past symbol start
    VAddr       pre_handler   = 0;
    VAddr       post_handler  = 0;
    u32         flags    = 0;
    std::string symbol_name;        // kprobe.symbol_name (the requested name)
    PtrAudit    pre_audit;
    PtrAudit    post_audit;
};

std::vector<KprobeInfo> enumerate_kprobes(const Engine& eng);

// /sys/findevil/kprobes.txt
ByteBuf format_kprobes(const Engine& eng);

} // namespace lmpfs::linux
