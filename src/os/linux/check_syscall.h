// check_syscall.h — verify the integrity of `sys_call_table`.
//
// Syscall hooking is the #1 primitive for Linux kernel rootkits: a
// malicious LKM overwrites entries in `sys_call_table` to point at its
// own handlers (typically in vmalloc memory, sometimes splicing back to
// the original via call/ret). This module reads every table entry and
// classifies it:
//
//   OK         entry points to a kallsyms symbol whose name matches the
//              expected handler pattern (`__x64_sys_*` / `sys_*` /
//              `__do_sys_*` / `sys_ni_syscall`).
//
//   SUSPICIOUS entry points into kernel text but the resolved symbol's
//              name doesn't match the expected pattern (could be a
//              compiler-emitted thunk, but worth investigating).
//
//   HOOKED     entry points OUTSIDE the kernel-text range [_stext.._etext],
//              after the recovered table has first passed a pointer-table
//              plausibility check. A corrupt or misread table is reported as
//              unavailable rather than as mass hooks.
//
// Output goes to /sys/findevil/check_syscall.txt and feeds the
// /sys/findevil/findevil.txt aggregator.
//
// Cross-ref: vol3 `linux.check_syscall.Check_syscall`,
//            MemProcFS `m_sys_syscall.c` + `m_evil_kern1.c`.
#pragma once
#include "core/types.h"
#include "core/stream.h"
#include <string>
#include <vector>

namespace lmpfs { class Engine; }

namespace lmpfs::linux {

struct SyscallEntry {
    u32         nr           = 0;       // index into sys_call_table
    VAddr       entry_addr   = 0;       // function pointer pulled from the table
    std::string resolved_name;          // kallsyms symbol the entry resolves to
    u64         distance     = 0;       // entry_addr - resolved_symbol.address
    enum Status { OK, SUSPICIOUS, HOOKED } status = OK;
    std::string note;                   // human-readable reason
};

// Read sys_call_table, classify each entry. Returns empty if the symbol,
// kernel-text bounds, or table-shape validation aren't usable.
std::vector<SyscallEntry> check_syscall_table(const Engine& eng);

// /sys/findevil/check_syscall.txt
ByteBuf format_check_syscall(const Engine& eng);

} // namespace lmpfs::linux
