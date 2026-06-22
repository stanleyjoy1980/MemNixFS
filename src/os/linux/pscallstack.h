// pscallstack.h — symbolised kernel-stack walk per task.
//
// For each task we read its kernel stack (THREAD_SIZE bytes anchored at
// `task->stack`, with the saved-SP at `task->thread.sp`) and find every
// 8-byte aligned value that points into kernel text. Each such value is
// a candidate return address; we resolve it via kallsyms to surface what
// chain of kernel functions the thread was last executing.
//
// Why this is useful:
//   * For sleeping/blocked threads it shows what the thread is waiting on
//     (e.g. `do_wait → schedule_timeout → schedule`).
//   * For threads inside a rootkit-injected handler, the rogue frame
//     shows up alongside the legitimate ones.
//   * For "what was this thread doing right when the dump was taken?"
//     — the answer that traditional `ps` can't give you.
//
// Output:
//   /proc/<pid>/kstack.txt    per-process; for tasks with a kernel stack.
//
// Cross-ref: vol3 `linux.pscallstack`; MemProcFS doesn't have a direct
//            equivalent (Windows ETHREAD-stack is its own thing).
#pragma once
#include "core/types.h"
#include "core/stream.h"
#include "os/linux/process.h"
#include <string>
#include <vector>

namespace lmpfs { class Engine; }

namespace lmpfs::linux {

struct KStackFrame {
    u64         offset_in_stack = 0;  // bytes from stack base
    VAddr       return_addr     = 0;
    std::string symbol;               // kallsyms name (without [module])
    u64         distance        = 0;  // bytes past symbol start
};

struct KStackTrace {
    VAddr   stack_base = 0;
    VAddr   thread_sp  = 0;
    std::vector<KStackFrame> frames;   // dedup'd, in stack order (lowest offset first)
    bool    ok         = false;
};

// Read this task's kernel stack and pick out the return-address-like
// kernel-text pointers. Returns ok=false for kernel-only tasks where we
// can't resolve task->stack or task->thread.sp.
KStackTrace walk_kernel_stack(const Engine& eng, const Process& p);

// /proc/<pid>/kstack.txt — pretty-printed per-task trace.
ByteBuf format_kstack(const Engine& eng, const Process& p);

} // namespace lmpfs::linux
