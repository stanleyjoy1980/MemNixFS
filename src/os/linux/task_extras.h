// task_extras.h — Tier-1 finisher generators for /proc/<pid>/{libs,ptrace}.txt.
//
// Kept separate from task_files.{h,cpp} because both new files need
// VMA enumeration / list-walking + dentry-path resolution and would
// otherwise inflate the already-large task_files.cpp.
//
// References:
//   vol3:      linux.library_list, linux.ptrace
//   MemProcFS: m_proc_ldrmodules.c (Windows equivalent)
//
// /proc/<pid>/libs.txt    — every shared library mapped into the process.
//                           Derived from file-backed exec VMAs; deduped
//                           by path; each row shows the path, the
//                           contiguous VA range it covers, total mapped
//                           bytes, and how many VMAs (rx / r-- / rw-)
//                           contribute. Cross-ref of /proc/<pid>/maps.
//
// /proc/<pid>/ptrace.txt  — every active ptrace relationship involving
//                           this task: who's ptracing me (task.parent),
//                           who I'm ptracing (task.ptraced list), plus
//                           task.ptrace flag bits decoded.
//
#pragma once
#include "core/types.h"
#include "core/stream.h"
#include "os/linux/process.h"

namespace lmpfs { class Engine; }

namespace lmpfs::linux {

ByteBuf gen_libs  (const Engine& eng, const Process& p);
ByteBuf gen_ptrace(const Engine& eng, const Process& p);

} // namespace lmpfs::linux
