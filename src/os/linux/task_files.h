// task_files.h — generators for the Linux-style /proc/<pid>/* text files.
//
// Each function returns the raw bytes that should appear at the named path,
// matching the real kernel's output format exactly so existing /proc-reading
// tools work unchanged against the mount.
//
// References:
//   MemProcFS:  m_misc_procinfo.c (cmdline view), m_proc_memmap.c (maps)
//   Volatility: framework/plugins/linux/envars.py, proc.py, psaux.py, lsof.py
//
#pragma once
#include "core/types.h"
#include "formats/physical_layer.h"
#include "symbols/isf_symbols.h"
#include "os/linux/kernel_resolver.h"
#include "os/linux/process.h"
#include "os/linux/vma.h"

namespace lmpfs::linux {

// /proc/<pid>/cmdline — NUL-separated argv read from mm->arg_start..arg_end.
ByteBuf gen_cmdline(const PhysicalLayer& phys, const IsfSymbols& isf,
                    const KernelContext& kctx, const Process& p);

// /proc/<pid>/environ — NUL-separated environ from mm->env_start..env_end.
ByteBuf gen_environ(const PhysicalLayer& phys, const IsfSymbols& isf,
                    const KernelContext& kctx, const Process& p);

// /proc/<pid>/comm — task->comm + '\n'.
ByteBuf gen_comm(const Process& p);

// /proc/<pid>/maps — exact Linux /proc/PID/maps format:
//   start-end perm pgoff dev:major:minor inode  path
ByteBuf gen_maps(const std::vector<Vma>& vmas);

// /proc/<pid>/status — Linux /proc/PID/status format (subset).
ByteBuf gen_status(const PhysicalLayer& phys, const IsfSymbols& isf,
                   const KernelContext& kctx, const Process& p);

// /proc/<pid>/stat — single-line space-separated stat fields (man proc(5)).
// Many fields are reconstructable; the rest are zero-filled. Compatible with
// `ps`, `top`, htop's parser.
ByteBuf gen_stat(const PhysicalLayer& phys, const IsfSymbols& isf,
                 const KernelContext& kctx, const Process& p);

// /proc/<pid>/statm — single line of memory stats in pages:
//   size resident shared text lib data dt
ByteBuf gen_statm(const PhysicalLayer& phys, const IsfSymbols& isf,
                  const KernelContext& kctx, const Process& p);

// /proc/<pid>/limits — rlimit table (Soft / Hard / Units columns).
ByteBuf gen_limits(const PhysicalLayer& phys, const IsfSymbols& isf,
                   const KernelContext& kctx, const Process& p);

// /proc/<pid>/loginuid — single ASCII integer.
ByteBuf gen_loginuid(const PhysicalLayer& phys, const IsfSymbols& isf,
                     const KernelContext& kctx, const Process& p);

// /proc/<pid>/oom_score_adj — signed integer (-1000..1000).
ByteBuf gen_oom_score_adj(const PhysicalLayer& phys, const IsfSymbols& isf,
                          const KernelContext& kctx, const Process& p);

// Per-process path-as-text files (we don't synthesise real symlinks under
// WinFsp). Each contains the resolved kernel-side path or an explanatory note.
ByteBuf gen_exe(const PhysicalLayer& phys, const IsfSymbols& isf,
                const KernelContext& kctx, const Process& p);
ByteBuf gen_cwd(const PhysicalLayer& phys, const IsfSymbols& isf,
                const KernelContext& kctx, const Process& p);
ByteBuf gen_root(const PhysicalLayer& phys, const IsfSymbols& isf,
                 const KernelContext& kctx, const Process& p);

// /proc/<pid>/capabilities — formatted cred caps.
ByteBuf gen_capabilities(const PhysicalLayer& phys, const IsfSymbols& isf,
                         const KernelContext& kctx, const Process& p);

} // namespace lmpfs::linux
