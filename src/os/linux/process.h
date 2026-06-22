#pragma once
#include "core/types.h"
#include "arch/x86_64/paging.h"
#include "symbols/isf_symbols.h"
#include "os/linux/kernel_resolver.h"
#include <string>
#include <vector>

namespace lmpfs::linux {

struct Process {
    u32         pid   = 0;
    u32         tgid  = 0;
    u32         ppid  = 0;
    u32         uid   = 0;
    u32         gid   = 0;
    std::string comm;
    VAddr       task_va = 0;
    PAddr       task_pa = 0;
    VAddr       mm      = 0;        // mm_struct pointer (0 for kernel threads)
};

// Enumerates user-visible processes by walking the init_task.tasks list.
std::vector<Process> list_processes(const PhysicalLayer&     phys,
                                    const x86_64::PageTable& pt,
                                    const IsfSymbols&        isf,
                                    const KernelContext&     kctx);

} // namespace lmpfs::linux
