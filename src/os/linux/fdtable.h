// fdtable.h — walk a process's open file descriptors.
//
// Reads `task->files->fdt->fd[0..max_fds]`, classifies each:
//   - Regular file/directory → resolve full path via dentry walk
//   - Socket          → `socket:[<inode>]`
//   - Pipe            → `pipe:[<inode>]`
//   - Anonymous inode → `anon_inode:<name>`
//   - Char/block dev  → `/dev/<name>` if resolvable
//
// Same format that `ls -la /proc/<pid>/fd/` produces on a live system.
//
// References:
//   Kernel:    fs/file.c (fdtable), fs/proc/fd.c
//   vol3:      framework/plugins/linux/lsof.py
//   MemProcFS: vmm/modules/m_proc_handle.c
//
#pragma once
#include "core/types.h"
#include "os/linux/process.h"
#include <string>
#include <vector>

namespace lmpfs {
class Engine;
}

namespace lmpfs::linux {

struct OpenFd {
    int          fd;
    VAddr        file_va;
    std::string  target;     // "/path/to/file" or "socket:[123]" or "anon_inode:foo"
    u64          mode;       // file->f_mode (read/write/exec bits)
    u64          flags;      // file->f_flags
    u64          pos;        // file->f_pos (seek position)
};

// Walk a single process's fd table.
std::vector<OpenFd> enumerate_fds(const Engine& eng, const Process& p);

// /proc/<pid>/fd_table.txt — formatted overview file
ByteBuf format_fd_table(const Engine& eng, const Process& p);

} // namespace lmpfs::linux
