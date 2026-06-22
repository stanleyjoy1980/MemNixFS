// process_views.h — `ps`-style text views over the canonical process list.
//
// The /proc/<pid>-<comm>/ tree already exposes every process individually —
// these files are just convenient flat / hierarchical renderings of the
// same data, the way `ps -ef`, `ps aux`, and `pstree` work on a live box.
//
// /sys/processes/
//     pslist.txt   ← flat `ps -ef`-style listing (PID PPID UID COMM CMDLINE)
//     pstree.txt   ← hierarchical tree by ppid (drawn with box characters)
//     psaux.txt    ← `ps aux`-style with VSZ + cmdline
//
// Cross-ref: vol3 `linux.pslist`, `linux.psaux`, `linux.pstree`;
//            MemProcFS `m_sys_proc.c`.
#pragma once
#include "core/types.h"
#include "core/stream.h"

namespace lmpfs { class Engine; }

namespace lmpfs::linux {

// `ps -ef` style: one process per line. PID, PPID, UID, COMM, CMDLINE.
ByteBuf format_pslist(const Engine& eng);

// `pstree` style: indented hierarchy of (PID COMM). Roots are processes
// whose ppid isn't another visible process (typically pid 0 / 1 / 2).
ByteBuf format_pstree(const Engine& eng);

// `ps aux` style: USER PID %CPU %MEM VSZ COMM CMDLINE. CPU% / MEM% are
// snapshot-impossible (we don't have time deltas) — shown as `-`.
ByteBuf format_psaux(const Engine& eng);

} // namespace lmpfs::linux
