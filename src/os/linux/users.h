// users.h — `/sys/users.txt` — UID → username table.
//
// Strategy: read /etc/passwd directly from the reconstructed root-fs
// (`/fs/etc/passwd`). The page-cache layer already exposes the file
// when it's cached at snapshot time. For UIDs that ARE in /etc/passwd
// we get the canonical username + home dir + shell; UIDs that aren't
// (system accounts, container UID mappings, transient users) are
// surfaced separately so analysts see the gap.
//
// References:
//   MPFS: `m_sys_user.c`
//   Kernel: no direct API — the kernel itself doesn't know names, only IDs.
//
#pragma once
#include "core/types.h"
#include "core/stream.h"

namespace lmpfs { class Engine; }

namespace lmpfs::linux {

// /sys/users.txt
ByteBuf format_users(const Engine& eng);

} // namespace lmpfs::linux
