// dmesg.h — extract the kernel's printk ring buffer from a dump.
//
// Modern kernels (≥ 5.10) use a lockless multi-buffer ring (struct
// printk_ringbuffer) instead of the legacy circular `log_buf`. We
// walk the new format: a descriptor ring (struct prb_desc) + an
// info ring (struct printk_info) + a text-data ring. Each finalized
// descriptor points to a (timestamp, text) record.
//
// References:
//   Kernel:    kernel/printk/printk_ringbuffer.{h,c}
//              kernel/printk/printk.c (the `prb` global)
//   vol3:      framework/plugins/linux/kmsg.py
//   MemProcFS: m_misc_eventlog.c (Windows-equivalent concept)
//
#pragma once
#include "core/types.h"

namespace lmpfs {
class Engine;
}

namespace lmpfs::linux {

// Produces a printable /var/log/kern.log-style listing — one line per
// committed/finalized record. Format:
//   "[%5u.%06u] <text>\n"
// where the timestamp is the kernel's ts_nsec since boot.
//
// On failure (missing symbols, unreadable struct, etc.) returns a
// short diagnostic message instead of an empty buffer — so the user
// always gets *something* in /sys/dmesg explaining what went wrong.
ByteBuf format_dmesg(const Engine& eng);

} // namespace lmpfs::linux
