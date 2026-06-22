// sysinfo.h — `/sys/` system-info trio that mirrors classic /proc files.
//
// Three files, all read directly from kernel state (no synthesis, no
// caching — re-reads on every cat):
//
//   /sys/hostname    init_uts_ns.name.nodename
//   /sys/uptime      jiffies_64 / HZ            (HZ assumed 1000; bannerdumps
//                                                the actual config if needed)
//   /sys/mounts      /proc/mounts-format reformat of the existing
//                    enumerate_mounts() output (a more grep-able alternative
//                    to /sys/mountinfo)
//
// References:
//   Kernel: include/linux/utsname.h, kernel/time/timekeeping.c
//   vol3:   boottime.py (close conceptual match)
//
#pragma once
#include "core/types.h"
#include "core/stream.h"

namespace lmpfs { class Engine; }

namespace lmpfs::linux {

ByteBuf format_hostname(const Engine& eng);
ByteBuf format_uptime  (const Engine& eng);
ByteBuf format_mounts  (const Engine& eng);   // /proc/mounts shape

// v0.28 additions
ByteBuf format_cpuinfo (const Engine& eng);   // boot_cpu_data summary
ByteBuf format_meminfo (const Engine& eng);   // totalram_pages + minimal stats
ByteBuf format_iomem   (const Engine& eng);   // iomem_resource tree walk
ByteBuf format_boottime(const Engine& eng);   // wall_now - jiffies/HZ

// Additional Tier-2 items in sysinfo_more.cpp
ByteBuf format_dns          (const Engine& eng);   // /sys/dns.txt
ByteBuf format_pidhashtable (const Engine& eng);   // /sys/pidhashtable
ByteBuf format_arp          (const Engine& eng);   // /sys/net/arp
ByteBuf format_unix_sockets (const Engine& eng);   // /sys/net/unix
ByteBuf format_routes       (const Engine& eng);   // /sys/net/routes
ByteBuf format_netfilter    (const Engine& eng);   // /sys/net/netfilter

} // namespace lmpfs::linux
