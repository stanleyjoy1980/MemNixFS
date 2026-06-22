// sys_module.h — builds the `/sys/` subtree (system-wide kernel views).
//
// Tier 2 features (kallsyms, modules, dmesg, …) will live under here. For now
// it has just `banner.txt` and `dtb.txt`, which serve double duty as smoke
// tests for the kernel page-table walker: if `banner.txt` returns the real
// kernel banner, kernel-VA → PA translation works.
//
// References:
//   MemProcFS:  m_sys.c (registers /sys/), m_sys_sysinfo.c
//   vol3:       framework/plugins/linux/* (kallsyms.py, lsmod.py, kmsg.py …)
//
#pragma once
#include "vfs/vfs.h"

namespace lmpfs {

class Engine;

namespace vfs {

NodePtr build_sys_tree(const Engine& eng);

} // namespace vfs
} // namespace lmpfs
