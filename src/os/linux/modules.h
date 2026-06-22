// modules.h — enumerate loaded kernel modules from a dump.
//
// Walks the global `modules` list_head, reading each `struct module`'s
// name, state, version, srcversion, and `mem[]` array (the new per-
// section memory descriptors introduced in kernel 6.4+, replacing the
// old core_layout / init_layout).
//
// Forensic value: rootkit detection. Hidden modules (LKM rootkits that
// unlink themselves from `modules` after init) won't show up here, but
// you compare this list against what `/sys/modules/` claims on a live
// system and discrepancies are your starting point.
//
// References:
//   Kernel:    kernel/module/main.c, include/linux/module.h
//   vol3:      framework/plugins/linux/lsmod.py
//   MemProcFS: vmm/modules/m_sys_driver.c (Windows-driver equivalent)
//
#pragma once
#include "core/types.h"
#include <string>
#include <vector>

namespace lmpfs {
class Engine;
}

namespace lmpfs::linux {

// MOD_MEM_NUM_TYPES constants from include/linux/module.h
enum ModMemType : u32 {
    MOD_TEXT = 0,
    MOD_DATA,
    MOD_RODATA,
    MOD_RO_AFTER_INIT,
    MOD_INIT_TEXT,
    MOD_INIT_DATA,
    MOD_INIT_RODATA,
    MOD_MEM_NUM_TYPES,
};

struct ModuleMem {
    VAddr       base;
    u32         size;
};

struct LoadedModule {
    std::string name;
    std::string version;
    std::string srcversion;
    std::string args;
    u32         state;       // 0=LIVE, 1=COMING, 2=GOING, -1=UNFORMED
    VAddr       module_va;   // VA of the struct module itself
    ModuleMem   mem[MOD_MEM_NUM_TYPES];
};

// Walks `modules` list, returns one entry per loaded module.
std::vector<LoadedModule> enumerate_modules(const Engine& eng);

// /sys/modules — short summary listing
ByteBuf format_modules_summary(const Engine& eng);

// /sys/modules/<name>/info.txt — per-module info file
ByteBuf format_module_info(const LoadedModule& m);

} // namespace lmpfs::linux
