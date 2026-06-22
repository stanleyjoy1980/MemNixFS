// integrity_checks.h — kernel function-pointer-table integrity checks.
//
// Both checks share a shape: walk a list of function pointers, validate
// each against the kernel-text range AND kallsyms naming conventions.
//
// tty_check          Walks the `tty_drivers` list. For each driver, audits
//                    every entry in its `tty_operations` vtable (open,
//                    read, write, ioctl, …). Keyloggers commonly hook
//                    tty open/close/ioctl to capture keystrokes.
//                    *(vol3: `linux.tty_check`)*
//
// keyboard_notifiers Walks `keyboard_notifier_list` — the chain of
//                    notifier_blocks called on every keyboard event.
//                    A rogue notifier_block.notifier_call is the
//                    classic kernel-keylogger primitive.
//                    *(vol3: `linux.keyboard_notifiers`)*
//
// Output goes to /sys/findevil/{tty_check,keyboard_notifiers}.txt and
// feeds the /sys/findevil/findevil.txt aggregator.
#pragma once
#include "core/types.h"
#include "core/stream.h"
#include <string>
#include <vector>

namespace lmpfs { class Engine; }

namespace lmpfs::linux {

struct PtrAudit {
    std::string slot_name;      // e.g. "open", "ioctl", or "notifier_block #2"
    VAddr       addr     = 0;
    std::string resolved;       // kallsyms symbol the addr resolves to
    u64         distance = 0;   // bytes past the resolved symbol
    enum Status { OK, NULL_OK, SUSPICIOUS, HOOKED } status = OK;
    std::string note;
};

// ----------------- Shared pointer-validation context -----------------
//
// Multiple plugins audit kernel function pointers against kallsyms +
// kernel-image bounds. They all want the same setup work cached: an
// address-sorted kallsyms index and a TextBounds struct. The
// PointerAuditCtx packages both, build once per request.
struct PointerAuditCtx {
    std::vector<std::size_t> addr_idx;   // kallsyms.symbols indices, sorted by addr
    VAddr  text_start = 0;
    VAddr  text_end   = 0;
    bool   text_ok    = false;
};
// Build the ctx from an Engine. Cheap (single sort over kallsyms).
PointerAuditCtx build_ptr_audit_ctx(const Engine& eng);

// Classify a single kernel function pointer in the same way
// check_syscall / tty_check / etc. do.
PtrAudit classify_kernel_ptr(const Engine& eng,
                              const PointerAuditCtx& ctx,
                              const std::string& slot,
                              VAddr addr);

// ----------------- tty_check -----------------

struct TtyDriverAudit {
    VAddr       driver_va  = 0;
    std::string name;           // tty_driver.name (a char*)
    std::string driver_name;    // tty_driver.driver_name
    VAddr       ops_va     = 0;
    std::vector<PtrAudit> ops;  // one entry per slot of tty_operations
};

std::vector<TtyDriverAudit> audit_tty_drivers(const Engine& eng);

ByteBuf format_tty_check(const Engine& eng);

// ----------------- keyboard_notifiers -----------------

struct KbdNotifierAudit {
    VAddr   block_va = 0;       // notifier_block VA
    i32     priority = 0;
    PtrAudit call;              // the notifier_call function-pointer audit
};

std::vector<KbdNotifierAudit> audit_keyboard_notifiers(const Engine& eng);

ByteBuf format_keyboard_notifiers(const Engine& eng);

// ----------------- check_idt -----------------
//
// Validate every entry of the Interrupt Descriptor Table. Each gate's
// handler should resolve to kernel text (typically named `asm_exc_*`,
// `asm_sysvec_*`, `irq_entries_start+N*...`).
//
// vol3: `linux.check_idt`.

struct IdtEntry {
    u8       vector  = 0;       // 0..255
    VAddr    handler = 0;
    PtrAudit audit;
};
std::vector<IdtEntry> audit_idt(const Engine& eng);
ByteBuf format_check_idt(const Engine& eng);

// ----------------- check_afinfo -----------------
//
// Audit /proc/net's seq_operations vtables — tcp4_seq_ops, tcp6_seq_ops,
// udp_seq_ops, udp6_seq_ops, arp_seq_ops, raw_seq_ops, unix_seq_ops,
// packet_seq_ops. Each has 4 function pointers (start/stop/next/show);
// hooking any of them is a network-stack rootkit primitive.
//
// vol3: `linux.check_afinfo`.

struct AfinfoAudit {
    std::string proto;          // "tcp4", "udp", "arp", …
    VAddr       seq_ops_va = 0;
    std::vector<PtrAudit> slots;     // start / stop / next / show
};
std::vector<AfinfoAudit> audit_afinfo(const Engine& eng);
ByteBuf format_check_afinfo(const Engine& eng);

// ----------------- check_creds -----------------
//
// Detect task_structs sharing a `cred` pointer across thread-group
// boundaries — the classic credential-stealer pattern is a non-root
// task's `cred` swapped to point at init's (root) cred.
//
// vol3: `linux.check_creds`.

struct CredShare {
    VAddr       cred_va = 0;
    u32         uid     = 0;
    u32         gid     = 0;
    std::vector<u32> pids;       // tasks that share this cred (their leader pids)
    bool        suspicious = false;
    std::string note;
};
std::vector<CredShare> audit_creds(const Engine& eng);
ByteBuf format_check_creds(const Engine& eng);

// ----------------- check_modules -----------------
//
// Cross-view of the kernel's module-tracking structures:
//   * `modules` linked list   — what /proc/modules shows
//   * `mod_tree` latch-tree   — address-keyed rb-tree of loaded modules
// A rootkit that unlinks from `modules` to hide from lsmod typically
// forgets to scrub `mod_tree`. Any module ptr in one set but not the
// other is suspicious.
//
// vol3: `linux.check_modules`.

struct ModuleCrossView {
    VAddr       mod_va     = 0;
    std::string name;
    bool        in_list_walk = false;   // visible via `modules` linked list
    bool        in_mod_tree  = false;   // visible via `mod_tree` rb-tree
    bool        in_kallsyms  = false;   // has kallsyms symbols in its mem range
    u32         kallsyms_symbols = 0;   // count of kallsyms entries attributed to it
    // v0.20 — module's own kallsyms (mod->kallsyms->num_symtab). When > 0
    // this is the authoritative "yes, this module has registered symbols"
    // signal — separate from built-in kernel kallsyms attribution above.
    u32         module_kallsyms_num = 0;
    bool        module_kallsyms_ok  = false;   // we successfully read it
};
std::vector<ModuleCrossView> audit_modules_cross(const Engine& eng);
ByteBuf format_check_modules(const Engine& eng);
ByteBuf format_modxview(const Engine& eng);    // 3-source rich view (v0.15)

} // namespace lmpfs::linux
