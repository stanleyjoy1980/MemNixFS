// integrity_checks.cpp — see header.
#include "os/linux/integrity_checks.h"
#include "os/linux/kva_reader.h"
#include "os/linux/modules.h"
#include "app/engine.h"
#include "symbols/isf_symbols.h"
#include "symbols/kallsyms.h"
#include "core/log.h"
#include <fmt/format.h>
#include <algorithm>
#include <cstring>
#include <map>
#include <unordered_map>
#include <unordered_set>

namespace lmpfs::linux {

namespace {

// ---------------- shared pointer-validation helpers ----------------

// Same recipe as in check_syscall.cpp — kept private so each check
// can vary the policy without affecting siblings.
struct AddrIndex {
    std::vector<std::size_t> idx;
};
AddrIndex build_addr_index(const KallsymsResult& ks) {
    AddrIndex a;
    a.idx.resize(ks.symbols.size());
    for (std::size_t i = 0; i < ks.symbols.size(); ++i) a.idx[i] = i;
    std::sort(a.idx.begin(), a.idx.end(),
        [&](std::size_t i, std::size_t j) {
            return ks.symbols[i].address < ks.symbols[j].address;
        });
    return a;
}
const KallsymsEntry* find_sym_below(const KallsymsResult& ks,
                                     const AddrIndex& a, VAddr addr) {
    if (a.idx.empty()) return nullptr;
    auto it = std::upper_bound(a.idx.begin(), a.idx.end(), addr,
        [&](VAddr v, std::size_t i) { return v < ks.symbols[i].address; });
    if (it == a.idx.begin()) return nullptr;
    --it;
    return &ks.symbols[*it];
}
struct TextBounds { VAddr start = 0; VAddr end = 0; bool ok = false; };
// "Kernel-image" bounds — wide enough to include .init.text (e.g.
// `early_idt_handler_array` that the IDT keeps pointing at even at
// runtime), .rodata, and __ksymtab. We try `_text` → `_end` first
// (full image), then `_stext` → `_etext` (just .text), then fall back
// to a generous x86_64 canonical range.
TextBounds resolve_text_bounds(const KallsymsResult& ks) {
    TextBounds b{};
    auto try_pair = [&](const char* lo, const char* hi) {
        auto a = ks.by_name.find(lo);
        auto z = ks.by_name.find(hi);
        if (a != ks.by_name.end() && z != ks.by_name.end()) {
            VAddr s = ks.symbols[a->second].address;
            VAddr e = ks.symbols[z->second].address;
            if (e > s) { b.start = s; b.end = e; b.ok = true; return true; }
        }
        return false;
    };
    if (try_pair("_text", "_end"))    return b;
    if (try_pair("_stext", "_etext")) return b;
    b.start = 0xffffffff80000000ULL;
    b.end   = 0xffffffffa0000000ULL;
    return b;
}

bool is_canonical_kernel_ptr(VAddr addr) {
    return addr >= 0xffffffff80000000ULL;
}

// Classify a single kernel function pointer.
PtrAudit classify_ptr(const Engine& eng, const KallsymsResult& ks,
                       const AddrIndex& ai, const TextBounds& tb,
                       const std::string& slot, VAddr addr)
{
    PtrAudit p{};
    p.slot_name = slot;
    p.addr      = addr;
    if (addr == 0) {
        p.status = PtrAudit::NULL_OK;
        p.note   = "NULL — handler not implemented";
        return p;
    }
    if (!is_canonical_kernel_ptr(addr)) {
        p.status = PtrAudit::SUSPICIOUS;
        p.note   = fmt::format("non-canonical pointer value {:#x}; source "
                                "structure may be unreadable or not a "
                                "function-pointer table, so no hook conclusion "
                                "is made from this slot", addr);
        return p;
    }
    if (addr < tb.start || addr >= tb.end) {
        p.status = PtrAudit::HOOKED;
        p.note   = fmt::format("entry @ {:#x} is OUTSIDE kernel text "
                                "[{:#x}..{:#x}]", addr, tb.start, tb.end);
        if (auto* s = find_sym_below(ks, ai, addr)) {
            p.resolved = s->name;
            p.distance = addr - s->address;
        }
        return p;
    }
    const KallsymsEntry* s = find_sym_below(ks, ai, addr);
    if (!s) {
        p.status = PtrAudit::SUSPICIOUS;
        p.note   = "kallsyms can't resolve a containing symbol";
        return p;
    }
    p.resolved = s->name;
    p.distance = addr - s->address;
    if (p.distance > 0x10000) {
        p.status = PtrAudit::SUSPICIOUS;
        p.note   = fmt::format("{:#x} bytes past nearest symbol — outside "
                                "any known function", p.distance);
        return p;
    }
    p.status = PtrAudit::OK;
    (void)eng;
    return p;
}

const char* status_str(PtrAudit::Status s) {
    switch (s) {
    case PtrAudit::OK:         return "OK";
    case PtrAudit::NULL_OK:    return "(null)";
    case PtrAudit::SUSPICIOUS: return "SUSPICIOUS";
    case PtrAudit::HOOKED:     return "★ HOOKED";
    }
    return "?";
}

// Read a NUL-terminated C string at `va`, max `maxlen`, kernel-VA.
std::string read_kstr(const Engine& eng, VAddr va, std::size_t maxlen) {
    if (va == 0) return {};
    return kva_read_cstr(eng, va, maxlen);
}

// tty_operations slot names + offsets (kept in lock-step with ISF; if a
// future kernel reorders these, the ISF reads at the bottom of
// audit_tty_drivers() will pick up the new layout).
struct TtyOpsSlot { const char* name; const char* isf_field; };
constexpr TtyOpsSlot kTtyOpsSlots[] = {
    {"lookup",          "lookup"},
    {"install",         "install"},
    {"remove",          "remove"},
    {"open",            "open"},
    {"close",           "close"},
    {"shutdown",        "shutdown"},
    {"cleanup",         "cleanup"},
    {"write",           "write"},
    {"put_char",        "put_char"},
    {"flush_chars",     "flush_chars"},
    {"write_room",      "write_room"},
    {"chars_in_buffer", "chars_in_buffer"},
    {"ioctl",           "ioctl"},
    {"compat_ioctl",    "compat_ioctl"},
    {"set_termios",     "set_termios"},
    {"throttle",        "throttle"},
    {"unthrottle",      "unthrottle"},
    {"stop",            "stop"},
    {"start",           "start"},
    {"hangup",          "hangup"},
    {"break_ctl",       "break_ctl"},
    {"flush_buffer",    "flush_buffer"},
    {"ldisc_ok",        "ldisc_ok"},
    {"set_ldisc",       "set_ldisc"},
    {"wait_until_sent", "wait_until_sent"},
    {"send_xchar",      "send_xchar"},
    {"tiocmget",        "tiocmget"},
    {"tiocmset",        "tiocmset"},
    {"resize",          "resize"},
    {"get_icount",      "get_icount"},
    {"get_serial",      "get_serial"},
    {"set_serial",      "set_serial"},
    {"show_fdinfo",     "show_fdinfo"},
    {"poll_init",       "poll_init"},
    {"poll_get_char",   "poll_get_char"},
    {"poll_put_char",   "poll_put_char"},
    {"proc_show",       "proc_show"},
};

} // anonymous

// =====================================================================
// tty_check
// =====================================================================

std::vector<TtyDriverAudit> audit_tty_drivers(const Engine& eng) {
    std::vector<TtyDriverAudit> out;
    const auto& isf = eng.isf();
    const auto& ks  = eng.kallsyms();
    if (!ks.ok) {
        log::warn("tty_check: kallsyms not extracted");
        return out;
    }
    auto* tty_sym = isf.find_symbol("tty_drivers");
    if (!tty_sym) {
        log::warn("tty_check: ISF lacks tty_drivers");
        return out;
    }

    // Driver-list offset within tty_driver
    u64 td_tty_drivers_off = 0xa8;
    u64 td_ops_off         = 0xa0;
    u64 td_name_off        = 0x20;
    u64 td_driver_name_off = 0x18;
    try {
        td_tty_drivers_off = isf.field_offset("tty_driver", "tty_drivers");
        td_ops_off         = isf.field_offset("tty_driver", "ops");
        td_name_off        = isf.field_offset("tty_driver", "name");
        td_driver_name_off = isf.field_offset("tty_driver", "driver_name");
    } catch (const std::exception& e) {
        log::warn("tty_check: ISF missing tty_driver field — {}", e.what());
        return out;
    }

    // Resolve every tty_operations slot's offset from the ISF (so kernel
    // version changes don't silently shift readings).
    std::vector<std::pair<std::string, u64>> ops_offsets;
    for (const auto& s : kTtyOpsSlots) {
        try {
            ops_offsets.emplace_back(s.name,
                isf.field_offset("tty_operations", s.isf_field));
        } catch (...) { /* slot absent in this kernel — skip */ }
    }

    AddrIndex   addr_idx = build_addr_index(ks);
    TextBounds  tb       = resolve_text_bounds(ks);

    // Walk the tty_drivers list. The head is the symbol itself; its
    // .next/.prev form a list_head, and each member is a struct tty_driver
    // linked via .tty_drivers (offset 0xa8).
    VAddr head_va = tty_sym->address;
    VAddr cur = 0;
    if (!kva_read_pod(eng, head_va, cur)) {
        log::warn("tty_check: can't read tty_drivers list head");
        return out;
    }
    int guard = 0;
    while (cur != 0 && cur != head_va && guard++ < 256) {
        VAddr drv = cur - td_tty_drivers_off;
        TtyDriverAudit a{};
        a.driver_va = drv;
        // Read driver_name + name (both char*).
        VAddr p = 0;
        if (kva_read_pod(eng, drv + td_driver_name_off, p) && p)
            a.driver_name = read_kstr(eng, p, 32);
        if (kva_read_pod(eng, drv + td_name_off, p) && p)
            a.name = read_kstr(eng, p, 32);
        kva_read_pod(eng, drv + td_ops_off, a.ops_va);

        // Audit every ops slot we know about.
        if (a.ops_va != 0) {
            for (const auto& [slot, off] : ops_offsets) {
                VAddr fptr = 0;
                kva_read_pod(eng, a.ops_va + off, fptr);
                a.ops.push_back(classify_ptr(eng, ks, addr_idx, tb,
                                              slot, fptr));
            }
        }

        out.push_back(std::move(a));

        VAddr nxt = 0;
        if (!kva_read_pod(eng, cur, nxt) || nxt == cur) break;
        cur = nxt;
    }
    log::info("tty_check: audited {} tty drivers", out.size());
    return out;
}

ByteBuf format_tty_check(const Engine& eng) {
    auto drivers = audit_tty_drivers(eng);
    std::string out;
    out.reserve(16 * 1024);

    std::size_t total = 0, hooked = 0, susp = 0;
    for (const auto& d : drivers)
        for (const auto& p : d.ops) {
            if (p.status == PtrAudit::HOOKED)        ++hooked;
            else if (p.status == PtrAudit::SUSPICIOUS) ++susp;
            ++total;
        }

    out += fmt::format(
        "# tty_check — every tty_driver's tty_operations vtable\n"
        "# {} driver(s) walked, {} slots audited: {} ★ HOOKED, {} SUSPICIOUS\n"
        "# Keyloggers commonly hook tty_operations.open / ioctl / write.\n"
        "#\n",
        drivers.size(), total, hooked, susp);
    if (drivers.empty()) {
        out += "; (tty_drivers list empty or unreadable)\n";
        return ByteBuf(out.begin(), out.end());
    }
    for (const auto& d : drivers) {
        out += fmt::format("\n=== {} (driver_name=\"{}\" @ {:#x}, ops @ {:#x}) ===\n",
                           d.name.empty() ? "?" : d.name,
                           d.driver_name, d.driver_va, d.ops_va);
        for (const auto& p : d.ops) {
            // Show NULL_OK on one compact line; SUSPICIOUS/HOOKED with a note.
            if (p.status == PtrAudit::NULL_OK) {
                out += fmt::format("  {:<18}  (null)\n", p.slot_name);
                continue;
            }
            out += fmt::format("  {:<18}  {:<11}  {:#016x}  {}\n",
                               p.slot_name, status_str(p.status), p.addr,
                               p.resolved.empty() ? "<unknown>" : p.resolved);
            if (p.status != PtrAudit::OK && !p.note.empty())
                out += fmt::format("                      └── {}\n", p.note);
        }
    }
    return ByteBuf(out.begin(), out.end());
}

// =====================================================================
// keyboard_notifiers
// =====================================================================

std::vector<KbdNotifierAudit> audit_keyboard_notifiers(const Engine& eng) {
    std::vector<KbdNotifierAudit> out;
    const auto& isf = eng.isf();
    const auto& ks  = eng.kallsyms();
    if (!ks.ok) {
        log::warn("keyboard_notifiers: kallsyms not extracted");
        return out;
    }
    auto* sym = isf.find_symbol("keyboard_notifier_list");
    if (!sym) {
        // fallback: kallsyms may have it even when ISF doesn't.
        auto it = ks.by_name.find("keyboard_notifier_list");
        if (it == ks.by_name.end()) {
            log::warn("keyboard_notifiers: keyboard_notifier_list not found");
            return out;
        }
    }

    u64 anh_head_off = 0x8;     // atomic_notifier_head.head
    u64 nb_call_off  = 0x0;     // notifier_block.notifier_call
    u64 nb_next_off  = 0x8;     // notifier_block.next
    u64 nb_prio_off  = 0x10;    // notifier_block.priority
    try {
        anh_head_off = isf.field_offset("atomic_notifier_head", "head");
        nb_call_off  = isf.field_offset("notifier_block", "notifier_call");
        nb_next_off  = isf.field_offset("notifier_block", "next");
        nb_prio_off  = isf.field_offset("notifier_block", "priority");
    } catch (...) {}

    VAddr list_va = sym ? sym->address
                        : ks.symbols[ks.by_name.at("keyboard_notifier_list")].address;
    VAddr first = 0;
    if (!kva_read_pod(eng, list_va + anh_head_off, first)) {
        log::warn("keyboard_notifiers: can't read .head");
        return out;
    }

    AddrIndex  addr_idx = build_addr_index(ks);
    TextBounds tb       = resolve_text_bounds(ks);

    VAddr cur = first;
    int guard = 0;
    while (cur != 0 && guard++ < 64) {
        KbdNotifierAudit a{};
        a.block_va = cur;
        VAddr fn = 0;
        kva_read_pod(eng, cur + nb_call_off, fn);
        kva_read_pod(eng, cur + nb_prio_off, a.priority);
        a.call = classify_ptr(eng, ks, addr_idx, tb,
            fmt::format("notifier #{}", out.size()), fn);
        out.push_back(std::move(a));
        VAddr nxt = 0;
        if (!kva_read_pod(eng, cur + nb_next_off, nxt) || nxt == cur) break;
        cur = nxt;
    }
    log::info("keyboard_notifiers: {} entries in chain", out.size());
    return out;
}

ByteBuf format_keyboard_notifiers(const Engine& eng) {
    auto entries = audit_keyboard_notifiers(eng);
    std::size_t hooked = 0, susp = 0;
    for (const auto& e : entries) {
        if (e.call.status == PtrAudit::HOOKED)        ++hooked;
        else if (e.call.status == PtrAudit::SUSPICIOUS) ++susp;
    }
    std::string out;
    out.reserve(2 * 1024);
    out += fmt::format(
        "# keyboard_notifiers — chain of notifier_blocks called on every\n"
        "# keyboard event. A rogue notifier_call is the classic kernel\n"
        "# keylogger primitive.\n"
        "#\n"
        "# {} entries in keyboard_notifier_list: {} ★ HOOKED, {} SUSPICIOUS\n"
        "#\n"
        "# block_va             priority   status       notifier_call\n"
        "# -------------------- --------- ------------ -------------\n",
        entries.size(), hooked, susp);
    for (const auto& e : entries) {
        out += fmt::format("  {:#018x}  {:>8}   {:<11}  {:#016x}  {}\n",
                           e.block_va, e.priority, status_str(e.call.status),
                           e.call.addr,
                           e.call.resolved.empty() ? "<unknown>" : e.call.resolved);
        if (e.call.status != PtrAudit::OK && !e.call.note.empty())
            out += fmt::format("                                          └── {}\n",
                               e.call.note);
    }
    return ByteBuf(out.begin(), out.end());
}

// =====================================================================
// Public wrappers for the shared pointer-audit helpers — let `tracing.cpp`
// and any future plugin reuse classify_ptr without re-implementing the
// kallsyms + text-bounds setup.
// =====================================================================

PointerAuditCtx build_ptr_audit_ctx(const Engine& eng) {
    const auto& ks = eng.kallsyms();
    PointerAuditCtx ctx{};
    AddrIndex   ai = build_addr_index(ks);
    ctx.addr_idx   = std::move(ai.idx);
    TextBounds  tb = resolve_text_bounds(ks);
    ctx.text_start = tb.start;
    ctx.text_end   = tb.end;
    ctx.text_ok    = tb.ok;
    return ctx;
}

PtrAudit classify_kernel_ptr(const Engine& eng,
                              const PointerAuditCtx& ctx,
                              const std::string& slot,
                              VAddr addr)
{
    AddrIndex  a;  a.idx = ctx.addr_idx;
    TextBounds t{};
    t.start = ctx.text_start; t.end = ctx.text_end; t.ok = ctx.text_ok;
    return classify_ptr(eng, eng.kallsyms(), a, t, slot, addr);
}

// =====================================================================
// check_idt
// =====================================================================

std::vector<IdtEntry> audit_idt(const Engine& eng) {
    std::vector<IdtEntry> out;
    const auto& isf = eng.isf();
    const auto& ks  = eng.kallsyms();
    if (!ks.ok) {
        log::warn("check_idt: kallsyms not extracted");
        return out;
    }
    auto* sym = isf.find_symbol("idt_table");
    if (!sym) {
        auto it = ks.by_name.find("idt_table");
        if (it == ks.by_name.end()) {
            log::warn("check_idt: idt_table symbol not found");
            return out;
        }
    }
    VAddr idt_va = sym ? sym->address
                       : ks.symbols[ks.by_name.at("idt_table")].address;

    AddrIndex   ai = build_addr_index(ks);
    TextBounds  tb = resolve_text_bounds(ks);
    log::info("check_idt: idt_table @ {:#x}", idt_va);

    // 256 entries × 16 bytes (gate_struct on x86_64).
    std::vector<u8> raw(256 * 16, 0);
    if (!kva_read(eng, idt_va, raw.data(), raw.size())) {
        log::warn("check_idt: failed to read IDT");
        return out;
    }
    for (int v = 0; v < 256; ++v) {
        const u8* p = raw.data() + v * 16;
        u16 off_lo = (u16)(p[0] | (p[1] << 8));
        u16 off_mid = (u16)(p[6] | (p[7] << 8));
        u32 off_hi;
        std::memcpy(&off_hi, p + 8, 4);
        VAddr handler = (VAddr(off_hi) << 32) | (VAddr(off_mid) << 16) | off_lo;
        // High 16 bits of a kernel pointer on x86_64 are always 0xFFFF;
        // canonicalise back from the truncated form the gate stores.
        if (handler && (handler & 0x0000800000000000ULL))
            handler |= 0xFFFF000000000000ULL;
        IdtEntry e{};
        e.vector  = (u8)v;
        e.handler = handler;
        e.audit   = classify_ptr(eng, ks, ai, tb,
                                  fmt::format("vec {}", v), handler);
        out.push_back(std::move(e));
    }
    return out;
}

ByteBuf format_check_idt(const Engine& eng) {
    auto entries = audit_idt(eng);
    std::size_t hooked = 0, susp = 0;
    for (const auto& e : entries) {
        if (e.audit.status == PtrAudit::HOOKED)        ++hooked;
        else if (e.audit.status == PtrAudit::SUSPICIOUS) ++susp;
    }
    std::string out;
    out.reserve(16 * 1024);
    out += fmt::format(
        "# check_idt — Interrupt Descriptor Table integrity\n"
        "# 256 entries scanned: {} ★ HOOKED, {} SUSPICIOUS\n"
        "# (HOOKED = handler points outside kernel text;\n"
        "#  expected names: asm_exc_*, asm_sysvec_*, irq_entries_start, …)\n"
        "#\n"
        "# vec  handler              status       symbol (+offset)\n"
        "# --- -------------------- ----------- ----------------------\n",
        hooked, susp);
    for (const auto& e : entries) {
        if (e.handler == 0 && e.audit.status == PtrAudit::NULL_OK) {
            // Don't list 0-handlers (legit: many vectors are unused gates).
            continue;
        }
        std::string sym = e.audit.resolved.empty()
            ? "<unknown>"
            : (e.audit.distance == 0 ? e.audit.resolved
                : fmt::format("{} +{:#x}", e.audit.resolved, e.audit.distance));
        const char* s =
            e.audit.status == PtrAudit::HOOKED     ? "★ HOOKED   " :
            e.audit.status == PtrAudit::SUSPICIOUS ? "  SUSPICIOUS" :
                                                     "  OK        ";
        out += fmt::format(" {:>3}  {:#018x}  {}  {}\n",
                           e.vector, e.handler, s, sym);
        if (e.audit.status != PtrAudit::OK && !e.audit.note.empty())
            out += fmt::format("                              └── {}\n",
                               e.audit.note);
    }
    return ByteBuf(out.begin(), out.end());
}

// =====================================================================
// check_afinfo
// =====================================================================

namespace {

// Every /proc/net protocol with a well-known seq_ops symbol. If a kernel
// lacks one of these (rare), we just skip it.
constexpr const char* kAfinfoSyms[] = {
    "tcp4_seq_ops", "tcp6_seq_ops",
    "udp_seq_ops",  "udp6_seq_ops",
    "udplite_seq_ops", "udplite6_seq_ops",
    "arp_seq_ops",  "raw_seq_ops",
    "unix_seq_ops", "packet_seq_ops",
};

constexpr const char* kSeqSlotNames[] = { "start", "stop", "next", "show" };

} // anonymous

std::vector<AfinfoAudit> audit_afinfo(const Engine& eng) {
    std::vector<AfinfoAudit> out;
    const auto& ks = eng.kallsyms();
    if (!ks.ok) { log::warn("check_afinfo: kallsyms not extracted"); return out; }

    AddrIndex   ai = build_addr_index(ks);
    TextBounds  tb = resolve_text_bounds(ks);

    for (const char* name : kAfinfoSyms) {
        auto it = ks.by_name.find(name);
        if (it == ks.by_name.end()) continue;
        VAddr ops_va = ks.symbols[it->second].address;
        AfinfoAudit a{};
        // Strip the trailing "_seq_ops" for a clean protocol label.
        std::string n = name;
        if (n.size() > 8 && n.substr(n.size() - 8) == "_seq_ops")
            n.resize(n.size() - 8);
        a.proto      = std::move(n);
        a.seq_ops_va = ops_va;
        // seq_operations is 4 function pointers (start, stop, next, show)
        // at offsets 0/8/16/24 (= 0x20 total).
        for (int slot = 0; slot < 4; ++slot) {
            VAddr fn = 0;
            kva_read_pod(eng, ops_va + slot * 8, fn);
            a.slots.push_back(classify_ptr(eng, ks, ai, tb,
                kSeqSlotNames[slot], fn));
        }
        out.push_back(std::move(a));
    }
    log::info("check_afinfo: audited {} /proc/net protocols", out.size());
    return out;
}

ByteBuf format_check_afinfo(const Engine& eng) {
    auto audits = audit_afinfo(eng);
    std::size_t hooked = 0, susp = 0;
    for (const auto& a : audits)
        for (const auto& s : a.slots) {
            if (s.status == PtrAudit::HOOKED)        ++hooked;
            else if (s.status == PtrAudit::SUSPICIOUS) ++susp;
        }
    std::string out;
    out.reserve(4 * 1024);
    out += fmt::format(
        "# check_afinfo — /proc/net seq_operations vtable audit\n"
        "# {} protocols audited, {} ★ HOOKED, {} SUSPICIOUS\n"
        "# Network-stack rootkits hook seq_operations.show to hide\n"
        "# connections from `netstat`/`ss`.\n"
        "#\n",
        audits.size(), hooked, susp);
    for (const auto& a : audits) {
        out += fmt::format("\n=== {} seq_ops @ {:#x} ===\n", a.proto, a.seq_ops_va);
        for (const auto& s : a.slots) {
            const char* st =
                s.status == PtrAudit::HOOKED     ? "★ HOOKED   " :
                s.status == PtrAudit::SUSPICIOUS ? "  SUSPICIOUS" :
                s.status == PtrAudit::NULL_OK    ? "  (null)    " :
                                                   "  OK        ";
            std::string sym = s.resolved.empty()
                ? "<unknown>"
                : (s.distance == 0 ? s.resolved
                    : fmt::format("{} +{:#x}", s.resolved, s.distance));
            out += fmt::format("  {:<6}  {}  {:#018x}  {}\n",
                               s.slot_name, st, s.addr, sym);
            if (s.status != PtrAudit::OK && s.status != PtrAudit::NULL_OK
                && !s.note.empty())
                out += fmt::format("                                              └── {}\n",
                                   s.note);
        }
    }
    return ByteBuf(out.begin(), out.end());
}

// =====================================================================
// check_creds
// =====================================================================

std::vector<CredShare> audit_creds(const Engine& eng) {
    std::vector<CredShare> out;
    const auto& isf = eng.isf();
    u64 ts_cred_off = 0, ts_real_cred_off = 0, cred_uid_off = 0, cred_gid_off = 0;
    try {
        ts_cred_off      = isf.field_offset("task_struct", "cred");
        ts_real_cred_off = isf.field_offset("task_struct", "real_cred");
    } catch (const std::exception& e) {
        log::warn("check_creds: ISF lacks task_struct field — {}", e.what());
        return out;
    }
    // cred.uid / gid are kuid_t/kgid_t (a single u32 wrapper each).
    cred_uid_off = 0x8;
    cred_gid_off = 0xc;
    try {
        cred_uid_off = isf.field_offset("cred", "uid");
        cred_gid_off = isf.field_offset("cred", "gid");
    } catch (...) {}

    // Map cred_va → list of pids that point at it.
    std::map<VAddr, CredShare> by_cred;
    for (const auto& p : eng.processes()) {
        VAddr cred_va = 0;
        if (!kva_read_pod(eng, p.task_va + ts_real_cred_off, cred_va))
            kva_read_pod(eng, p.task_va + ts_cred_off, cred_va);
        if (cred_va == 0) continue;
        auto& cs = by_cred[cred_va];
        if (cs.cred_va == 0) {
            cs.cred_va = cred_va;
            kva_read_pod(eng, cred_va + cred_uid_off, cs.uid);
            kva_read_pod(eng, cred_va + cred_gid_off, cs.gid);
        }
        cs.pids.push_back(p.pid);
    }

    for (auto& [_, cs] : by_cred) {
        // Heuristic: a cred shared by >1 thread group is suspicious unless
        // it's `init_cred` (the kernel reuses init_cred for many kthreads).
        // We can't easily check init_cred here without a kallsyms lookup,
        // so flag any uid=0 cred shared by more than one tgid AS LONG AS
        // at least one of those tgids has a user mm (i.e. isn't a kthread).
        if (cs.uid == 0 && cs.pids.size() > 1) {
            // Count user-mode processes among sharers.
            std::size_t user_procs = 0;
            for (u32 pid : cs.pids) {
                for (const auto& p : eng.processes()) {
                    if (p.pid == pid && p.mm != 0) { ++user_procs; break; }
                }
            }
            if (user_procs > 1) {
                cs.suspicious = true;
                cs.note = fmt::format(
                    "{} user processes share this root-cred — unusual "
                    "(legitimate sharing is mostly between init_cred and "
                    "kthreads)", user_procs);
            }
        }
        out.push_back(cs);
    }
    // Sort: suspicious first, then by uid asc.
    std::sort(out.begin(), out.end(),
        [](const CredShare& a, const CredShare& b) {
            if (a.suspicious != b.suspicious) return a.suspicious;
            if (a.uid != b.uid) return a.uid < b.uid;
            return a.pids.size() > b.pids.size();
        });
    return out;
}

ByteBuf format_check_creds(const Engine& eng) {
    auto creds = audit_creds(eng);
    std::size_t susp = 0;
    for (const auto& c : creds) if (c.suspicious) ++susp;
    std::string out;
    out.reserve(8 * 1024);
    out += fmt::format(
        "# check_creds — task.real_cred sharing audit\n"
        "# {} unique cred pointers across visible tasks, {} flagged.\n"
        "# Looks for non-kthread tasks sharing a root cred — the classic\n"
        "# credential-stealer pattern.\n"
        "#\n"
        "# uid    gid    cred_va              n_sharers   status     pids\n"
        "# ----- ----- --------------------- ----------- ---------- ----\n",
        creds.size(), susp);
    for (const auto& c : creds) {
        std::string pid_str;
        for (std::size_t i = 0; i < c.pids.size() && i < 12; ++i) {
            if (i) pid_str += ",";
            pid_str += fmt::format("{}", c.pids[i]);
        }
        if (c.pids.size() > 12) pid_str += fmt::format(",… (+{})",
                                                       c.pids.size() - 12);
        const char* st = c.suspicious ? "★ SUSP    " : "  OK      ";
        out += fmt::format("  {:>4}  {:>4}  {:#018x}  {:>9}    {}  {}\n",
                           c.uid, c.gid, c.cred_va, c.pids.size(), st, pid_str);
        if (c.suspicious && !c.note.empty())
            out += fmt::format("                                                  └── {}\n",
                               c.note);
    }
    return ByteBuf(out.begin(), out.end());
}

// =====================================================================
// check_modules — cross-view: `modules` list vs. `mod_tree` rb-tree
// =====================================================================

namespace {

// Recursively walk one rb_tree half of mod_tree's latch_tree.
//
// Container chain (when walking half `latch_half`):
//   rb_node  →  is latch_tree_node.node[latch_half]  (offset = latch_half * 0x18)
//                ltn_va = rb_node_va - latch_half * 0x18
//   ltn      →  embedded inside mod_tree_node.node   (offset = mtn_node_off)
//                mtn_va = ltn_va - mtn_node_off
//   mtn.mod  →  struct module * at mtn_va + mtn_mod_off
//
// mod_tree is a latch_tree (kernel/locking/latch.h) — TWO parallel rb-trees
// that share data; readers pick one based on a seqlock. For our purposes
// they contain the same entries, so we walk ONLY half 0. (Walking both
// AND trying both `latch_half` values per node creates 4× the entries,
// half of them garbage from wrong container_of arithmetic.)
void walk_rb_tree_for_modules(const Engine& eng,
                               VAddr rb_node_va,
                               std::unordered_set<VAddr>& visited_nodes,
                               std::unordered_set<VAddr>& mod_ptrs,
                               int latch_half,        // 0 or 1
                               u64 mtn_node_off,
                               u64 mtn_mod_off,
                               int depth = 0)
{
    if (rb_node_va == 0 || depth > 64) return;
    if (!visited_nodes.insert(rb_node_va).second) return;

    // rb_node: __rb_parent_color @ 0, rb_right @ 8, rb_left @ 16.
    VAddr right = 0, left = 0;
    kva_read_pod(eng, rb_node_va + 8,  right);
    kva_read_pod(eng, rb_node_va + 16, left);

    u64 ltn_off = (u64)latch_half * 0x18;
    if (rb_node_va > ltn_off) {
        VAddr ltn_va = rb_node_va - ltn_off;
        if (ltn_va > mtn_node_off) {
            VAddr mtn_va = ltn_va - mtn_node_off;
            VAddr mod_va = 0;
            if (kva_read_pod(eng, mtn_va + mtn_mod_off, mod_va) &&
                mod_va >= 0xffff800000000000ULL)
                mod_ptrs.insert(mod_va);
        }
    }
    walk_rb_tree_for_modules(eng, left,  visited_nodes, mod_ptrs,
                              latch_half, mtn_node_off, mtn_mod_off, depth + 1);
    walk_rb_tree_for_modules(eng, right, visited_nodes, mod_ptrs,
                              latch_half, mtn_node_off, mtn_mod_off, depth + 1);
}

} // anonymous

std::vector<ModuleCrossView> audit_modules_cross(const Engine& eng) {
    std::vector<ModuleCrossView> out;
    const auto& isf = eng.isf();
    const auto& ks  = eng.kallsyms();

    // Set of module VAs from the `modules` linked-list walk.
    auto visible = enumerate_modules(eng);
    std::unordered_map<VAddr, std::string> list_by_va;
    // Per-module: count kallsyms entries that fall inside any of its mem regions.
    std::unordered_map<VAddr, u32> kallsyms_per_mod;
    // Sorted (range_start, range_end, mod_va) for fast range lookup.
    struct ModRange { VAddr start; VAddr end; VAddr mod_va; };
    std::vector<ModRange> ranges;
    for (const auto& m : visible) {
        list_by_va[m.module_va] = m.name;
        kallsyms_per_mod[m.module_va] = 0;
        for (const auto& mem : m.mem) {
            if (mem.base == 0 || mem.size == 0) continue;
            ranges.push_back({ mem.base, mem.base + mem.size, m.module_va });
        }
    }
    std::sort(ranges.begin(), ranges.end(),
        [](const ModRange& a, const ModRange& b) { return a.start < b.start; });

    // Third source: count kallsyms symbols in each module's mem range
    // (a module visible in kallsyms but NOT in `modules` list / mod_tree
    // would be a vol3-style modxview hit; here we just expose the count
    // alongside the existing list/tree views so the analyst can see
    // attribution and orphans together).
    constexpr u64 kModBase = 0xffffffffc0000000ULL;
    u32 orphan_syms = 0;
    if (ks.ok && !ranges.empty()) {
        for (const auto& s : ks.symbols) {
            if (s.address < kModBase) continue;
            // Binary search for the range containing s.address.
            auto it = std::upper_bound(ranges.begin(), ranges.end(), s.address,
                [](VAddr a, const ModRange& r) { return a < r.start; });
            if (it == ranges.begin()) { ++orphan_syms; continue; }
            --it;
            if (s.address >= it->end) { ++orphan_syms; continue; }
            ++kallsyms_per_mod[it->mod_va];
        }
    }
    (void)orphan_syms;   // exposed by hidden_modules; not surfaced here

    // Walk mod_tree's latch_tree — half 0 only (both halves carry the
    // same entries; walking both would just duplicate).
    std::unordered_set<VAddr> tree_ptrs;
    auto* sym = isf.find_symbol("mod_tree");
    if (sym) {
        u64 mtn_mod_off = 0, mtn_node_off = 8;
        try {
            mtn_mod_off  = isf.field_offset("mod_tree_node", "mod");
            mtn_node_off = isf.field_offset("mod_tree_node", "node");
        } catch (...) { /* keep defaults */ }

        // latch_tree_root.tree is an rb_root[2] starting at offset 8
        // (since `seq` is at 0; checked in ISF). Each rb_root is an
        // rb_node* at offset 0.
        VAddr latch_root_0 = sym->address + 8;
        VAddr rb_root = 0;
        kva_read_pod(eng, latch_root_0, rb_root);
        std::unordered_set<VAddr> visited;
        walk_rb_tree_for_modules(eng, rb_root, visited, tree_ptrs,
                                  /*latch_half=*/0, mtn_node_off, mtn_mod_off);
    } else {
        log::warn("check_modules: mod_tree symbol absent — list-only");
    }
    log::info("check_modules: {} via list-walk, {} via mod_tree",
              list_by_va.size(), tree_ptrs.size());

    // v0.20 — fourth source: each module's own kallsyms table
    // (`module.kallsyms` → `mod_kallsyms.num_symtab`). This is the
    // authoritative "module has registered symbols" signal — the built-
    // in kernel kallsyms table almost never has per-module entries.
    //
    // Field offsets are read from the ISF lazily; if absent we silently
    // leave module_kallsyms_ok=false and skip the column.
    u64 mod_kallsyms_off  = 0;
    u64 mks_num_symtab_off = 0;
    bool mod_kallsyms_available = false;
    try {
        mod_kallsyms_off   = isf.field_offset("module", "kallsyms");
        mks_num_symtab_off = isf.field_offset("mod_kallsyms", "num_symtab");
        mod_kallsyms_available = true;
    } catch (const std::exception& e) {
        log::debug("modxview: mod_kallsyms unavailable — {}", e.what());
    }
    auto read_module_kallsyms_count = [&](VAddr mod_va) -> std::pair<bool,u32> {
        if (!mod_kallsyms_available) return { false, 0u };
        VAddr mks_ptr = 0;
        if (!kva_read_pod(eng, mod_va + mod_kallsyms_off, mks_ptr)) return { false, 0u };
        if (mks_ptr == 0) return { true, 0u };   // valid: module without symtab
        u32 n = 0;
        if (!kva_read_pod(eng, mks_ptr + mks_num_symtab_off, n)) return { false, 0u };
        // Sanity-bound to filter wild values from un-mapped reads.
        if (n > 1'000'000u) return { false, 0u };
        return { true, n };
    };

    // Build union by VA.
    std::unordered_set<VAddr> all;
    for (const auto& [va, _] : list_by_va) all.insert(va);
    for (VAddr va : tree_ptrs)              all.insert(va);
    for (VAddr va : all) {
        ModuleCrossView v{};
        v.mod_va        = va;
        auto it         = list_by_va.find(va);
        v.in_list_walk  = it != list_by_va.end();
        v.in_mod_tree   = tree_ptrs.count(va) > 0;
        v.name          = v.in_list_walk ? it->second : "(unknown)";
        auto kit        = kallsyms_per_mod.find(va);
        v.kallsyms_symbols = kit == kallsyms_per_mod.end() ? 0 : kit->second;
        v.in_kallsyms      = v.kallsyms_symbols > 0;
        auto [mk_ok, mk_n] = read_module_kallsyms_count(va);
        v.module_kallsyms_ok  = mk_ok;
        v.module_kallsyms_num = mk_n;
        out.push_back(std::move(v));
    }
    std::sort(out.begin(), out.end(),
        [](const ModuleCrossView& a, const ModuleCrossView& b) {
            // suspect entries (asymmetric across views) first
            int sa = (int)a.in_list_walk + (int)a.in_mod_tree + (int)a.in_kallsyms;
            int sb = (int)b.in_list_walk + (int)b.in_mod_tree + (int)b.in_kallsyms;
            if (sa != sb) return sa < sb;
            return a.name < b.name;
        });
    return out;
}

ByteBuf format_modxview(const Engine& eng) {
    auto views = audit_modules_cross(eng);
    // Asymmetric = present in only one of {list, tree}. The two kallsyms
    // columns are NOT used for the verdict (a properly-loaded module is
    // expected to have both `mod->kallsyms.num_symtab > 0` AND zero hits
    // in the built-in kernel kallsyms table; deviations from EITHER
    // expectation may have legitimate causes — stripped modules, etc.).
    // Surfacing both columns lets the analyst spot e.g. "tree-only with
    // 0 module-symtab" → almost certainly a hidden rootkit, while
    // "list+tree but 0 module-symtab" → likely just CONFIG_KALLSYMS=n
    // on a custom kernel.
    std::size_t both = 0, asym = 0;
    std::size_t mk_ok = 0, mk_zero = 0;
    bool any_mk_ok = false;
    for (const auto& v : views) {
        if (v.in_list_walk && v.in_mod_tree) ++both;
        else if (v.in_list_walk != v.in_mod_tree) ++asym;
        if (v.module_kallsyms_ok) {
            any_mk_ok = true;
            if (v.module_kallsyms_num > 0) ++mk_ok;
            else ++mk_zero;
        }
    }
    std::string out;
    out.reserve(8 * 1024);
    out += fmt::format(
        "# modxview — modules cross-view (v0.20 — authoritative mod_kallsyms).\n"
        "# Four independent sources, two of them used for the verdict:\n"
        "#   list:     `modules` global linked-list walk\n"
        "#   tree:     `mod_tree` latch_tree (rb-tree by address range)\n"
        "#   gsyms:    count of BUILT-IN kallsyms symbols falling in this\n"
        "#             module's mem range. Almost always 0 (built-in\n"
        "#             kallsyms only carries vmlinux symbols).\n"
        "#   msyms:    `module.kallsyms.num_symtab` — the module's OWN\n"
        "#             symbol-table count. This IS the authoritative\n"
        "#             \"module has registered symbols\" signal. v0.20.\n"
        "#             A module visible in list/tree with msyms=0 may be\n"
        "#             a rootkit that scrubbed its symtab; investigate.\n"
        "#\n"
        "# {} modules total: {} symmetric (list + tree both yes), "
        "{} ★ ASYMMETRIC (in only one).\n"
        "# Module-kallsyms: {} with non-zero msyms, {} with msyms=0{}.\n"
        "# Asymmetric entries are the suspicious ones — a rootkit that\n"
        "# unlinks from `modules` to hide from lsmod typically forgets\n"
        "# `mod_tree`.\n"
        "#\n"
        "# list  tree  gsyms  msyms     mod_va               name\n"
        "# ----+-----+-----+--------+--------------------+------\n",
        views.size(), both, asym, mk_ok, mk_zero,
        any_mk_ok ? "" : "  (mod_kallsyms field absent in ISF — column shows '-')");
    for (const auto& v : views) {
        const char* flag = (v.in_list_walk != v.in_mod_tree) ? "★ " : "  ";
        std::string msyms = v.module_kallsyms_ok
            ? fmt::format("{}", v.module_kallsyms_num)
            : std::string("-");
        out += fmt::format("{}  {}  {}  {:>5}  {:>8}  {:#018x}  {}\n",
                           flag,
                           v.in_list_walk ? "yes " : " no ",
                           v.in_mod_tree  ? "yes " : " no ",
                           v.kallsyms_symbols,
                           msyms,
                           v.mod_va, v.name);
    }
    return ByteBuf(out.begin(), out.end());
}

ByteBuf format_check_modules(const Engine& eng) {
    auto views = audit_modules_cross(eng);
    std::size_t list_only = 0, tree_only = 0;
    for (const auto& v : views) {
        if (v.in_list_walk && !v.in_mod_tree) ++list_only;
        else if (!v.in_list_walk && v.in_mod_tree) ++tree_only;
    }
    std::string out;
    out.reserve(8 * 1024);
    out += fmt::format(
        "# check_modules — cross-view: `modules` list vs. `mod_tree` rb-tree\n"
        "# {} unique modules total; {} ★ in list but NOT in tree, "
        "{} ★ in tree but NOT in list.\n"
        "# Asymmetry is suspicious — rootkits unlinking from `modules`\n"
        "# (to hide from lsmod) typically forget mod_tree.\n"
        "#\n"
        "# list  tree  mod_va               name\n"
        "# ----+-----+--------------------+------\n",
        views.size(), list_only, tree_only);
    for (const auto& v : views) {
        const char* status =
            (v.in_list_walk && v.in_mod_tree) ? "OK   " :
            (v.in_list_walk)                  ? "★ LST" :
                                                "★ TRE";
        out += fmt::format("  {}  {}  {:#018x}  {}\n",
                           v.in_list_walk ? "yes  " : " no  ",
                           v.in_mod_tree  ? "yes  " : " no  ",
                           v.mod_va, v.name);
        (void)status;
    }
    return ByteBuf(out.begin(), out.end());
}

} // namespace lmpfs::linux
