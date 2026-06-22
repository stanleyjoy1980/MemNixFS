// tracing.cpp — see header.
#include "os/linux/tracing.h"
#include "os/linux/kva_reader.h"
#include "app/engine.h"
#include "symbols/isf_symbols.h"
#include "symbols/kallsyms.h"
#include "core/log.h"
#include <fmt/format.h>
#include <algorithm>

namespace lmpfs::linux {

namespace {

// KPROBE_TABLE_SIZE is hardcoded in include/linux/kprobes.h
constexpr std::size_t kKprobeTableSize = 64;

const char* kprobe_flag_str(u32 f) {
    // KPROBE_FLAG_* bits (from include/linux/kprobes.h)
    if (f == 0) return "";
    static thread_local char buf[64];
    char* p = buf; *p = 0;
    auto add = [&](const char* s) {
        if (p != buf) *p++ = '|';
        while (*s) *p++ = *s++;
        *p = 0;
    };
    if (f & 0x01) add("GONE");
    if (f & 0x02) add("DISABLED");
    if (f & 0x04) add("OPTIMIZED");
    if (f & 0x08) add("FTRACE");
    if (f & 0x10) add("ON_FUNC_ENTRY");
    return buf;
}

// Resolve nearest kallsyms symbol below addr (returns nullptr if none).
const KallsymsEntry* nearest_sym(const KallsymsResult& ks,
                                  const std::vector<std::size_t>& idx,
                                  VAddr addr)
{
    if (idx.empty()) return nullptr;
    auto it = std::upper_bound(idx.begin(), idx.end(), addr,
        [&](VAddr v, std::size_t i) { return v < ks.symbols[i].address; });
    if (it == idx.begin()) return nullptr;
    --it;
    return &ks.symbols[*it];
}

} // anonymous

std::vector<KprobeInfo> enumerate_kprobes(const Engine& eng) {
    std::vector<KprobeInfo> out;
    const auto& isf = eng.isf();
    const auto& ks  = eng.kallsyms();
    if (!ks.ok) {
        log::warn("tracing: kallsyms not extracted; kprobes audit disabled");
        return out;
    }
    auto* sym = isf.find_symbol("kprobe_table");
    if (!sym) {
        log::warn("tracing: kprobe_table symbol absent");
        return out;
    }

    u64 hlist_off    = 0;
    u64 addr_off     = 0x28, sym_name_off = 0x30, offset_off = 0x38;
    u64 pre_off      = 0x40, post_off     = 0x48, flags_off  = 0x78;
    try {
        hlist_off    = isf.field_offset("kprobe", "hlist");
        addr_off     = isf.field_offset("kprobe", "addr");
        sym_name_off = isf.field_offset("kprobe", "symbol_name");
        offset_off   = isf.field_offset("kprobe", "offset");
        pre_off      = isf.field_offset("kprobe", "pre_handler");
        post_off     = isf.field_offset("kprobe", "post_handler");
        flags_off    = isf.field_offset("kprobe", "flags");
    } catch (const std::exception& e) {
        log::warn("tracing: kprobe field offsets missing — {}", e.what());
        return out;
    }
    (void)offset_off;

    PointerAuditCtx ctx = build_ptr_audit_ctx(eng);
    VAddr table_va = sym->address;
    log::info("tracing: kprobe_table @ {:#x}", table_va);

    for (std::size_t b = 0; b < kKprobeTableSize; ++b) {
        VAddr first = 0;
        if (!kva_read_pod(eng, table_va + b * 8, first)) continue;
        VAddr node = first;
        int guard = 0;
        while (node != 0 && guard++ < 1024) {
            VAddr kp = node - hlist_off;
            KprobeInfo k{};
            k.bucket    = (u32)b;
            k.kprobe_va = kp;
            kva_read_pod(eng, kp + addr_off,     k.addr);
            kva_read_pod(eng, kp + pre_off,      k.pre_handler);
            kva_read_pod(eng, kp + post_off,     k.post_handler);
            kva_read_pod(eng, kp + flags_off,    k.flags);

            // Read symbol_name pointer.
            VAddr sname_ptr = 0;
            kva_read_pod(eng, kp + sym_name_off, sname_ptr);
            if (sname_ptr) k.symbol_name = kva_read_cstr(eng, sname_ptr, 64);

            // Resolve the probed address against kallsyms.
            if (const auto* s = nearest_sym(ks, ctx.addr_idx, k.addr)) {
                k.symbol   = s->name;
                k.distance = k.addr - s->address;
            }

            k.pre_audit  = classify_kernel_ptr(eng, ctx, "pre_handler",
                                                k.pre_handler);
            k.post_audit = classify_kernel_ptr(eng, ctx, "post_handler",
                                                k.post_handler);
            out.push_back(std::move(k));

            // hlist_node.next is at offset 0 within hlist_node.
            VAddr next = 0;
            if (!kva_read_pod(eng, node, next) || next == node) break;
            node = next;
        }
    }
    log::info("tracing: enumerated {} kprobes", out.size());
    return out;
}

ByteBuf format_kprobes(const Engine& eng) {
    auto kps = enumerate_kprobes(eng);
    std::size_t pre_hooked = 0, post_hooked = 0;
    for (const auto& k : kps) {
        if (k.pre_audit.status == PtrAudit::HOOKED)  ++pre_hooked;
        if (k.post_audit.status == PtrAudit::HOOKED) ++post_hooked;
    }
    std::string out;
    out.reserve(8 * 1024);
    out += fmt::format(
        "# /sys/findevil/kprobes.txt — every registered kernel kprobe\n"
        "# Walks kprobe_table[64]. Each kprobe instruments a kernel address\n"
        "# with a pre_handler / post_handler. Rootkits register kprobes at\n"
        "# syscall entries to filter results (hide files / processes / sockets).\n"
        "#\n"
        "# {} kprobe(s) registered. Handler audit: {} pre_handler ★ HOOKED, "
        "{} post_handler ★ HOOKED.\n"
        "#\n"
        "# Note: eBPF KPROBE programs that attach a kprobe also show up here\n"
        "# AND in /sys/findevil/ebpf.txt — cross-referencing the two sets\n"
        "# is how to spot eBPF kprobe rootkits.\n"
        "#\n"
        "# bucket  kprobe_va             addr                  flags         "
        "probed_symbol (requested name)\n"
        "# ------+---------------------+---------------------+-------------+"
        "---------------------------\n",
        kps.size(), pre_hooked, post_hooked);
    if (kps.empty()) {
        out += "; no kprobes registered (or `kprobe_table` symbol missing).\n";
        return ByteBuf(out.begin(), out.end());
    }
    for (const auto& k : kps) {
        std::string probed = k.symbol.empty()
            ? "<unknown>"
            : (k.distance == 0 ? k.symbol
                : fmt::format("{} +{:#x}", k.symbol, k.distance));
        std::string req = k.symbol_name.empty() ? "" :
                          fmt::format(" (req={})", k.symbol_name);
        out += fmt::format("  {:>4}    {:#018x}  {:#018x}  {:<13}  {}{}\n",
                           k.bucket, k.kprobe_va, k.addr,
                           kprobe_flag_str(k.flags),
                           probed, req);
        // Show handler audits (only if non-trivial).
        auto print_handler = [&](const char* label, const PtrAudit& a) {
            if (a.status == PtrAudit::NULL_OK) return;
            const char* st =
                a.status == PtrAudit::HOOKED     ? "★ HOOKED   " :
                a.status == PtrAudit::SUSPICIOUS ? "  SUSPICIOUS" :
                                                   "  OK        ";
            std::string r = a.resolved.empty() ? "<unknown>"
                : (a.distance == 0 ? a.resolved
                    : fmt::format("{} +{:#x}", a.resolved, a.distance));
            out += fmt::format("            {:<14} {:#018x}  {}  {}\n",
                               label, a.addr, st, r);
        };
        print_handler("pre_handler:",  k.pre_audit);
        print_handler("post_handler:", k.post_audit);
    }
    return ByteBuf(out.begin(), out.end());
}

} // namespace lmpfs::linux
