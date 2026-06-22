// tracepoints.cpp — see header.
#include "os/linux/tracepoints.h"
#include "os/linux/kva_reader.h"
#include "app/engine.h"
#include "symbols/isf_symbols.h"
#include "symbols/kallsyms.h"
#include "core/log.h"
#include <fmt/format.h>

namespace lmpfs::linux {

namespace {

constexpr std::size_t kMaxHandlers   = 64;     // sanity bound
constexpr std::size_t kMaxTracepoints = 4000;  // sanity bound (test dump: 1167)

// Read `struct tracepoint` at `tp_va`. We read just the two fields we
// care about: `name` (pointer) and `funcs` (pointer to handler array).
// The struct's layout is, per include/linux/tracepoint-defs.h:
//   name  @ offset 0   (const char*)
//   key   @ offset 8   (static_key — a few words)
//   ... other ptrs ...
//   funcs @ offset varies; we resolve via ISF.
//
// If the ISF doesn't have `struct tracepoint`, we fall back to a
// hard-coded layout that's stable on modern (5.x+) x86_64: name@0,
// funcs at a struct-end offset that we compute from typical sizes.
bool resolve_tracepoint_offsets(const IsfSymbols& isf,
                                 u64& off_name, u64& off_funcs) {
    try {
        off_name  = isf.field_offset("tracepoint", "name");
        off_funcs = isf.field_offset("tracepoint", "funcs");
        log::info("tracepoint: ISF struct tracepoint: name@{:#x} funcs@{:#x}",
                   off_name, off_funcs);
        return true;
    } catch (...) {
        // Fallback to the 6.x layout WITH static_call fields:
        //   name @ 0
        //   key (struct static_key) @ 8   size 16
        //   static_call_key @ 24
        //   static_call_tramp @ 32
        //   iterator @ 40
        //   regfunc  @ 48
        //   unregfunc @ 56
        //   funcs @ 64 (0x40)
        // Older kernels without static_call inline had funcs @ 0x30.
        // We pick 0x40 because it matches every kernel ≥ 5.10 with the
        // distro-default CONFIG_HAVE_STATIC_CALL_INLINE=y; the wrong
        // value just produces garbage reads which our value-sanity
        // filter (see scan loop) catches.
        off_name  = 0;
        off_funcs = 0x40;
        log::warn("tracepoint: ISF lacks struct tracepoint — using "
                   "fallback offsets name@0 funcs@0x40");
        return false;
    }
}

bool resolve_tp_func_offset_func(const IsfSymbols& isf, u64& off_func) {
    try {
        off_func = isf.field_offset("tracepoint_func", "func");
        return true;
    } catch (...) {
        off_func = 0;
        return false;          // tracepoint_func.func IS at offset 0
    }
}

} // anonymous

std::vector<TracepointInfo> enumerate_active_tracepoints(const Engine& eng) {
    std::vector<TracepointInfo> out;
    const auto& ks  = eng.kallsyms();
    if (!ks.ok) {
        log::warn("tracepoints: kallsyms unavailable — skipping");
        return out;
    }
    u64 off_name = 0, off_funcs = 0;
    resolve_tracepoint_offsets(eng.isf(), off_name, off_funcs);
    u64 off_tpf_func = 0;
    resolve_tp_func_offset_func(eng.isf(), off_tpf_func);

    PointerAuditCtx ctx = build_ptr_audit_ctx(eng);

    constexpr const char* kPrefix = "__tracepoint_";
    constexpr std::size_t kPrefixLen = 13;
    constexpr const char* kPfx = "__pfx_";
    constexpr std::size_t kPfxLen = 6;

    std::size_t scanned = 0;
    for (const auto& s : ks.symbols) {
        if (scanned >= kMaxTracepoints) break;
        // Names look like "__tracepoint_<event>" (data symbol, type 'D'/'d').
        // Skip the kCFI prefix wrapper "__pfx___tracepoint_<event>" — that's
        // a function-prefix landing pad, NOT the tracepoint struct.
        const auto& n = s.name;
        if (n.size() < kPrefixLen + 1) continue;
        if (std::memcmp(n.data(), kPfx, kPfxLen) == 0) continue;
        if (std::memcmp(n.data(), kPrefix, kPrefixLen) != 0) continue;
        ++scanned;

        TracepointInfo tp;
        tp.name          = n.substr(kPrefixLen);
        tp.tracepoint_va = s.address;

        // Read the `funcs` pointer. Skip if read fails.
        VAddr funcs_va = 0;
        if (!kva_read_pod(eng, s.address + off_funcs, funcs_va)) continue;
        if (funcs_va == 0) continue;   // no handlers attached
        tp.funcs_va = funcs_va;

        // Walk the tracepoint_func array. Each entry is ~24 bytes
        // (func ptr + data ptr + prio + pad). We read func until NULL.
        constexpr std::size_t kTpFuncStride = 24;
        for (std::size_t i = 0; i < kMaxHandlers; ++i) {
            VAddr func = 0;
            VAddr entry_va = funcs_va + i * kTpFuncStride + off_tpf_func;
            if (!kva_read_pod(eng, entry_va, func)) break;
            if (func == 0) break;
            // Sanity: a real handler is a kernel-text or module VA. Anything
            // outside the canonical kernel half is junk past the end of the
            // funcs array (poison / uninitialized / heap-overrun read). Stop
            // here to avoid emitting noise.
            constexpr VAddr kKernelHalfStart = 0xffff800000000000ULL;
            if (func < kKernelHalfStart) break;

            TracepointHandler h;
            h.func  = func;
            // data is the next pointer-sized slot. Best-effort read.
            kva_read_pod(eng, entry_va + sizeof(VAddr), h.data);
            h.audit = classify_kernel_ptr(eng, ctx,
                                            "tracepoint_handler", func);
            tp.handlers.push_back(std::move(h));
        }

        if (!tp.handlers.empty()) out.push_back(std::move(tp));
    }
    log::info("tracepoints: scanned {} `__tracepoint_*` symbols; {} have "
              "≥1 handler attached", scanned, out.size());
    return out;
}

ByteBuf format_tracepoints(const Engine& eng) {
    auto tps = enumerate_active_tracepoints(eng);
    std::size_t hooked = 0;
    for (const auto& t : tps)
        for (const auto& h : t.handlers)
            if (h.audit.status == PtrAudit::HOOKED) ++hooked;

    std::string out;
    out.reserve(8 * 1024);
    out += fmt::format(
        "# /sys/findevil/tracepoints.txt — kernel tracepoints with active\n"
        "# handlers. Walks every `__tracepoint_*` symbol from kallsyms and\n"
        "# reads its `tracepoint.funcs` array. Each handler is\n"
        "# classify_ptr-audited against kernel-text bounds + kallsyms\n"
        "# handler-name conventions.\n"
        "#\n"
        "# {} tracepoint(s) with handlers; {} handler(s) flagged HOOKED.\n"
        "#\n"
        "# tracepoint                          tp_va             func_va           audit\n"
        "# ----------------------------------+----------------+----------------+--------\n",
        tps.size(), hooked);
    if (tps.empty()) {
        out += "; no tracepoints have handlers (clean kernel) — or ISF\n"
               "; lacks `struct tracepoint`; check the warn-level log.\n";
        return ByteBuf(out.begin(), out.end());
    }
    for (const auto& t : tps) {
        for (std::size_t i = 0; i < t.handlers.size(); ++i) {
            const auto& h = t.handlers[i];
            const char* status =
                h.audit.status == PtrAudit::HOOKED     ? "* HOOKED" :
                h.audit.status == PtrAudit::SUSPICIOUS ? "  SUSP. " : "  ok    ";
            std::string resolved = h.audit.resolved.empty() ? "?"
                : (h.audit.distance == 0
                    ? h.audit.resolved
                    : fmt::format("{}+{:#x}", h.audit.resolved, h.audit.distance));
            // First handler row shows the tracepoint name; subsequent
            // rows align under it.
            std::string n = (i == 0) ? t.name.substr(0, 34) : "";
            out += fmt::format("  {:<34}  {:#016x}  {:#016x}  {}  {}\n",
                                n, t.tracepoint_va, h.func, status, resolved);
        }
    }
    return ByteBuf(out.begin(), out.end());
}

} // namespace lmpfs::linux
