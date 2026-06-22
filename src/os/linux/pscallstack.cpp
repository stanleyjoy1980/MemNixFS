// pscallstack.cpp — see header.
#include "os/linux/pscallstack.h"
#include "os/linux/kva_reader.h"
#include "app/engine.h"
#include "symbols/isf_symbols.h"
#include "symbols/kallsyms.h"
#include "core/log.h"
#include <fmt/format.h>
#include <algorithm>
#include <cstring>
#include <unordered_set>

namespace lmpfs::linux {

namespace {

// Linux x86_64 default kernel-stack size (CONFIG_THREAD_INFO_IN_TASK
// makes this independent of arch's struct thread_info; the slab cache
// is always allocated as 4 contiguous pages = 16 KiB).
constexpr std::size_t kThreadSize = 16 * 1024;

// Same address-index helper used by check_syscall + integrity_checks.
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
struct TextBounds { VAddr start = 0; VAddr end = 0; };
TextBounds resolve_text_bounds(const KallsymsResult& ks) {
    TextBounds b{};
    auto a = ks.by_name.find("_stext");
    auto z = ks.by_name.find("_etext");
    if (a != ks.by_name.end() && z != ks.by_name.end()) {
        b.start = ks.symbols[a->second].address;
        b.end   = ks.symbols[z->second].address;
        if (b.end > b.start) return b;
    }
    b.start = 0xffffffff80000000ULL;
    b.end   = 0xffffffffa0000000ULL;
    return b;
}

} // anonymous

KStackTrace walk_kernel_stack(const Engine& eng, const Process& p) {
    KStackTrace out{};
    const auto& isf = eng.isf();
    const auto& ks  = eng.kallsyms();
    if (!ks.ok || p.task_va == 0) return out;

    u64 ts_stack_off = 0, ts_thread_off = 0, thread_sp_off = 0;
    try {
        ts_stack_off  = isf.field_offset("task_struct",   "stack");
        ts_thread_off = isf.field_offset("task_struct",   "thread");
        thread_sp_off = isf.field_offset("thread_struct", "sp");
    } catch (const std::exception& e) {
        log::debug("kstack: ISF lacks field — {}", e.what());
        return out;
    }

    // task.stack is the BASE of the kernel stack (lowest address). The
    // stack grows DOWN from base + THREAD_SIZE, so saved-sp >= base.
    VAddr stack_base = 0;
    if (!kva_read_pod(eng, p.task_va + ts_stack_off, stack_base) ||
        stack_base == 0)
        return out;
    VAddr thread_sp = 0;
    kva_read_pod(eng, p.task_va + ts_thread_off + thread_sp_off, thread_sp);

    out.stack_base = stack_base;
    out.thread_sp  = thread_sp;

    // Read the whole THREAD_SIZE window. Kernel stacks are slab-allocated
    // (direct-map memory) so kva_read serves us via subtract-direct-map.
    std::vector<u8> stack(kThreadSize, 0);
    if (!kva_read(eng, stack_base, stack.data(), kThreadSize)) {
        log::debug("kstack: pid {} stack @ {:#x} unreadable",
                   p.pid, stack_base);
        return out;
    }

    AddrIndex   ai = build_addr_index(ks);
    TextBounds  tb = resolve_text_bounds(ks);

    // Scan every 8-byte aligned position for kernel-text return-address-
    // shaped values. Dedup by symbol name (the same function can appear
    // many times on a stack from spurious matches in stale memory).
    std::unordered_set<std::string> seen;
    for (std::size_t off = 0; off + 8 <= stack.size(); off += 8) {
        u64 v = 0;
        std::memcpy(&v, stack.data() + off, 8);
        if (v < tb.start || v >= tb.end) continue;
        const KallsymsEntry* sym = find_sym_below(ks, ai, v);
        if (!sym) continue;
        u64 dist = v - sym->address;
        // Reject "way past nearest symbol" as not a real return into
        // that function (some adjacent data section).
        if (dist > 0x10000) continue;
        // Dedup — only keep the first sighting of each symbol on the
        // stack (lowest offset = closest to current frame).
        if (!seen.insert(sym->name).second) continue;

        KStackFrame f{};
        f.offset_in_stack = (u64)off;
        f.return_addr     = v;
        f.symbol          = sym->name;
        f.distance        = dist;
        out.frames.push_back(std::move(f));
    }
    // Stack grows down; saved-SP is somewhere mid-buffer. Frames at lower
    // offsets are closer to the saved-SP (= currently-executing context).
    out.ok = true;
    return out;
}

ByteBuf format_kstack(const Engine& eng, const Process& p) {
    auto tr = walk_kernel_stack(eng, p);
    std::string out;
    out.reserve(4 * 1024);
    if (!tr.ok) {
        out = fmt::format("; pid {} ({}) — no kernel stack readable\n"
                          "; (kernel task with no `stack` pointer, or "
                          "direct-map unreadable)\n",
                          p.pid, p.comm);
        return ByteBuf(out.begin(), out.end());
    }
    out += fmt::format(
        "# /proc/{}/kstack.txt — kernel-stack walk for pid {} ({})\n"
        "# stack base = {:#018x}, thread.sp = {:#018x}\n"
        "# {} unique kernel-text return addresses found on the stack\n"
        "# (lower offset = closer to currently-executing frame)\n"
        "#\n"
        "# offset  return_addr           symbol (+offset)\n"
        "# ------ -------------------- -------------------------\n",
        p.pid, p.pid, p.comm,
        tr.stack_base, tr.thread_sp, tr.frames.size());
    for (const auto& f : tr.frames) {
        std::string sym = f.distance == 0
            ? f.symbol
            : fmt::format("{} +{:#x}", f.symbol, f.distance);
        out += fmt::format("  {:#06x}  {:#018x}  {}\n",
                           f.offset_in_stack, f.return_addr, sym);
    }
    return ByteBuf(out.begin(), out.end());
}

} // namespace lmpfs::linux
