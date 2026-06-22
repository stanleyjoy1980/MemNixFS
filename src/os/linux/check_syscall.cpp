// check_syscall.cpp — see header.
#include "os/linux/check_syscall.h"
#include "os/linux/kva_reader.h"
#include "app/engine.h"
#include "symbols/kallsyms.h"
#include "core/log.h"
#include <fmt/format.h>
#include <algorithm>
#include <cstring>

namespace lmpfs::linux {

namespace {

// Hard cap on how far we walk sys_call_table. Modern x86_64 has ~458
// real syscalls (latest is `__NR_landlock_restrict_self` etc); plus a
// trailing tail of sys_ni_syscall padding. 600 is safe.
constexpr std::size_t kMaxSyscalls = 600;

thread_local std::string g_unavailable_reason;

void set_unavailable(std::string reason) {
    g_unavailable_reason = std::move(reason);
}

bool is_canonical_kernel_ptr(VAddr addr) {
    return addr >= 0xffffffff80000000ULL;
}

// An address-sorted index into ks.symbols, built once. (kallsyms is
// typically address-sorted at extraction time, but we don't depend on that.)
struct AddrIndex {
    std::vector<std::size_t> idx;   // indices into ks.symbols, ascending by address
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

// Return the highest-addressed kallsyms entry whose address is ≤ addr.
const KallsymsEntry* find_symbol_below(const KallsymsResult& ks,
                                        const AddrIndex& a, VAddr addr) {
    if (a.idx.empty()) return nullptr;
    auto it = std::upper_bound(a.idx.begin(), a.idx.end(), addr,
        [&](VAddr v, std::size_t i) { return v < ks.symbols[i].address; });
    if (it == a.idx.begin()) return nullptr;
    --it;
    return &ks.symbols[*it];
}

// Recognize the kernel's syscall-handler naming conventions. On x86_64
// kernels with the per-arch wrapper macros, every entry resolves to one
// of these prefixes (or to `sys_ni_syscall` for unimplemented numbers).
bool name_is_syscall_handler(const std::string& n) {
    if (n.empty()) return false;
    static const char* prefixes[] = {
        "__x64_sys_",    "__x64_compat_sys_",
        "__ia32_sys_",   "__ia32_compat_sys_",
        "__do_sys_",     "__se_sys_",
        "sys_",          "compat_sys_",
        "__arm64_sys_",  // for completeness — not relevant on x86 dumps
    };
    for (const char* p : prefixes) {
        std::size_t plen = std::strlen(p);
        if (n.size() >= plen && n.compare(0, plen, p) == 0) return true;
    }
    // `sys_ni_syscall` shows up bare (no prefix) and is legitimate.
    return n == "sys_ni_syscall";
}

} // anonymous

std::vector<SyscallEntry> check_syscall_table(const Engine& eng) {
    g_unavailable_reason.clear();
    std::vector<SyscallEntry> out;
    const auto& ks = eng.kallsyms();
    if (!ks.ok) {
        log::warn("check_syscall: kallsyms not extracted");
        set_unavailable("kallsyms were not extracted");
        return out;
    }

    auto sct_it = ks.by_name.find("sys_call_table");
    if (sct_it == ks.by_name.end()) {
        log::warn("check_syscall: kallsyms lacks `sys_call_table`");
        set_unavailable("kallsyms does not contain sys_call_table");
        return out;
    }
    VAddr sct_va = ks.symbols[sct_it->second].address;

    // Determine the table's real length. The kernel exposes
    // `__NR_syscalls` as a `#define`, not a symbol — but we can get the
    // size by looking at the next kallsyms symbol after sys_call_table.
    // The byte gap between them is the table's size.
    AddrIndex addr_idx_for_sizing;     // built early; reused below
    addr_idx_for_sizing = build_addr_index(ks);
    std::size_t table_bytes = 0;
    {
        auto it = std::upper_bound(addr_idx_for_sizing.idx.begin(),
                                    addr_idx_for_sizing.idx.end(),
                                    sct_va,
            [&](VAddr v, std::size_t i) { return v < ks.symbols[i].address; });
        if (it != addr_idx_for_sizing.idx.end()) {
            VAddr next_sym = ks.symbols[*it].address;
            if (next_sym > sct_va && next_sym - sct_va < 64 * 1024)
                table_bytes = next_sym - sct_va;
        }
    }
    const std::size_t nr_syscalls = (table_bytes > 0) ? (table_bytes / 8) :
                                                         kMaxSyscalls;
    log::info("check_syscall: sys_call_table size = {} bytes ({} entries)",
              table_bytes, nr_syscalls);

    // Kernel-text bounds (.text). We need _stext / _etext (or the
    // _text / _etext pair) from kallsyms.
    VAddr text_start = 0, text_end = 0;
    auto stext_it = ks.by_name.find("_stext");
    auto etext_it = ks.by_name.find("_etext");
    if (stext_it != ks.by_name.end()) text_start = ks.symbols[stext_it->second].address;
    if (etext_it != ks.by_name.end()) text_end   = ks.symbols[etext_it->second].address;
    if (text_start == 0 || text_end == 0) {
        // Conservative fallback: x86_64 kernel-image canonical range.
        text_start = 0xffffffff80000000ULL;
        text_end   = 0xffffffffa0000000ULL;
        log::warn("check_syscall: _stext/_etext not in kallsyms; using "
                  "fallback range {:#x}..{:#x}", text_start, text_end);
    }
    log::info("check_syscall: sys_call_table={:#x} text=[{:#x}..{:#x}]",
              sct_va, text_start, text_end);

    // Reuse the address index we just built for sizing.
    const AddrIndex& addr_idx = addr_idx_for_sizing;

    // Walk the table for exactly nr_syscalls entries (computed above
    // from the next-symbol-after-sys_call_table). Don't try to
    // heuristically detect the end via NULLs — sparse NULLs are normal.
    std::size_t nonzero_entries = 0;
    std::size_t canonical_entries = 0;
    for (std::size_t nr = 0; nr < nr_syscalls; ++nr) {
        VAddr entry = 0;
        if (!kva_read_pod(eng, sct_va + nr * 8, entry)) {
            log::debug("check_syscall: read failed at nr={}", nr);
            break;
        }
        SyscallEntry s{};
        s.nr         = (u32)nr;
        s.entry_addr = entry;
        if (entry != 0) {
            ++nonzero_entries;
            if (is_canonical_kernel_ptr(entry)) ++canonical_entries;
        }

        // NULL entries: in modern Linux these correspond to deliberately
        // unused syscall numbers (security removals, reserved-for-future,
        // architecture-specific gaps). Treat as OK with a note rather
        // than HOOKED — a real hook would point SOMEWHERE.
        if (entry == 0) {
            s.status = SyscallEntry::OK;
            s.note   = "unused slot (NULL — reserved / removed / arch-gap)";
            s.resolved_name = "<unused>";
            out.push_back(std::move(s));
            continue;
        }

        const KallsymsEntry* sym = find_symbol_below(ks, addr_idx, entry);
        if (sym) {
            s.resolved_name = sym->name;
            s.distance      = entry - sym->address;
        }

        // ---- classify ----
        if (entry < text_start || entry >= text_end) {
            s.status = SyscallEntry::HOOKED;
            s.note   = fmt::format("entry @ {:#x} is OUTSIDE kernel text "
                                   "[{:#x}..{:#x}] — almost certainly hooked",
                                   entry, text_start, text_end);
        } else if (!sym) {
            s.status = SyscallEntry::SUSPICIOUS;
            s.note   = "kallsyms can't resolve a containing symbol";
        } else if (s.distance > 0x10000) {
            // A real syscall handler is a function ≤ a few KB. If we're
            // 64 KB past the nearest symbol, we're not inside it.
            s.status = SyscallEntry::SUSPICIOUS;
            s.note   = fmt::format("{} away from nearest kallsyms symbol "
                                   "({}) — likely outside any known function",
                                   s.distance, sym->name);
        } else if (!name_is_syscall_handler(sym->name)) {
            s.status = SyscallEntry::SUSPICIOUS;
            s.note   = fmt::format("resolved symbol `{}` doesn't match a "
                                   "syscall-handler naming pattern", sym->name);
        } else {
            s.status = SyscallEntry::OK;
        }

        out.push_back(std::move(s));
    }

    // If the candidate table mostly contains non-canonical values, we are
    // not looking at a function-pointer table. On some incomplete LiME dumps
    // this can happen when the table VA resolves to nearby instruction bytes;
    // treating that as "every syscall is hooked" would be misleading.
    if (nonzero_entries >= 16 && canonical_entries * 4 < nonzero_entries * 3) {
        set_unavailable(fmt::format(
            "sys_call_table candidate at {:#x} did not look like a pointer table: "
            "{} of {} non-null entries were canonical kernel addresses",
            sct_va, canonical_entries, nonzero_entries));
        log::warn("check_syscall: {}", g_unavailable_reason);
        out.clear();
        return out;
    }
    log::info("check_syscall: {} entries checked", out.size());
    return out;
}

ByteBuf format_check_syscall(const Engine& eng) {
    auto entries = check_syscall_table(eng);
    if (entries.empty()) {
        std::string msg =
            "; check_syscall: unavailable: " +
            (g_unavailable_reason.empty()
                 ? std::string("could not recover a usable sys_call_table")
                 : g_unavailable_reason) +
            ".\n"
            "; No syscall-hook conclusion was made from this source.\n";
        return ByteBuf(msg.begin(), msg.end());
    }
    std::size_t ok = 0, susp = 0, hooked = 0;
    for (const auto& e : entries) {
        if (e.status == SyscallEntry::OK)         ++ok;
        else if (e.status == SyscallEntry::SUSPICIOUS) ++susp;
        else                                       ++hooked;
    }
    std::string out;
    out.reserve(64 * 1024);
    out += fmt::format(
        "# check_syscall — sys_call_table integrity check\n"
        "# {} entries scanned: {} OK, {} SUSPICIOUS, {} ★ HOOKED\n"
        "# (HOOKED = entry points outside the kernel-text range; that's\n"
        "#  unambiguous rootkit behaviour. SUSPICIOUS = inside text but\n"
        "#  the symbol name doesn't match a syscall-handler convention.)\n"
        "#\n"
        "# nr   entry_addr           status      resolved_symbol (+offset)\n"
        "# --- -------------------- ----------- -------------------------\n",
        entries.size(), ok, susp, hooked);
    // Surface ★ HOOKED first, then SUSPICIOUS, then OK.
    auto sorted = entries;
    std::stable_sort(sorted.begin(), sorted.end(),
        [](const SyscallEntry& a, const SyscallEntry& b) {
            return (int)a.status > (int)b.status;   // HOOKED(2) > SUSP(1) > OK(0)
        });
    for (const auto& e : sorted) {
        const char* s =
            e.status == SyscallEntry::HOOKED     ? "★ HOOKED  " :
            e.status == SyscallEntry::SUSPICIOUS ? "  SUSPICIOUS" :
                                                   "  OK       ";
        std::string sym_col;
        if (!e.resolved_name.empty()) {
            if (e.distance == 0) sym_col = e.resolved_name;
            else sym_col = fmt::format("{} +{:#x}", e.resolved_name, e.distance);
        } else {
            sym_col = "<unknown>";
        }
        out += fmt::format("  {:>3}  {:#018x}  {}  {}\n",
                           e.nr, e.entry_addr, s, sym_col);
        if (e.status != SyscallEntry::OK && !e.note.empty()) {
            out += fmt::format("        └── {}\n", e.note);
        }
    }
    return ByteBuf(out.begin(), out.end());
}

} // namespace lmpfs::linux
