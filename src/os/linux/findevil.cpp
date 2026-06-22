// findevil.cpp — see header.
#include "os/linux/findevil.h"
#include "os/linux/vma.h"
#include "os/linux/modules.h"
#include "os/linux/kva_reader.h"
#include "arch/x86_64/paging.h"
#include "os/linux/check_syscall.h"
#include "os/linux/integrity_checks.h"
#include "os/linux/ebpf.h"
#include "os/linux/entropy.h"
#include "os/linux/tracing.h"
#include "os/linux/av_edr.h"
#include "os/linux/task_files.h"
#include "os/linux/fdtable.h"
#include "os/linux/netstat.h"
#include "os/linux/csv_export.h"
#include "app/engine.h"
#include "symbols/isf_symbols.h"
#include "formats/physical_layer.h"
#include "core/log.h"
#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <set>
#include <unordered_set>
#include <unordered_map>

namespace lmpfs::linux {

// ================================================================
// MALFIND — suspicious VMAs
// ================================================================

namespace {

// vm_flags bits we care about (include/linux/mm.h):
constexpr u64 VM_READ  = 0x00000001;
constexpr u64 VM_WRITE = 0x00000002;
constexpr u64 VM_EXEC  = 0x00000004;
constexpr u64 VM_GROWSDOWN = 0x00000100;   // stack
constexpr u64 VM_LOCKED    = 0x00002000;

std::string flag_str(u64 vm_flags) {
    std::string s;
    s += (vm_flags & VM_READ)  ? 'r' : '-';
    s += (vm_flags & VM_WRITE) ? 'w' : '-';
    s += (vm_flags & VM_EXEC)  ? 'x' : '-';
    return s;
}

} // anon

std::vector<MalfindHit> find_malfind(const Engine& eng, const Process& p) {
    std::vector<MalfindHit> hits;
    if (p.mm == 0) return hits;   // kernel thread

    std::vector<Vma> vmas;
    try {
        vmas = enumerate_vmas(eng.phys(), eng.isf(), eng.kernel(), p);
    } catch (...) {
        // Maple-tree walker can blow up on partially-freed mm_struct slabs
        // (e.g. processes in the middle of being torn down at snapshot time).
        return hits;
    }
    // Sanity: legitimate Linux processes have at most a few thousand VMAs.
    // If we got back an absurd count, the walker recursed into garbage.
    if (vmas.size() > 50'000) {
        log::debug("malfind: pid {} returned {} VMAs — capping (looks corrupt)",
                   p.pid, vmas.size());
        return hits;
    }
    // Pass 1 — classify by VMA flags only (no memory reads). We only care
    // about EXECUTABLE regions; everything malfind reports is anon-exec.
    for (const auto& v : vmas) {
        if (!v.executable()) continue;
        const bool write = v.writable();
        const bool anon  = (v.vm_file == 0);
        const u64  size  = v.vm_end - v.vm_start;

        // [vdso] / signal-restorer: kernel-provided RX anonymous page(s), 1-2
        // pages, present on EVERY process. Never the finding — exclude entirely
        // so the report isn't 90% vDSO noise. (A real payload is larger.)
        if (anon && !write && size <= 0x4000) continue;

        std::string reason;
        bool high = false;
        if (anon && write) {
            reason = "RWX anonymous mapping — classic code injection";
            high = true;                       // strongest injection marker
        } else if (v.vm_flags & VM_GROWSDOWN) {
            reason = "executable stack";
            high = true;
        } else if (anon) {
            // RX anonymous, bigger than vDSO. This is the state a payload sits
            // in AFTER mprotect(PROT_READ|PROT_EXEC) — e.g. Meterpreter's
            // reflectively-loaded stage. It's ALSO what JITs (browsers, node,
            // JVM) produce, so it's notable-not-damning: surface it for review
            // instead of silently calling it benign (the old behaviour, which
            // is why post-mprotect injected code slipped through).
            reason = "anonymous executable mapping (RX) — JIT or injected code; inspect";
            high = false;
        } else {
            // File-backed executable (library / the program text). Normal.
            continue;
        }

        MalfindHit h{};
        h.vm_start      = v.vm_start;
        h.vm_end        = v.vm_end;
        h.vm_flags      = v.vm_flags;
        h.reason        = std::move(reason);
        h.high_severity = high;
        hits.push_back(std::move(h));
    }

    // Pass 2 — only if we flagged something, peek at the first bytes of each
    // region so the analyst can tell a LIVE payload (non-zero code) from an
    // empty reservation (zero-filled) without dumping the whole VMA. Resolving
    // the PGD is skipped entirely for the common case of zero hits.
    if (!hits.empty()) {
        PAddr pgd = 0;
        try { pgd = resolve_user_pgd(eng.phys(), eng.isf(), eng.kernel(), p); }
        catch (...) { pgd = 0; }
        if (pgd) {
            x86_64::PageTable upt(eng.phys(), pgd);
            for (auto& h : hits) {
                u8 buf[64] = {};
                std::size_t got = upt.read(h.vm_start, buf, sizeof(buf));
                if (got == 0) { h.content_hint = "unreadable (paged out)"; continue; }
                bool nonzero = false;
                for (std::size_t i = 0; i < got; ++i) if (buf[i]) { nonzero = true; break; }
                if (!nonzero) {
                    h.content_hint = "zero-filled (empty reservation)";
                } else {
                    std::size_t start = 0;
                    while (start < got && buf[start] == 0) ++start;
                    std::string hex;
                    for (std::size_t i = start; i < start + 8 && i < got; ++i)
                        hex += fmt::format("{:02x} ", buf[i]);
                    if (start == 0)
                        h.content_hint = "non-zero [" + hex + "...]";
                    else
                        h.content_hint = fmt::format(
                            "non-zero at +0x{:x} [{}...]", start, hex);
                }
            }
        }
    }
    return hits;
}

ByteBuf format_proc_malfind(const Engine& eng, const Process& p) {
    auto hits = find_malfind(eng, p);
    std::string out;
    out.reserve(2 * 1024);
    if (hits.empty()) {
        out = fmt::format("; pid {} ({}): no anonymous executable regions "
                          "(vDSO / signal pages excluded as benign)\n",
                          p.pid, p.comm);
    } else {
        out += fmt::format(
            "# pid {} ({}): {} anonymous-executable region(s)\n"
            "# (vDSO/signal-restorer pages excluded; ★ = RWX or exec-stack — an\n"
            "#  injection marker. RX-anon is JIT-or-injected: check 'content'.)\n"
            "# sev vm_start          vm_end             perms  size      content / reason\n"
            "#---+-----------------+-----------------+------+---------+----------------\n",
            p.pid, p.comm, hits.size());
        for (const auto& h : hits) {
            out += fmt::format("  {} {:#016x}  {:#016x}  {}  {:>7} B  {}\n"
                               "                                                     {}\n",
                               h.high_severity ? "★" : " ",
                               h.vm_start, h.vm_end, flag_str(h.vm_flags),
                               h.vm_end - h.vm_start,
                               h.content_hint.empty() ? "-" : h.content_hint,
                               h.reason);
        }
    }
    return ByteBuf(out.begin(), out.end());
}

ByteBuf format_findevil_malfind(const Engine& eng) {
    std::string out;
    out.reserve(64 * 1024);
    std::size_t total_pids = 0, total_hits = 0, errors = 0,
                high_hits = 0, high_pids = 0;
    for (const auto& p : eng.processes()) {
        std::vector<MalfindHit> hits;
        try { hits = find_malfind(eng, p); }
        catch (...) { ++errors; continue; }
        if (hits.empty()) continue;
        ++total_pids;
        total_hits += hits.size();
        bool any_high = false;
        for (const auto& h : hits) if (h.high_severity) { ++high_hits; any_high = true; }
        if (any_high) ++high_pids;
        try {
            std::string section = fmt::format(
                "\n=== pid {} ({}) — {} region(s){} ===\n",
                p.pid, p.comm, hits.size(),
                any_high ? "  ★ injection marker" : "");
            for (const auto& h : hits) {
                section += fmt::format(
                    "  {} {:#016x} - {:#016x}  {}  {:>7} B  {}\n"
                    "      {}\n",
                    h.high_severity ? "★" : " ",
                    h.vm_start, h.vm_end, flag_str(h.vm_flags),
                    h.vm_end - h.vm_start, h.reason,
                    h.content_hint.empty() ? "-" : h.content_hint);
            }
            out += section;
        } catch (...) {
            ++errors;
        }
    }
    std::string header = fmt::format(
        "# malfind — anonymous executable memory (code-injection detector)\n"
        "#\n"
        "# {} anon-exec region(s) across {} process(es). Of those, {} are ★\n"
        "# injection markers (RWX-anon or executable stack) across {} process(es);\n"
        "# the rest are RX-anon (JIT engines AND post-mprotect injected payloads\n"
        "# both look like this — use the 'content' hint + the process identity to\n"
        "# triage). [vdso]/signal pages are EXCLUDED as benign.\n"
        "# {} processes scanned, {} skipped due to errors.\n"
        "#\n"
        "# Reading a row: non-zero content = the region holds bytes (live code or\n"
        "# data); zero-filled = an empty reservation. A browser/node/JVM/gnome JS\n"
        "# process with RWX/RX-anon is expected; an unexpected process is not.\n",
        total_hits, total_pids, high_hits, high_pids,
        eng.processes().size(), errors);
    std::string combined = header + out;
    return ByteBuf(combined.begin(), combined.end());
}

// ================================================================
// PSSCAN — physical-memory scan for hidden task_structs
// ================================================================

namespace {

// A comm field looks like a process name: 2+ printable bytes followed by
// NUL padding to 16. Real comm strings start with [a-zA-Z0-9_] and use the
// restricted ASCII subset Linux uses for kthread / user names.
bool plausible_comm(const u8* p) {
    if (p[0] == 0) return false;
    // First char must be letter / digit / underscore (no bracket-like or
    // punctuation-leading names exist on Linux).
    u8 c0 = p[0];
    if (!((c0 >= 'a' && c0 <= 'z') || (c0 >= 'A' && c0 <= 'Z') ||
          (c0 >= '0' && c0 <= '9') || c0 == '_')) return false;
    bool seen_nul = false;
    int  real_len = 0;
    for (int i = 0; i < 16; ++i) {
        u8 c = p[i];
        if (c == 0) { seen_nul = true; continue; }
        if (seen_nul) return false;        // non-NUL after NUL → bogus
        ++real_len;
        // Restricted to chars that actually appear in real Linux comm fields:
        // kthread names ("kworker/u8:1H+i915"), bash/firefox/etc.
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') ||
              c == '_' || c == '-' || c == '/' || c == '.' ||
              c == '[' || c == ']' || c == ':' || c == '+' ||
              c == '@' || c == '~'))
            return false;
    }
    if (!seen_nul)    return false;
    if (real_len < 2) return false;   // single-byte "names" are noise
    return true;
}

} // anon

std::vector<PsScanHit> scan_for_tasks(const Engine& eng) {
    std::vector<PsScanHit> out;
    const auto& isf  = eng.isf();
    const auto& phys = eng.phys();

    u64 task_size = 0, comm_off = 0, pid_off = 0, tgid_off = 0, tasks_off = 0,
        mm_off = 0, state_off = 0;
    try {
        task_size = isf.type_size("task_struct");
        comm_off  = isf.field_offset("task_struct", "comm");
        pid_off   = isf.field_offset("task_struct", "pid");
        tgid_off  = isf.field_offset("task_struct", "tgid");
        tasks_off = isf.field_offset("task_struct", "tasks");
        mm_off    = isf.field_offset("task_struct", "mm");
    } catch (const std::exception& e) {
        log::warn("psscan: ISF lacks task_struct field — {}", e.what());
        return out;
    }
    // task_struct.__state is a u32 at offset 0x18 on 6.x. Optional — if
    // absent we just skip that check.
    try { state_off = isf.field_offset("task_struct", "__state"); }
    catch (...) {
        try { state_off = isf.field_offset("task_struct", "state"); }
        catch (...) { state_off = 0; }
    }
    (void)task_size;

    // Build sets from the official list. We track:
    //   * exact (pid, comm) tuples for direct matches
    //   * pid-only set so we can recognise threads (whose tgid matches an
    //     entry in this set) instead of flagging them as "hidden"
    std::set<std::pair<u32, std::string>> known;
    std::set<u32>                          known_pids;
    for (const auto& p : eng.processes()) {
        known.emplace(p.pid, p.comm);
        known_pids.insert(p.pid);
    }

    // Helper: is this a "kernel pointer" — high bits set, canonical form.
    auto is_kernel_ptr = [](u64 p) {
        return p >= 0xffff800000000000ULL && p < 0xffffffffffffffffULL;
    };

    constexpr std::size_t kChunk = 4 * 1024 * 1024;
    std::vector<u8> buf(kChunk + 32);
    PAddr maxa = phys.max_address();
    PAddr pa = 0;
    std::size_t signature_hits = 0, sanity_passed = 0;
    log::info("psscan: scanning {:.1f} MB for task_struct signatures...",
              maxa / (1024.0 * 1024));

    while (pa < maxa) {
        std::size_t want = std::min<u64>(kChunk + 32, maxa - pa);
        std::size_t got  = phys.read(pa, buf.data(), want);
        if (got < 32) { pa += kChunk; continue; }

        // Sliding window: task_struct is slab-allocated and at least 8-byte
        // aligned. We step 8 bytes at a time.
        const std::size_t max_off = (got > comm_off + 16) ? (got - comm_off - 16) : 0;
        for (std::size_t i = 0; i < max_off; i += 8) {
            if (!plausible_comm(buf.data() + i + comm_off)) continue;
            ++signature_hits;

            // Read pid + tgid + mm + tasks.next + tasks.prev for validation.
            const std::size_t base = i;
            // Bounds check the deepest read.
            if (base + tasks_off + 16 > got) continue;

            u32 pid = 0, tgid = 0;
            u64 mm = 0, tnext = 0, tprev = 0;
            std::memcpy(&pid,   buf.data() + base + pid_off,   4);
            std::memcpy(&tgid,  buf.data() + base + tgid_off,  4);
            std::memcpy(&mm,    buf.data() + base + mm_off,    8);
            std::memcpy(&tnext, buf.data() + base + tasks_off + 0, 8);
            std::memcpy(&tprev, buf.data() + base + tasks_off + 8, 8);

            std::string comm(
                reinterpret_cast<const char*>(buf.data() + base + comm_off), 16);
            std::size_t n = 0;
            while (n < comm.size() && comm[n]) ++n;
            comm.resize(n);
            if (comm.empty()) continue;

            // ---- Sanity gauntlet (each filter throws out ~10x noise) ----
            // PID range: kernel pid_max is at most 2^22, but typical max
            // is 32k or 4M. Reject anything obviously bogus.
            if (pid > 0x400000)  continue;
            if (tgid > 0x400000) continue;
            // PID 0 is reserved for the per-CPU idle threads (swapper/N).
            // Reject any pid=0 record whose comm doesn't start with that.
            if (pid == 0 && comm.compare(0, 8, "swapper/") != 0) continue;
            // For a real task, the thread-group leader has tgid == pid.
            // Threads share tgid with the leader. Either way, tgid != 0
            // unless pid == 0 (swapper kthreads).
            if (pid != 0 && tgid == 0) continue;
            // *** Killer filter — Linux PID allocation invariant ***
            // The thread-group leader is the FIRST task created in the
            // group, so its pid IS the tgid. Threads created later get
            // monotonically-higher pids → for threads, pid > tgid.
            // pid < tgid is structurally impossible. This single check
            // caught two false positives on the Alpine test dump
            // (`io-symbolic.svg`, `nf.N`) where stale memory mimicked
            // a task_struct.
            if (pid > 0 && pid < tgid) continue;
            // mm is either NULL (kernel thread) or a kernel pointer.
            if (mm != 0 && !is_kernel_ptr(mm)) continue;
            // tasks.next + tasks.prev MUST be kernel pointers (this is the
            // killer filter — random bytes almost never satisfy both).
            if (!is_kernel_ptr(tnext)) continue;
            if (!is_kernel_ptr(tprev)) continue;
            // __state should be a small value (TASK_RUNNING…TASK_DEAD bits).
            // Anything > 0x1ff is essentially impossible.
            if (state_off && base + state_off + 4 <= got) {
                u32 state = 0;
                std::memcpy(&state, buf.data() + base + state_off, 4);
                if (state > 0x1ff) continue;
            }

            // Cross-validation: tasks.next points (kernel-VA) to ANOTHER
            // task_struct's `tasks` field. Convert to PA via direct_map and
            // verify the destination also has a plausible comm. This kills
            // string-coincidence false positives like `libEGL.so.1` at the
            // right offset with a usable-looking pid byte.
            const u64 dmap = eng.kernel().direct_map_base;
            if (dmap != 0 && tnext > dmap) {
                PAddr next_task_pa = (tnext - dmap) - tasks_off;
                if (next_task_pa < phys.max_address()) {
                    u8 ncomm[16] = {};
                    if (phys.read(next_task_pa + comm_off, ncomm, 16) == 16) {
                        if (!plausible_comm(ncomm)) continue;
                    } else {
                        continue;
                    }
                } else {
                    continue;
                }
            }
            // ----------------------------------------------------------------

            PsScanHit h{};
            h.task_pa = pa + base;
            h.pid     = pid;
            h.tgid    = tgid;
            h.comm    = comm;
            // Visible if any of:
            //   - exact (pid, comm) match in eng.processes()
            //   - pid 0 swapper kthread (our process list skips these)
            //   - tgid matches a known leader pid (this is a thread of a
            //     visible process — only the leader appears in processes())
            h.on_official_list =
                known.count({pid, comm}) > 0 ||
                (pid == 0 && comm.compare(0, 8, "swapper/") == 0) ||
                (tgid != pid && known_pids.count(tgid) > 0);
            out.push_back(std::move(h));
            ++sanity_passed;
        }
        pa += kChunk;
    }
    log::info("psscan: {} signature hits → {} passed sanity (scanned {} MB)",
              signature_hits, sanity_passed, maxa / (1024 * 1024));
    return out;
}

ByteBuf format_findevil_psscan(const Engine& eng) {
    auto hits = scan_for_tasks(eng);
    std::size_t hidden = 0;
    for (const auto& h : hits) if (!h.on_official_list) ++hidden;

    std::string out;
    out.reserve(64 * 1024);
    out += fmt::format(
        "# psscan — physical-memory cross-view of task_struct signatures.\n"
        "#\n"
        "# This is a SECONDARY check — the canonical process list is at\n"
        "# /sys/processes/pslist.txt and /proc/<pid>-<comm>/. psscan exists\n"
        "# to surface things the canonical walk would miss:\n"
        "#\n"
        "#   * threads of a visible process (pid != tgid). We list them as\n"
        "#     `visible` here even though they aren't in /proc — thread\n"
        "#     enumeration is on the roadmap.\n"
        "#   * task_structs whose slab page is still in memory but which\n"
        "#     have been unlinked from init_task.tasks (DKOM rootkit).\n"
        "#   * exited processes whose slab hasn't been reused yet.\n"
        "#\n"
        "# Only entries marked HIDDEN are unambiguously suspicious.\n"
        "#\n"
        "# {} candidates total, {} NOT in the official process list (HIDDEN).\n#\n"
        "# pid    tgid     status      task_pa             comm\n"
        "#------+--------+-----------+-------------------+--------\n",
        hits.size(), hidden);
    // Sort: hidden first so analyst sees them immediately.
    std::stable_sort(hits.begin(), hits.end(),
        [](const PsScanHit& a, const PsScanHit& b) {
            if (a.on_official_list != b.on_official_list)
                return !a.on_official_list;
            return a.pid < b.pid;
        });
    for (const auto& h : hits) {
        out += fmt::format("{:>6}  {:>6}  {:<10}  {:#018x}  {}\n",
                           h.pid, h.tgid,
                           h.on_official_list ? "visible" : "HIDDEN",
                           h.task_pa, h.comm);
    }
    return ByteBuf(out.begin(), out.end());
}

// ================================================================
// HIDDEN_MODULES — scan vmalloc for kernel module signatures
// ================================================================

namespace {

// A loaded module has a recognizable name byte string at a known offset
// inside its `struct module` (offset 0x18 on 6.x x86_64). Names are
// printable, NUL-terminated, ≤ 56 chars.
bool plausible_modname(const u8* p, std::size_t len) {
    if (len < 2) return false;
    if (p[0] < 0x20 || p[0] >= 0x7F) return false;
    bool seen_nul = false;
    for (std::size_t i = 0; i < len; ++i) {
        u8 c = p[i];
        if (c == 0) { seen_nul = true; continue; }
        if (seen_nul) return false;
        if (c < 0x20 || c >= 0x7F) return false;
        // Module names contain underscores, dashes, alphanumeric.
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-')) return false;
    }
    return seen_nul;
}

} // anon

std::vector<HiddenModuleHit> scan_for_modules(const Engine& eng) {
    std::vector<HiddenModuleHit> out;

    // Known modules from the official `modules` linked-list walk.
    auto visible = enumerate_modules(eng);
    for (const auto& m : visible) {
        HiddenModuleHit h{};
        h.name             = m.name;
        h.mod_va           = m.module_va;
        h.on_official_list = true;
        out.push_back(std::move(h));
    }

    // Cross-view: count kallsyms entries in the module address range
    // (0xffffffffc0000000+) that fall OUTSIDE any visible module's
    // memory range. Each such "orphan symbol" is a hint that a hidden
    // module is loaded — a rootkit can unlink from the `modules` list
    // but typically forgets to scrub kallsyms.
    const auto& ks = eng.kallsyms();
    constexpr u64 kModuleArea = 0xffffffffc0000000ULL;
    std::size_t orphan_syms = 0, total_module_syms = 0;
    if (ks.ok) {
        for (const auto& s : ks.symbols) {
            if (s.address < kModuleArea) continue;
            ++total_module_syms;
            bool covered = false;
            for (const auto& m : visible) {
                for (const auto& mem : m.mem) {
                    if (mem.base == 0 || mem.size == 0) continue;
                    if (s.address >= mem.base &&
                        s.address <  mem.base + mem.size) {
                        covered = true; break;
                    }
                }
                if (covered) break;
            }
            if (!covered) ++orphan_syms;
        }
    }

    if (orphan_syms > 0) {
        // We don't have per-symbol module attribution — record a single
        // synthetic "hidden module suspected" entry with the count.
        HiddenModuleHit h{};
        h.name = fmt::format("(suspected hidden module — {} orphan kallsyms "
                             "entries in module memory not covered by any "
                             "visible module's range; total in-range syms = {})",
                             orphan_syms, total_module_syms);
        h.on_official_list = false;
        out.push_back(std::move(h));
    }

    std::sort(out.begin(), out.end(),
        [](const HiddenModuleHit& a, const HiddenModuleHit& b) {
            if (a.on_official_list != b.on_official_list)
                return !a.on_official_list;
            return a.name < b.name;
        });
    return out;
}

ByteBuf format_findevil_hidden_modules(const Engine& eng) {
    auto hits = scan_for_modules(eng);
    std::size_t hidden = 0;
    for (const auto& h : hits) if (!h.on_official_list) ++hidden;

    std::string out;
    out.reserve(4 * 1024);
    out += fmt::format(
        "# hidden_modules — diff between the `modules` list walk\n"
        "#                  and kallsyms' module-symbol ranges.\n"
        "# {} module-name records, {} of them NOT in the visible list.\n"
        "# (entries marked HIDDEN are suspicious — a rootkit may have\n"
        "#  unlinked them from `modules` but missed the kallsyms tree.)\n#\n"
        "# status      name\n"
        "#-----------+----------------------------------------\n",
        hits.size(), hidden);
    for (const auto& h : hits) {
        out += fmt::format("  {:<10}  {}\n",
                           h.on_official_list ? "visible" : "HIDDEN",
                           h.name);
    }
    return ByteBuf(out.begin(), out.end());
}

// ================================================================
// AGGREGATED — findevil.txt
// ================================================================

namespace {

std::string one_line_text(ByteBuf b, std::size_t max = 220) {
    std::string s(b.begin(), b.end());
    for (char& c : s) {
        if (c == '\0' || c == '\r' || c == '\n' || c == '\t') c = ' ';
    }
    while (!s.empty() && s.back() == ' ') s.pop_back();
    if (s.size() > max) s.resize(max);
    return s.empty() ? std::string("-") : s;
}

std::string lower_copy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool name_contains_any(const std::string& value, std::initializer_list<const char*> names) {
    auto l = lower_copy(value);
    for (const char* n : names)
        if (l.find(n) != std::string::npos) return true;
    return false;
}

bool expected_jit_comm(const std::string& comm) {
    return name_contains_any(comm, {
        "firefox", "chrome", "chromium", "node", "java", "qemu",
        "electron", "code", "gnome-shell", "webkit", "python", "gjs"
    });
}

bool shell_like_comm(const std::string& comm) {
    auto l = lower_copy(comm);
    return l == "bash" || l == "zsh" || l == "fish" || l == "sh" ||
           l == "dash" || l == "ksh" || l == "tcsh" || l == "csh";
}

bool admin_or_dump_comm(const std::string& comm) {
    auto l = lower_copy(comm);
    return l == "sudo" || l == "su" || l == "doas" || l == "pkexec" ||
           l == "avml" || l.find("lime") != std::string::npos ||
           l == "insmod" || l == "modprobe" || l == "rmmod" ||
           l == "apt" || l == "apt-get" || l == "dnf" || l == "dnf5" ||
           l == "yum" || l == "rpm" || l == "pacman";
}

bool network_tool_comm(const std::string& comm) {
    auto l = lower_copy(comm);
    return l == "nc" || l == "ncat" || l == "socat" || l == "curl" ||
           l == "wget" || l == "ssh" || l == "sshd" || l == "python" ||
           l == "python3" || l == "perl" || l == "ruby" || l == "openssl";
}

std::string proc_cmdline(const Engine& eng, const Process& p) {
    try { return one_line_text(gen_cmdline(eng.phys(), eng.isf(), eng.kernel(), p)); }
    catch (...) { return "-"; }
}

u64 effective_caps(const Engine& eng, const Process& p) {
    try {
        u64 cred_off = eng.isf().field_offset("task_struct", "cred");
        u64 cap_off = eng.isf().field_offset("cred", "cap_effective");
        VAddr cred = 0;
        if (!kva_read_pod(eng, p.task_va + cred_off, cred) || cred == 0) return 0;
        u64 caps = 0;
        kva_read_pod(eng, cred + cap_off, caps);
        return caps;
    } catch (...) {
        return 0;
    }
}

void sort_findings(std::vector<Finding>& fs) {
    std::stable_sort(fs.begin(), fs.end(), [](const Finding& a, const Finding& b) {
        int ar = severity_rank(a.severity), br = severity_rank(b.severity);
        if (ar != br) return ar < br;
        if (a.confidence != b.confidence) return a.confidence > b.confidence;
        if (a.pid != b.pid) return a.pid < b.pid;
        return a.type < b.type;
    });
}

} // anonymous

int severity_rank(const std::string& severity) {
    if (severity == "HIGH") return 0;
    if (severity == "MEDIUM") return 1;
    if (severity == "REVIEW") return 2;
    return 3;
}

std::vector<Finding> collect_findevil_indicators(const Engine& eng) {
    std::vector<Finding> out;
    std::unordered_map<u32, Process> by_pid;
    for (const auto& p : eng.processes()) by_pid[p.pid] = p;

    try {
        for (const auto& h : scan_for_tasks(eng)) {
            if (h.on_official_list) continue;
            Finding f;
            f.severity = "HIGH"; f.confidence = "medium";
            f.type = "PROC_HIDDEN"; f.source = "psscan";
            f.pid = h.pid; f.tgid = h.tgid; f.comm = h.comm;
            f.summary = fmt::format("task_struct seen in physical scan but not visible list: pid={} comm={}", h.pid, h.comm);
            f.evidence = fmt::format("task_pa={:#x}", h.task_pa);
            f.false_positive_note = "Can be acquisition drift or freed task slabs; inspect psscan details before calling compromise.";
            f.next_step = "/sys/findevil/psscan.txt";
            out.push_back(std::move(f));
        }
    } catch (...) {}

    try {
        for (const auto& h : scan_for_modules(eng)) {
            if (h.on_official_list) continue;
            Finding f;
            f.severity = "HIGH"; f.confidence = "medium";
            f.type = "KMOD_HIDDEN"; f.source = "hidden_modules";
            f.summary = fmt::format("module-like object not present in module list: {}", h.name);
            f.evidence = fmt::format("module_va={:#x}", h.mod_va);
            f.false_positive_note = "Can be stale module memory; confirm with modxview/check_modules.";
            f.next_step = "/sys/findevil/hidden_modules.txt";
            out.push_back(std::move(f));
        }
    } catch (...) {}

    try {
        for (const auto& s : check_syscall_table(eng)) {
            if (s.status != SyscallEntry::HOOKED && s.status != SyscallEntry::SUSPICIOUS) continue;
            Finding f;
            f.severity = s.status == SyscallEntry::HOOKED ? "HIGH" : "MEDIUM";
            f.confidence = s.status == SyscallEntry::HOOKED ? "high" : "medium";
            f.type = s.status == SyscallEntry::HOOKED ? "KERNEL_SYSCALL_HOOK" : "KERNEL_SYSCALL_SUSPICIOUS";
            f.source = "check_syscall";
            f.summary = fmt::format("syscall table entry {} points to {}", s.nr, s.resolved_name);
            f.evidence = fmt::format("nr={} target={:#x} note={}", s.nr, s.entry_addr, s.note);
            f.false_positive_note = "HOOKED means outside kernel text; SUSPICIOUS means symbol naming did not match syscall conventions.";
            f.next_step = "/sys/findevil/check_syscall.txt";
            out.push_back(std::move(f));
        }
    } catch (...) {}

    try {
        for (const auto& e : audit_idt(eng)) {
            if (e.audit.status != PtrAudit::HOOKED && e.audit.status != PtrAudit::SUSPICIOUS) continue;
            Finding f;
            f.severity = e.audit.status == PtrAudit::HOOKED ? "HIGH" : "MEDIUM";
            f.confidence = e.audit.status == PtrAudit::HOOKED ? "high" : "medium";
            f.type = e.audit.status == PtrAudit::HOOKED ? "KERNEL_IDT_HOOK" : "KERNEL_IDT_SUSPICIOUS";
            f.source = "check_idt";
            f.summary = fmt::format("IDT vector {} handler audit note {}", e.vector, e.audit.note);
            f.evidence = fmt::format("handler={:#x} symbol={}", e.audit.addr, e.audit.resolved);
            f.false_positive_note = "Unexpected IDT handlers are high signal, but verify symbol recovery and kernel text range.";
            f.next_step = "/sys/findevil/check_idt.txt";
            out.push_back(std::move(f));
        }
    } catch (...) {}

    try {
        for (const auto& k : enumerate_kprobes(eng)) {
            if (k.pre_audit.status != PtrAudit::HOOKED && k.post_audit.status != PtrAudit::HOOKED) continue;
            Finding f;
            f.severity = "HIGH"; f.confidence = "high";
            f.type = "KERNEL_KPROBE_HOOK"; f.source = "kprobes";
            f.summary = fmt::format("kprobe handler points outside expected kernel text: {}", k.symbol_name);
            f.evidence = fmt::format("addr={:#x} pre={:#x} post={:#x}", k.addr, k.pre_handler, k.post_handler);
            f.false_positive_note = "Kprobes are legitimate for tracing; hooked handler pointers are the suspicious part.";
            f.next_step = "/sys/findevil/kprobes.txt";
            out.push_back(std::move(f));
        }
    } catch (...) {}

    try {
        for (const auto& bp : enumerate_bpf_programs(eng)) {
            if (!(bp.type == 2 || bp.type == 5 || bp.type == 17 || bp.type == 26 || bp.type == 29)) continue;
            Finding f;
            f.severity = "REVIEW"; f.confidence = "medium";
            f.type = "EBPF_TRACING_PROGRAM"; f.source = "ebpf";
            f.summary = fmt::format("loaded tracing-capable eBPF program: {}", bp.name.empty() ? "(unnamed)" : bp.name);
            f.evidence = fmt::format("id={} type={} tag={}", bp.id, bpf_prog_type_name(bp.type), bp.tag_hex);
            f.false_positive_note = "Tracing eBPF is common on modern systems; malicious use needs hook/context review.";
            f.next_step = "/sys/findevil/ebpf.txt";
            out.push_back(std::move(f));
        }
    } catch (...) {}

    for (const auto& p : eng.processes()) {
        auto cmd = proc_cmdline(eng, p);
        try {
            auto mal = find_malfind(eng, p);
            std::size_t high_entropy = 0;
            try {
                for (const auto& e : scan_entropy(eng, p)) if (e.entropy >= 7.0) ++high_entropy;
            } catch (...) {}
            for (const auto& h : mal) {
                Finding f;
                f.severity = h.high_severity ? "HIGH" : (expected_jit_comm(p.comm) ? "REVIEW" : "MEDIUM");
                f.confidence = h.high_severity ? "high" : "medium";
                f.type = h.high_severity ? "PROC_PRIVATE_RWX" : "PROC_ANON_EXEC";
                f.source = "malfind";
                f.pid = p.pid; f.tgid = p.tgid; f.uid = p.uid; f.comm = p.comm;
                f.summary = fmt::format("{} anonymous executable memory in {}", h.high_severity ? "RWX/exec-stack" : "RX", p.comm);
                f.evidence = fmt::format("range={:#x}-{:#x} perms={} content={} entropy_hits={} cmdline={}",
                    h.vm_start, h.vm_end, flag_str(h.vm_flags), h.content_hint.empty() ? "-" : h.content_hint, high_entropy, cmd);
                f.false_positive_note = h.high_severity
                    ? "Some JIT runtimes use RWX, but unexpected RWX anonymous memory is a strong injection marker."
                    : "RX anonymous memory is normal for JIT runtimes and also matches post-mprotect injected payloads.";
                f.next_step = fmt::format("/proc/{}-{}/malfind.txt", p.pid, p.comm);
                out.push_back(std::move(f));
            }
        } catch (...) {}

        u64 caps = effective_caps(eng, p);
        if (p.uid != 0 && caps != 0) {
            Finding f;
            f.severity = "MEDIUM"; f.confidence = "medium";
            f.type = "PROC_NONROOT_CAPS"; f.source = "credentials";
            f.pid = p.pid; f.tgid = p.tgid; f.uid = p.uid; f.comm = p.comm;
            f.summary = "non-root process has effective Linux capabilities";
            f.evidence = fmt::format("cap_effective={:#x} cmdline={}", caps, cmd);
            f.false_positive_note = "Services may legitimately carry narrow capabilities; broad or unexpected caps deserve review.";
            f.next_step = fmt::format("/proc/{}-{}/capabilities", p.pid, p.comm);
            out.push_back(std::move(f));
        }

        auto parent = by_pid.find(p.ppid);
        std::string parent_comm = parent == by_pid.end() ? "" : parent->second.comm;
        if (admin_or_dump_comm(p.comm) || shell_like_comm(p.comm)) {
            Finding f;
            f.severity = admin_or_dump_comm(p.comm) ? "REVIEW" : "INFO";
            f.confidence = "medium";
            f.type = admin_or_dump_comm(p.comm) ? "PROC_ADMIN_OR_ACQUISITION_TOOL" : "PROC_SHELL_ACTIVITY";
            f.source = "process_context";
            f.pid = p.pid; f.tgid = p.tgid; f.uid = p.uid; f.comm = p.comm;
            f.summary = fmt::format("{} running with parent {}", p.comm, parent_comm.empty() ? "(unknown)" : parent_comm);
            f.evidence = fmt::format("ppid={} parent={} cmdline={}", p.ppid, parent_comm.empty() ? "-" : parent_comm, cmd);
            f.false_positive_note = "Administrative and shell activity is context, not compromise by itself.";
            f.next_step = fmt::format("/proc/{}-{}/status", p.pid, p.comm);
            out.push_back(std::move(f));
        }

        try {
            auto fds = enumerate_fds(eng, p);
            std::size_t socket_fds = 0, network_socket_fds = 0, deleted_fds = 0;
            std::string sample;
            for (const auto& fd : fds) {
                auto lt = lower_copy(fd.target);
                if (lt.find("socket:") != std::string::npos) {
                    ++socket_fds;
                    if (lt.find("tcp") != std::string::npos || lt.find("udp") != std::string::npos || lt.find("unix") != std::string::npos) {
                        ++network_socket_fds;
                        if (sample.empty()) sample = fd.target;
                    }
                }
                if (lt.find("deleted") != std::string::npos || lt.find("anon/no-name") != std::string::npos) {
                    ++deleted_fds;
                    if (sample.empty()) sample = fd.target;
                }
            }
            if ((network_tool_comm(p.comm) && socket_fds) || deleted_fds) {
                Finding f;
                f.severity = deleted_fds ? "MEDIUM" : "REVIEW";
                f.confidence = "medium";
                f.type = deleted_fds ? "PROC_DELETED_OR_ORPHAN_FD" : "PROC_NETWORK_TOOL_SOCKET";
                f.source = "fd_table";
                f.pid = p.pid; f.tgid = p.tgid; f.uid = p.uid; f.comm = p.comm;
                f.summary = deleted_fds ? "process has deleted/orphan-looking file descriptor evidence" : "network-capable process owns socket descriptors";
                f.evidence = fmt::format("socket_fds={} network_socket_fds={} deleted_or_orphan_fds={} sample={} cmdline={}",
                    socket_fds, network_socket_fds, deleted_fds, sample.empty() ? "-" : sample, cmd);
                f.false_positive_note = deleted_fds
                    ? "Deleted fds are common during updates/log rotation; executable or unexpected owners matter most."
                    : "Network tools are often legitimate; correlate with shell history and timeline.";
                f.next_step = fmt::format("/proc/{}-{}/fd_table.txt", p.pid, p.comm);
                out.push_back(std::move(f));
            }
        } catch (...) {}
    }

    sort_findings(out);
    return out;
}

ByteBuf format_findevil_indicators_txt(const Engine& eng) {
    auto fs = collect_findevil_indicators(eng);
    std::string out;
    out.reserve(64 * 1024);
    out += "# /sys/findevil/indicators.txt - normalized ranked indicators\n";
    out += "# Severity is conservative: ambiguous desktop/JIT/admin behavior is REVIEW/INFO unless stronger evidence exists.\n";
    out += "# Missing rows are not proof the host is clean; inspect unavailable/partial notes in the raw check files.\n\n";
    out += fmt::format("total indicators: {}\n\n", fs.size());
    out += "sev     conf    type                         pid     uid   comm              summary\n";
    out += "------- ------- ---------------------------- ------- ----- ----------------- -------\n";
    for (const auto& f : fs) {
        out += fmt::format("{:<7} {:<7} {:<28} {:>7} {:>5} {:<17} {}\n",
            f.severity, f.confidence, f.type, f.pid, f.uid, f.comm, f.summary);
        out += fmt::format("        source={} evidence={}\n", f.source, f.evidence.empty() ? "-" : f.evidence);
        if (!f.false_positive_note.empty()) out += fmt::format("        false-positive/context: {}\n", f.false_positive_note);
        if (!f.next_step.empty()) out += fmt::format("        next-step: {}\n", f.next_step);
    }
    if (fs.empty()) out += "checked: no normalized indicators were produced by available checks.\n";
    return ByteBuf(out.begin(), out.end());
}

ByteBuf format_findevil_indicators_csv(const Engine& eng) {
    auto fs = collect_findevil_indicators(eng);
    std::string out;
    out += "severity,confidence,type,source,pid,tgid,uid,comm,summary,evidence,false_positive_note,next_step\r\n";
    for (const auto& f : fs) {
        out += fmt::format("{},{},{},{},{},{},{},{},{},{},{},{}\r\n",
            csv_quote(f.severity), csv_quote(f.confidence), csv_quote(f.type), csv_quote(f.source),
            f.pid, f.tgid, f.uid, csv_quote(f.comm), csv_quote(f.summary),
            csv_quote(f.evidence), csv_quote(f.false_positive_note), csv_quote(f.next_step));
    }
    return ByteBuf(out.begin(), out.end());
}

ByteBuf format_findevil_indicators_json(const Engine& eng) {
    using nlohmann::json;
    json rows = json::array();
    for (const auto& f : collect_findevil_indicators(eng)) {
        rows.push_back({
            {"severity", f.severity}, {"confidence", f.confidence},
            {"type", f.type}, {"source", f.source},
            {"pid", f.pid}, {"tgid", f.tgid}, {"uid", f.uid},
            {"comm", f.comm}, {"summary", f.summary},
            {"evidence", f.evidence},
            {"false_positive_note", f.false_positive_note},
            {"next_step", f.next_step}
        });
    }
    std::string s = rows.dump(2, ' ', false, json::error_handler_t::replace);
    s.push_back('\n');
    return ByteBuf(s.begin(), s.end());
}

ByteBuf format_findevil_triage(const Engine& eng) {
    auto fs = collect_findevil_indicators(eng);
    std::size_t high = 0, med = 0, review = 0, info = 0;
    std::size_t kernel = 0, proc = 0, net = 0;
    for (const auto& f : fs) {
        if (f.severity == "HIGH") ++high;
        else if (f.severity == "MEDIUM") ++med;
        else if (f.severity == "REVIEW") ++review;
        else ++info;
        if (f.type.rfind("KERNEL_", 0) == 0 || f.type.rfind("KMOD_", 0) == 0) ++kernel;
        else if (f.type.rfind("PROC_NETWORK", 0) == 0) ++net;
        else if (f.type.rfind("PROC_", 0) == 0) ++proc;
    }
    std::string out;
    out.reserve(32 * 1024);
    out += "# /sys/findevil/triage.txt - ranked threat-hunt entry point\n";
    out += "# This consumes /sys/findevil/indicators.*. Missing findings are not proof that the host is clean.\n";
    out += "# Severity is conservative: ambiguous JIT/admin/network behavior remains REVIEW/INFO.\n\n";
    out += fmt::format(
        "[summary]\n"
        "total indicators: {}\n"
        "severity: HIGH={} MEDIUM={} REVIEW={} INFO={}\n"
        "families: kernel={} process={} network={}\n\n",
        fs.size(), high, med, review, info, kernel, proc, net);

    out += "[highest priority]\n";
    if (fs.empty()) {
        out += "checked: no normalized indicators were produced by available checks.\n";
    } else {
        std::size_t limit = std::min<std::size_t>(fs.size(), 40);
        for (std::size_t i = 0; i < limit; ++i) {
            const auto& f = fs[i];
            out += fmt::format(
                "{} {} conf={} pid={} uid={} comm={} source={} summary={}\n"
                "    evidence={}\n"
                "    context={}\n"
                "    next={}\n",
                f.severity, f.type, f.confidence, f.pid, f.uid, f.comm,
                f.source, f.summary,
                f.evidence.empty() ? "-" : f.evidence,
                f.false_positive_note.empty() ? "-" : f.false_positive_note,
                f.next_step.empty() ? "-" : f.next_step);
        }
        if (fs.size() > limit)
            out += fmt::format("... {} more indicator row(s); see /sys/findevil/indicators.txt\n", fs.size() - limit);
    }

    out += "\n[next steps]\n";
    out += "- Open /sys/findevil/indicators.txt for the full ranked indicator set.\n";
    out += "- Open /sys/findevil/findevil.txt for legacy aggregate counters.\n";
    out += "- Open /forensic/timeline/findevil.txt to place high-signal findings in time context.\n";
    return ByteBuf(out.begin(), out.end());
}
ByteBuf format_findevil_summary(const Engine& eng) {
    std::size_t mal_pids = 0, mal_hits = 0, mal_high = 0, mal_high_pids = 0;
    for (const auto& p : eng.processes()) {
        std::vector<MalfindHit> h;
        try { h = find_malfind(eng, p); } catch (...) { continue; }
        if (h.empty()) continue;
        ++mal_pids; mal_hits += h.size();
        bool any_high = false;
        for (const auto& x : h) if (x.high_severity) { ++mal_high; any_high = true; }
        if (any_high) ++mal_high_pids;
    }
    auto ps = scan_for_tasks(eng);
    std::size_t hidden_tasks = 0;
    for (const auto& h : ps) if (!h.on_official_list) ++hidden_tasks;
    auto hm = scan_for_modules(eng);
    std::size_t hidden_mods = 0;
    for (const auto& h : hm) if (!h.on_official_list) ++hidden_mods;

    auto syscalls = check_syscall_table(eng);
    std::size_t syscall_hooked = 0, syscall_susp = 0;
    for (const auto& s : syscalls) {
        if (s.status == SyscallEntry::HOOKED)     ++syscall_hooked;
        else if (s.status == SyscallEntry::SUSPICIOUS) ++syscall_susp;
    }

    auto tty = audit_tty_drivers(eng);
    std::size_t tty_total = 0, tty_hooked = 0, tty_susp = 0;
    for (const auto& d : tty)
        for (const auto& p : d.ops) {
            ++tty_total;
            if (p.status == PtrAudit::HOOKED)        ++tty_hooked;
            else if (p.status == PtrAudit::SUSPICIOUS) ++tty_susp;
        }

    auto kbd = audit_keyboard_notifiers(eng);
    std::size_t kbd_hooked = 0, kbd_susp = 0;
    for (const auto& e : kbd) {
        if (e.call.status == PtrAudit::HOOKED)        ++kbd_hooked;
        else if (e.call.status == PtrAudit::SUSPICIOUS) ++kbd_susp;
    }

    // v0.13 — Tier-5A integrity checks
    auto idt = audit_idt(eng);
    std::size_t idt_hooked = 0, idt_susp = 0;
    for (const auto& e : idt) {
        if (e.audit.status == PtrAudit::HOOKED)        ++idt_hooked;
        else if (e.audit.status == PtrAudit::SUSPICIOUS) ++idt_susp;
    }
    auto afi = audit_afinfo(eng);
    std::size_t afi_hooked = 0, afi_susp = 0;
    std::size_t afi_slots = 0;
    for (const auto& a : afi)
        for (const auto& s : a.slots) {
            ++afi_slots;
            if (s.status == PtrAudit::HOOKED)        ++afi_hooked;
            else if (s.status == PtrAudit::SUSPICIOUS) ++afi_susp;
        }
    auto creds = audit_creds(eng);
    std::size_t cred_susp = 0;
    for (const auto& c : creds) if (c.suspicious) ++cred_susp;
    auto modx = audit_modules_cross(eng);
    std::size_t mod_asym = 0;
    for (const auto& m : modx)
        if (m.in_list_walk != m.in_mod_tree) ++mod_asym;

    // v0.14 — eBPF + entropy
    auto bpf_progs = enumerate_bpf_programs(eng);
    std::size_t bpf_tracing = 0;
    for (const auto& b : bpf_progs) {
        // Tracing/KPROBE/RAW_TRACEPOINT/LSM types are the modern-rootkit
        // ones; surface their count so the analyst notices them.
        // bpf_prog_type values: KPROBE=2, TRACEPOINT=5, RAW_TRACEPOINT=17,
        // TRACING=26, LSM=29.
        if (b.type == 2 || b.type == 5 || b.type == 17 ||
            b.type == 26 || b.type == 29)
            ++bpf_tracing;
    }
    std::size_t entropy_pids = 0, entropy_hits = 0;
    for (const auto& p : eng.processes()) {
        if (p.mm == 0) continue;
        std::vector<EntropyHit> hs;
        try { hs = scan_entropy(eng, p); } catch (...) { continue; }
        bool any_high = false;
        for (const auto& h : hs) if (h.entropy >= 7.0) {
            ++entropy_hits; any_high = true;
        }
        if (any_high) ++entropy_pids;
    }

    // v0.16 — kprobes
    auto kps = enumerate_kprobes(eng);
    std::size_t kp_hooked = 0;
    for (const auto& k : kps) {
        if (k.pre_audit.status == PtrAudit::HOOKED ||
            k.post_audit.status == PtrAudit::HOOKED)
            ++kp_hooked;
    }

    // v0.20 — AV/EDR fingerprint counts (informational; not a "bad" signal)
    auto ae_hits = scan_av_edr(eng);
    std::size_t ae_proc = 0, ae_mod = 0;
    for (const auto& h : ae_hits) {
        if (h.source == AvEdrHit::Source::Process) ++ae_proc;
        else                                       ++ae_mod;
    }

    std::string out;
    out.reserve(8 * 1024);
    out += "# Findevil — aggregated threat-hunt findings\n";
    out += "# (See /sys/findevil/{malfind,psscan,hidden_modules}.txt for detail.)\n#\n";
    out += fmt::format("malfind:         {} anon-exec region(s) across {} process(es); "
                       "{} RWX/exec-stack marker(s) across {} process(es)\n"
                       "                 (vDSO/signal pages excluded; RX-anon is "
                       "JIT-or-injected — see REVIEW below + malfind.txt).\n",
                       mal_hits, mal_pids, mal_high, mal_high_pids);
    out += fmt::format("psscan:          {} task candidates by phys scan, "
                       "{} NOT in visible list (HIDDEN)\n",
                       ps.size(), hidden_tasks);
    out += fmt::format("hidden_modules:  {} module record(s), "
                       "{} NOT in `modules` list (HIDDEN)\n",
                       hm.size(), hidden_mods);
    out += fmt::format("check_syscall:   {} syscalls scanned, "
                       "{} HOOKED (outside kernel text), {} SUSPICIOUS\n",
                       syscalls.size(), syscall_hooked, syscall_susp);
    out += fmt::format("tty_check:       {} driver(s), {} ops audited, "
                       "{} HOOKED, {} SUSPICIOUS\n",
                       tty.size(), tty_total, tty_hooked, tty_susp);
    out += fmt::format("keyboard_notify: {} notifier(s) in chain, "
                       "{} HOOKED, {} SUSPICIOUS\n",
                       kbd.size(), kbd_hooked, kbd_susp);
    out += fmt::format("check_idt:       256 IDT entries, "
                       "{} HOOKED, {} SUSPICIOUS\n",
                       idt_hooked, idt_susp);
    out += fmt::format("check_afinfo:    {} /proc/net protocols, "
                       "{} ops scanned, {} HOOKED, {} SUSPICIOUS\n",
                       afi.size(), afi_slots, afi_hooked, afi_susp);
    out += fmt::format("check_creds:     {} unique creds across visible tasks, "
                       "{} flagged (root-cred sharing)\n",
                       creds.size(), cred_susp);
    out += fmt::format("check_modules:   {} module records cross-viewed, "
                       "{} asymmetric (in only one of: list / mod_tree)\n",
                       modx.size(), mod_asym);
    out += fmt::format("ebpf:            {} loaded eBPF program(s), "
                       "{} of TRACING/KPROBE/LSM type (modern rootkit primitives)\n",
                       bpf_progs.size(), bpf_tracing);
    out += fmt::format("entropy:         {} process(es) with high-entropy VMA(s), "
                       "{} hit(s) total (likely packed/encrypted)\n",
                       entropy_pids, entropy_hits);
    out += fmt::format("kprobes:         {} registered kprobe(s), "
                       "{} with HOOKED handler\n",
                       kps.size(), kp_hooked);
    out += fmt::format("av_edr:          {} userspace agent(s) running, "
                       "{} LKM agent(s) loaded (signature scan)\n",
                       ae_proc, ae_mod);
    out += "\n";

    // Kernel-level indicators are UNAMBIGUOUS (a rootkit hooked something or
    // hid a task/module) — these drive the verdict. Userspace anon-exec
    // (malfind) is deliberately NOT in here: it's ambiguous (every JIT runtime
    // trips it), so folding it into the verdict either cries wolf on a desktop
    // or — worse — gets hand-waved as "clean" when a real payload is RX-anon.
    // Instead we ALWAYS surface anon-exec as a REVIEW line below.
    const bool kernel_bad = (hidden_tasks > 0) || (hidden_mods > 0) ||
                            (syscall_hooked > 0) || (tty_hooked > 0) ||
                            (kbd_hooked > 0) || (idt_hooked > 0) ||
                            (afi_hooked > 0) || (cred_susp > 0) ||
                            (mod_asym > 0) || (kp_hooked > 0);
    if (kernel_bad) {
        out += "VERDICT: SUSPICIOUS — kernel-level compromise indicator(s) above\n"
               "         (hooks / hidden task / hidden module). Inspect the\n"
               "         per-check files.\n";
    } else {
        out += "VERDICT: no kernel-level compromise indicators by these checks\n"
               "         (heuristics — not a guarantee the box is clean).\n";
    }
    // Always surface userspace anon-exec — this is where injected code lives,
    // and silently calling it benign is exactly how a Meterpreter payload would
    // slip past.
    if (mal_pids > 0) {
        out += fmt::format(
            "\nREVIEW:  {} process(es) hold anonymous executable memory "
            "({} RWX/exec-stack marker(s)).\n"
            "         JIT runtimes (browser, node, JVM, gnome JS) trip this\n"
            "         legitimately — but injected code (Meterpreter, shellcode)\n"
            "         looks IDENTICAL. Open malfind.txt: a process you'd expect\n"
            "         to JIT is fine; an unexpected one with non-zero anon-exec\n"
            "         is a strong injection signal.\n",
            mal_pids, mal_high);
    }
    return ByteBuf(out.begin(), out.end());
}

} // namespace lmpfs::linux
