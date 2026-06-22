#include "os/linux/kernel_resolver.h"
#include "os/linux/banner_scan.h"
#include "os/linux/dtb_resolver.h"
#include "core/error.h"
#include "core/log.h"
#include <cstring>
#include <algorithm>
#include <vector>

namespace lmpfs::linux {

namespace {

// Scans the physical layer in CHUNK-sized buffers for the byte pattern
// "swapper" followed by ("/0" | 2 NUL bytes) followed by 6 NUL bytes.
// This is the `comm` field of init_task, whose offset back from the start of
// task_struct is well-known via ISF.
constexpr std::size_t kScanChunk = 4 * 1024 * 1024;

struct Match {
    PAddr pa;
};

bool match_swapper(const u8* p, std::size_t left) {
    // "swapper" = 7 bytes; then ("/0" or "\0\0") = 2 bytes; then 7x NUL.
    if (left < 16) return false;
    if (std::memcmp(p, "swapper", 7) != 0) return false;
    bool tail_ok = (p[7] == '/' && p[8] == '0') ||
                   (p[7] == 0   && p[8] == 0);
    if (!tail_ok) return false;
    for (int i = 9; i < 16; ++i) if (p[i] != 0) return false;
    return true;
}

std::vector<PAddr> scan_swapper(const PhysicalLayer& phys) {
    std::vector<PAddr> hits;
    std::vector<u8>    buf(kScanChunk + 16);
    PAddr maxa = phys.max_address();
    PAddr pa = 0;
    log::debug("Scanning {:.1f} MB for swapper signature...", maxa / (1024.0 * 1024));
    while (pa < maxa) {
        std::size_t want = std::min<u64>(kScanChunk + 16, maxa - pa);
        std::size_t got  = phys.read(pa, buf.data(), want);
        if (got == 0) { pa += kScanChunk; continue; }
        std::size_t scan_end = (got >= 16) ? (got - 16) : 0;
        for (std::size_t i = 0; i < scan_end; ++i) {
            if (match_swapper(buf.data() + i, got - i)) {
                hits.push_back(pa + i);
            }
        }
        pa += kScanChunk; // overlap of 16 handled by reading want=CHUNK+16
    }
    log::debug("Found {} swapper candidates", hits.size());
    return hits;
}

bool read_string(const PhysicalLayer& phys, PAddr pa, std::size_t max, std::string& out) {
    std::vector<u8> b(max);
    std::size_t got = phys.read(pa, b.data(), b.size());
    if (got == 0) return false;
    std::size_t n = 0;
    while (n < got && b[n]) ++n;
    out.assign(reinterpret_cast<char*>(b.data()), n);
    return true;
}

} // anonymous

// Scan the dump for ALL "Linux version " strings and return every implied shift.
// The kernel keeps multiple copies (image, printk log, /proc/version), so we
// need to pick the one whose shift is 2 MiB aligned (matches KASLR).
//
// In BTF-only mode (no `linux_banner` symbol in the ISF) we still scan for
// banner PAs — the shift value is meaningless without the symbol, so we
// report 0 there. Caller may still use the PA itself.
static std::vector<std::pair<PAddr, i64>>
banner_candidate_shifts(const PhysicalLayer& phys, const IsfSymbols& isf) {
    std::vector<std::pair<PAddr, i64>> out;
    auto sym = isf.find_symbol("linux_banner");
    const bool have_sym = (sym != nullptr);
    const PAddr static_pa = have_sym
        ? sym->address - 0xffffffff80000000ULL
        : 0;

    for (const auto& cand : scan_banner_candidates(phys)) {
        if (cand.score < 0) continue;
        i64 shift = have_sym
            ? static_cast<i64>(cand.pa) - static_cast<i64>(static_pa)
            : 0;
        out.emplace_back(cand.pa, shift);
    }
    return out;
}

// Compares the dump's actual "Linux version " banner with the ISF's
// metadata.name. They embed the same kernel release (e.g. "6.14.0-36-generic"),
// so the build number must appear in the banner. If it doesn't, the user
// almost certainly passed the wrong ISF — and we'd silently read struct
// fields at the wrong offsets, like we did before we caught this.
static void warn_if_isf_mismatch(const PhysicalLayer& phys, const IsfSymbols& isf) {
    auto sym = isf.find_symbol("linux_banner");
    if (!sym) return;
    auto banner = find_banner_in_dump(phys);
    if (banner.empty()) return;

    log::debug("Dump banner: {}", banner);
    const std::string& release = isf.kernel_release();
    if (!release.empty() && banner.find(release) == std::string::npos) {
        log::error("===========================================================");
        log::error("  ISF/dump MISMATCH! ISF is for kernel '{}' but the dump's", release);
        log::error("  banner reports a different kernel. Struct field offsets");
        log::error("  WILL be wrong (silently — many bugs look like this).");
        log::error("  Pick the matching .json.xz from the symbols directory.");
        log::error("===========================================================");
    }
}

KernelContext resolve_kernel(const PhysicalLayer& phys, const IsfSymbols& isf) {
    KernelContext ctx{};

    // init_task is OPTIONAL: full DWARF-derived ISFs have it (so we can
    // derive KASLR shift symbolically); BTF-derived ISFs only carry types,
    // so we fall back to direct-from-swapper-scan init_task discovery and a
    // best-effort KASLR shift (=0 unless banner symbol is also present).
    auto init_task_sym = isf.find_symbol("init_task");
    const bool have_symbols = (init_task_sym != nullptr);
    if (!have_symbols) {
        log::warn("ISF has no `init_task` symbol — running in BTF/types-only "
                  "mode. Process listing will work via direct-map; kernel-VA "
                  "reads (kallsyms, modules, dmesg, DTB walks) will be limited.");
    }

    warn_if_isf_mismatch(phys, isf);

    u64 task_struct_size = isf.type_size("task_struct");
    u64 comm_off         = isf.field_offset("task_struct", "comm");
    u64 pid_off          = isf.field_offset("task_struct", "pid");
    u64 tgid_off         = isf.field_offset("task_struct", "tgid");
    u64 tasks_off        = isf.field_offset("task_struct", "tasks");

    if (have_symbols)
        log::debug("init_task VA (pre-KASLR) = {:#x}", init_task_sym->address);
    log::debug("task_struct: size={:#x} pid@{:#x} comm@{:#x} tasks@{:#x}",
              task_struct_size, pid_off, comm_off, tasks_off);

    // First try a banner-based shift (robust against task_struct layout drift).
    auto banner_candidates = banner_candidate_shifts(phys, isf);
    log::debug("Banner string found at {} location(s)", banner_candidates.size());
    for (auto& [at, sh] : banner_candidates) {
        bool aligned_2mb = (sh & 0x1FFFFF) == 0;
        log::debug("  banner @ PA {:#x} shift={:#x} 2MB-aligned={}", at, sh, aligned_2mb);
    }

    auto hits = scan_swapper(phys);
    if (hits.empty()) throw_error("kernel: no swapper signature found");

    const VAddr init_task_sym_addr = have_symbols ? init_task_sym->address : 0;

    for (PAddr comm_pa : hits) {
        PAddr task_pa = (comm_pa >= comm_off) ? (comm_pa - comm_off) : 0;

        u32 pid = 0;
        bool ok_pid   = phys.read_pod(task_pa + pid_off, pid);
        u64 next = 0, prev = 0;
        bool ok_next  = phys.read_pod(task_pa + tasks_off + 0, next);
        bool ok_prev  = phys.read_pod(task_pa + tasks_off + 8, prev);

        // dump the comm bytes for sanity
        char buf[24] = {};
        phys.read(comm_pa, buf, 16);
        log::debug("comm bytes @ {:#x}: '{}' (raw: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x})",
                   comm_pa, buf, (u8)buf[0],(u8)buf[1],(u8)buf[2],(u8)buf[3],(u8)buf[4],
                   (u8)buf[5],(u8)buf[6],(u8)buf[7],(u8)buf[8]);
        log::debug("candidate: comm_pa={:#x} task_pa={:#x} pid={} (ok={}) next={:#x} prev={:#x} (ok={},{})",
                   comm_pa, task_pa, pid, ok_pid, next, prev, ok_next, ok_prev);

        if (!ok_pid || pid != 0)               continue;
        if (!ok_next || !ok_prev)              continue;
        if (next == 0 || prev == 0)            continue;

        // KASLR phys shift = task_pa - "static" PA for init_task at its ISF VA.
        // When BTF-only (no symbol), we don't know the static VA → leave shift 0.
        // Kernel-VA reads will be degraded but process listing (which uses the
        // direct map only) still works.
        i64 phys_shift = have_symbols
            ? static_cast<i64>(task_pa) -
              static_cast<i64>(kernel_va_to_pa_static(init_task_sym_addr, 0))
            : 0;
        log::debug("phys_shift candidate = {:#x} (low bits {:#x})",
                   phys_shift, phys_shift & 0x1FFFFF);

        // Use the same shift for virt: KASLR slides text by N pages,
        // and the physical relocation == virtual relocation in practice.
        ctx.kaslr_phys_shift = phys_shift;
        ctx.kaslr_virt_shift = phys_shift;
        ctx.init_task_va     = have_symbols
            ? init_task_sym_addr + ctx.kaslr_virt_shift
            : 0;
        ctx.init_task_pa     = task_pa;

        log::debug("init_task @ PA {:#x} (KASLR shift = {:#x})", task_pa, phys_shift);

        // Derive the direct-map base from init_task.tasks.next (a kernel
        // direct-map pointer to the first real task_struct). Multiple 1 GiB
        // aligned bases may map the sample below max_pa; validate the implied
        // task_struct instead of accepting the highest fitting base.
        constexpr u64 k1GB = 0x40000000ULL;
        VAddr dm_va_sample = next;
        PAddr maxa = phys.max_address();
        VAddr cand_base = dm_va_sample & ~(k1GB - 1);
        VAddr best_base = 0;
        int best_score = -1;
        auto printable_comm = [](const char* s) {
            if (s[0] < 0x20 || s[0] >= 0x7f) return false;
            for (int i = 0; i < 16 && s[i]; ++i) {
                unsigned char c = static_cast<unsigned char>(s[i]);
                if (c < 0x20 || c >= 0x7f) return false;
            }
            return true;
        };
        const VAddr init_tasks_runtime_a = have_symbols ? init_task_sym_addr + tasks_off : 0;
        const VAddr init_tasks_runtime_b = have_symbols ? init_task_sym_addr + ctx.kaslr_virt_shift + tasks_off : 0;
        for (VAddr base = cand_base, tries = 0; tries < 64 && base != 0; base -= k1GB, ++tries) {
            u64 sample_off = dm_va_sample - base;
            if (sample_off >= maxa || sample_off < tasks_off) continue;
            PAddr first_task_pa = static_cast<PAddr>(sample_off - tasks_off);
            if (first_task_pa + comm_off + 16 >= maxa) continue;

            u32 first_pid = 0, first_tgid = 0;
            u64 first_next = 0, first_prev = 0;
            char first_comm[16] = {};
            bool ok = phys.read_pod(first_task_pa + pid_off, first_pid) &&
                      phys.read_pod(first_task_pa + tgid_off, first_tgid) &&
                      phys.read_pod(first_task_pa + tasks_off + 0, first_next) &&
                      phys.read_pod(first_task_pa + tasks_off + 8, first_prev) &&
                      phys.read(first_task_pa + comm_off, first_comm, sizeof(first_comm)) == sizeof(first_comm);
            if (!ok) continue;

            int score = 0;
            if (first_pid > 0 && first_pid < 1'000'000) score += 2;
            if (first_tgid > 0 && first_tgid < 1'000'000) score += 1;
            if (printable_comm(first_comm)) score += 3;
            if (first_prev == init_tasks_runtime_a || first_prev == init_tasks_runtime_b) score += 4;
            if (first_next > base && (first_next - base) < maxa && (first_next - base) >= tasks_off) {
                PAddr second_task_pa = static_cast<PAddr>((first_next - base) - tasks_off);
                u32 second_pid = 0, second_tgid = 0;
                u64 second_prev = 0;
                char second_comm[16] = {};
                bool second_ok = phys.read_pod(second_task_pa + pid_off, second_pid) &&
                                 phys.read_pod(second_task_pa + tgid_off, second_tgid) &&
                                 phys.read_pod(second_task_pa + tasks_off + 8, second_prev) &&
                                 phys.read(second_task_pa + comm_off, second_comm, sizeof(second_comm)) == sizeof(second_comm);
                if (second_ok &&
                    second_pid > 0 && second_pid < 1'000'000 &&
                    second_tgid > 0 && second_tgid < 1'000'000 &&
                    printable_comm(second_comm) &&
                    second_prev == dm_va_sample) {
                    score += 4;
                }
            }
            std::size_t comm_len = 0;
            while (comm_len < sizeof(first_comm) && first_comm[comm_len]) ++comm_len;
            std::string comm_s(first_comm, comm_len);
            log::debug("direct-map candidate base={:#x} first_task_pa={:#x} pid={} tgid={} comm='{}' prev={:#x} score={}",
                       base, first_task_pa, first_pid, first_tgid, comm_s, first_prev, score);
            if (score > best_score) {
                best_score = score;
                best_base = base;
            }
            if (score >= 11) break;
        }
        if (best_base == 0) {
            throw_error("kernel: failed to derive validated direct-map base");
        }
        ctx.direct_map_base = best_base;
        log::debug("direct_map_base = {:#x} (sample PA = {:#x})",
                  ctx.direct_map_base, dm_va_sample - ctx.direct_map_base);

        // In BTF-only mode we have no init_task SYMBOL, so init_task_va was
        // left at 0 above. But we DID locate it physically (task_pa) and we
        // now have the direct-map base — and init_task's physical page is
        // covered by the direct map like all kernel RAM. So the direct-map
        // alias `direct_map_base + task_pa` is a usable kernel VA for it.
        // This is what lets mountinfo (and the dcache-tree page-cache walk it
        // seeds) follow init_task.nsproxy.mnt_ns without any DWARF/kallsyms
        // symbols. Reads through this VA go via the kva_reader direct-map
        // strategy, which works whenever direct_map_base is known.
        if (ctx.init_task_va == 0 && ctx.direct_map_base != 0)
            ctx.init_task_va = ctx.direct_map_base + task_pa;

        // -------- DTB resolution (multi-strategy, validated) ----------------
        // Hand off to dtb_resolver.cpp which tries banner-anchored shifts
        // first, then init_task-anchored, validating each by walking the
        // candidate PGD and confirming "Linux version " round-trips. In BTF-
        // only mode there are no symbols to drive this, so we skip it and run
        // in degraded mode (kernel-VA reads disabled).
        if (have_symbols) {
            try {
                auto dtb_result = resolve_dtb(phys, isf, task_pa, banner_candidates);
                ctx.dtb              = dtb_result.dtb;
                ctx.kaslr_phys_shift = dtb_result.phys_shift;
                ctx.kaslr_virt_shift = dtb_result.virt_shift;
                ctx.init_task_va     = init_task_sym_addr + ctx.kaslr_virt_shift;
                ctx.dtb_validated    = dtb_result.validated;
                ctx.dtb_strategy     = dtb_result.strategy;
                if (ctx.dtb_validated)
                    log::debug("DTB walks to banner OK — kernel-VA reads enabled");
            } catch (const std::exception& e) {
                log::warn("DTB resolution failed: {} — kernel-VA reads disabled", e.what());
                ctx.dtb           = 0;
                ctx.dtb_validated = false;
                ctx.dtb_strategy  = "none";
            }
        } else {
            log::debug("BTF-only ISF: skipping symbolic DTB resolution");
            ctx.dtb           = 0;
            ctx.dtb_validated = false;
            ctx.dtb_strategy  = "btf-types-only";
        }

        if (auto banner_sym = isf.find_symbol("linux_banner")) {
            PAddr banner_pa = kernel_va_to_pa_static(banner_sym->address, ctx.kaslr_phys_shift);
            read_string(phys, banner_pa, 512, ctx.banner);
        } else {
            // BTF-only: pick the banner directly from the dump scan.
            for (auto& [at, _] : banner_candidates) {
                std::string s; read_string(phys, at, 512, s);
                if (s.find("Linux version ") == 0) { ctx.banner = std::move(s); break; }
            }
        }
        return ctx;
    }
    throw_error("kernel: failed to validate init_task against any swapper hit");
}

} // namespace lmpfs::linux
