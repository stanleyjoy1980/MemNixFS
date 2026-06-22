// entropy.cpp — see header.
#include "os/linux/entropy.h"
#include "os/linux/vma.h"
#include "arch/x86_64/paging.h"
#include "app/engine.h"
#include "core/log.h"
#include <fmt/format.h>
#include <algorithm>
#include <cmath>

namespace lmpfs::linux {

namespace {

constexpr double kEntropyHighSeverityThreshold = 7.0;   // bits/byte
constexpr std::size_t kSamplePages = 8;                 // first N pages of each VMA

double shannon_entropy(const u8* buf, std::size_t n) {
    if (n == 0) return 0.0;
    std::array<u64, 256> freq{};
    for (std::size_t i = 0; i < n; ++i) ++freq[buf[i]];
    double H = 0.0;
    for (u64 c : freq) {
        if (c == 0) continue;
        double p = double(c) / double(n);
        H -= p * std::log2(p);
    }
    return H;
}

} // anonymous

std::vector<EntropyHit> scan_entropy(const Engine& eng, const Process& p) {
    std::vector<EntropyHit> out;
    if (p.mm == 0) return out;
    std::vector<Vma> vmas;
    try { vmas = enumerate_vmas(eng.phys(), eng.isf(), eng.kernel(), p); }
    catch (...) { return out; }

    // Resolve user PGD once per task (instead of per VMA).
    PAddr user_pgd_pa = resolve_user_pgd(eng.phys(), eng.isf(), eng.kernel(), p);
    if (user_pgd_pa == 0) return out;
    x86_64::PageTable upt(eng.phys(), user_pgd_pa);

    constexpr std::size_t kPageSize = 4096;
    std::vector<u8> buf(kSamplePages * kPageSize, 0);

    for (const auto& v : vmas) {
        if (!(v.vm_flags & 0x4)) continue;        // need VM_EXEC
        std::size_t size = v.vm_end - v.vm_start;
        if (size == 0) continue;
        std::size_t want = std::min(size, kSamplePages * kPageSize);
        std::size_t got = upt.read(v.vm_start, buf.data(), want);
        if (got == 0) continue;
        EntropyHit h{};
        h.vm_start       = v.vm_start;
        h.vm_end         = v.vm_end;
        h.vm_flags       = v.vm_flags;
        h.anonymous      = (v.vm_file == 0);
        h.entropy        = shannon_entropy(buf.data(), got);
        h.bytes_sampled  = got;
        out.push_back(std::move(h));
    }
    return out;
}

ByteBuf format_proc_entropy(const Engine& eng, const Process& p) {
    auto hits = scan_entropy(eng, p);
    std::string out;
    out.reserve(2 * 1024);
    out += fmt::format(
        "# /proc/{}/entropy.txt — Shannon-entropy scan of executable VMAs\n"
        "# pid {} ({}), {} exec VMA(s) sampled (up to {} pages each)\n"
        "# Threshold: >{:.1f} bits/byte flagged as ★ HIGH (likely packed/encrypted).\n"
        "#\n"
        "# vm_start          vm_end             flags    anon  bytes    entropy\n"
        "# ----------------+----------------+--------+-----+--------+--------\n",
        p.pid, p.pid, p.comm, hits.size(), kSamplePages,
        kEntropyHighSeverityThreshold);
    for (const auto& h : hits) {
        const char* sev = h.entropy >= kEntropyHighSeverityThreshold
            ? " ★ HIGH" : "";
        out += fmt::format("{:#016x}  {:#016x}  {}{}{}    {}     {:>6}    {:.3f}{}\n",
                           h.vm_start, h.vm_end,
                           (h.vm_flags & 1) ? 'r' : '-',
                           (h.vm_flags & 2) ? 'w' : '-',
                           (h.vm_flags & 4) ? 'x' : '-',
                           h.anonymous ? "Y" : "N",
                           h.bytes_sampled,
                           h.entropy, sev);
    }
    return ByteBuf(out.begin(), out.end());
}

ByteBuf format_findevil_entropy(const Engine& eng) {
    std::string body;
    body.reserve(8 * 1024);
    std::size_t total_pids = 0, total_high = 0, errs = 0;
    for (const auto& p : eng.processes()) {
        if (p.mm == 0) continue;
        std::vector<EntropyHit> hits;
        try { hits = scan_entropy(eng, p); }
        catch (...) { ++errs; continue; }
        if (hits.empty()) continue;
        std::vector<EntropyHit> high;
        for (const auto& h : hits)
            if (h.entropy >= kEntropyHighSeverityThreshold) high.push_back(h);
        if (high.empty()) continue;
        ++total_pids;
        total_high += high.size();
        body += fmt::format("\n=== pid {} ({}) — {} high-entropy VMA(s) ===\n",
                            p.pid, p.comm, high.size());
        for (const auto& h : high) {
            body += fmt::format(
                "  {:#016x} - {:#016x}  {}{}{}  {:<5}  entropy={:.3f}\n",
                h.vm_start, h.vm_end,
                (h.vm_flags & 1) ? 'r' : '-',
                (h.vm_flags & 2) ? 'w' : '-',
                (h.vm_flags & 4) ? 'x' : '-',
                h.anonymous ? "anon" : "file",
                h.entropy);
        }
    }
    std::string hdr = fmt::format(
        "# /sys/findevil/entropy.txt — high-entropy executable VMAs\n"
        "# {} process(es) with ≥1 high-entropy VMA, {} total hits.\n"
        "# Threshold: ≥ {:.1f} bits/byte (legitimate x86_64 code is ~5.5-6.0;\n"
        "# packed/encrypted/shellcode is ~7.5-8.0).\n"
        "# {} processes skipped due to errors.\n",
        total_pids, total_high, kEntropyHighSeverityThreshold, errs);
    std::string combined = hdr + body;
    return ByteBuf(combined.begin(), combined.end());
}

} // namespace lmpfs::linux
