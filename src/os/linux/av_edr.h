// av_edr.h — fingerprint known AV / EDR / endpoint-agent products in a dump.
//
// Two scans, one report:
//
//   1) Process scan      — match every Process's comm / cmdline-arg0 path
//                          against a signature table.
//   2) Kernel-module scan — match every loaded module's name against the
//                          same table (CrowdStrike, Trend Micro, etc. all
//                          ship LSM / netfilter LKMs).
//
// Powers `/sys/findevil/av_edr.txt`. Forensically useful in two opposite
// directions:
//
//   * Triage: "is this box monitored?" If yes, expect telemetry already
//     exists in the vendor's cloud — pull it rather than re-deriving
//     locally.
//   * Adversary OPSEC: malware that *kills* the agent will leave the
//     module loaded but the process dead. This plugin reports both
//     surfaces so the discrepancy is visible.
//
// References:
//   MemProcFS:    no direct analog (Windows AV detection is more diffuse).
//   vol3:         no direct plugin; `linux.pslist` + grep is the manual
//                 equivalent.
//
#pragma once
#include "core/types.h"
#include <string>
#include <vector>

namespace lmpfs { class Engine; }

namespace lmpfs::linux {

struct AvEdrHit {
    enum class Source { Process, Module };
    Source      source;
    std::string vendor;
    std::string product;
    std::string evidence;   // the matched string / module name
    u32         pid     = 0;     // valid when source == Process
    u32         uid     = 0;
    std::string comm;            // process comm (Process only)
    VAddr       mod_va  = 0;     // valid when source == Module
};

// Run both scans; returns a flat list of hits.
std::vector<AvEdrHit> scan_av_edr(const Engine& eng);

// `/sys/findevil/av_edr.txt` — human-readable report.
ByteBuf format_av_edr(const Engine& eng);

} // namespace lmpfs::linux
