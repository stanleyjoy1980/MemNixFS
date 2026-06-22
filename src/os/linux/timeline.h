// timeline.h — aggregate timestamped events from every source we have
// into one chronological timeline. This is MemProcFS's `m_fc_timeline.c`
// pattern — a forensic "what happened, in what order" view.
//
// Event sources tapped:
//   * dmesg (printk_ringbuffer)         — kernel events with [sec.usec]
//   * bash_history (per-pid HIST_ENTRY) — user-typed commands with HISTTIMEFORMAT
//   * eBPF prog_aux.load_time           — when each eBPF program was loaded
//   * (future: file mtimes from cached inodes, process start times, …)
//
// Output:
//   /forensic/timeline.txt  — human-readable, time-sorted
//   /forensic/timeline.csv  — RFC 4180, SIEM-ingest
//
// Each row: time (ISO-ish or "boot+N s") | source | actor | summary
#pragma once
#include "core/types.h"
#include "core/stream.h"
#include <string>
#include <vector>

namespace lmpfs { class Engine; }

namespace lmpfs::linux {

struct TimelineEvent {
    // "Sortable time": for absolute-time events, the seconds-since-epoch
    // string ("2026-02-10 09:03:56 UTC"). For relative events (dmesg
    // `[N.M]`), the string "boot+NNN.MMM" with leading zeros so it sorts
    // before any wall-clock event.
    std::string sort_key;
    std::string display_time;     // user-friendly version of the above
    std::string source;           // "dmesg", "bash", "ebpf", …
    std::string actor;            // e.g. "pid=4849 uid=1000" or "kernel"
    std::string summary;          // free-text, one line
    std::string type;             // PROC, NET, SHELL, KERN, EVIL, LOG
    std::string action;           // START, LOAD, CMD, EVENT, FINDING
    u32         pid = 0;
    u32         uid = 0;
    std::string object;
    std::string confidence = "medium";
};

std::vector<TimelineEvent> build_timeline(const Engine& eng);

ByteBuf format_timeline_txt(const Engine& eng);   // /forensic/timeline.txt
ByteBuf format_timeline_csv(const Engine& eng);   // /forensic/timeline.csv
ByteBuf format_timeline_summary_txt(const Engine& eng);
ByteBuf format_timeline_domain_txt(const Engine& eng, const std::string& domain);
ByteBuf format_timeline_domain_csv(const Engine& eng, const std::string& domain);

} // namespace lmpfs::linux
