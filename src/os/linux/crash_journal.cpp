#include "os/linux/crash_journal.h"
#include "os/linux/dmesg.h"
#include "os/linux/pagecache.h"
#include "app/engine.h"
#include <fmt/format.h>
#include <algorithm>
#include <cctype>
#include <set>
#include <sstream>
#include <string>

namespace lmpfs::linux {

namespace {

constexpr u64 kMaxRecoveredLogBytes = 8ull * 1024 * 1024;
constexpr std::size_t kMaxLineBytes = 4096;

struct SourceText {
    std::string name;
    std::string state;
    std::string text;
    bool checked = false;
    bool partial = false;
};

struct LogCandidate {
    CachedInode inode;
    std::string kind;
    std::string state;
    RecoveredFileStats stats;
    u64 recovered_size = 0;
    u64 cached_bytes = 0;
};

struct CrashEvent {
    std::string severity;
    std::string source;
    std::string time;
    std::string category;
    std::string evidence;
};

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool contains_any(const std::string& lower, std::initializer_list<const char*> pats) {
    for (const char* p : pats) {
        if (lower.find(p) != std::string::npos) return true;
    }
    return false;
}

bool is_text_log_path(const std::string& lower) {
    return lower == "/var/log/syslog" ||
           lower == "/var/log/messages" ||
           lower == "/var/log/kern.log" ||
           lower == "/var/log/auth.log" ||
           lower == "/var/log/secure" ||
           lower == "/var/log/audit/audit.log" ||
           lower == "/var/log/dmesg" ||
           lower.find("/var/log/syslog.") == 0 ||
           lower.find("/var/log/messages.") == 0 ||
           lower.find("/var/log/kern.log.") == 0 ||
           lower.find("/var/log/auth.log.") == 0 ||
           lower.find("/var/log/secure.") == 0;
}

std::string normalise_log_path(std::string path) {
    std::string lower = to_lower(path);
    if (lower.find("/root/var/log/") == 0 ||
        lower == "/root/var/log") {
        return path.substr(5);
    }
    if (lower.find("/root/run/log/") == 0 ||
        lower == "/root/run/log") {
        return path.substr(5);
    }
    return path;
}

bool is_journald_path(const std::string& lower) {
    return (lower.find("/var/log/journal/") == 0 ||
            lower.find("/run/log/journal/") == 0) &&
           lower.size() >= 8 &&
           lower.rfind(".journal") == lower.size() - 8;
}

std::string type_of_candidate(const std::string& lower, const std::string& fs) {
    if (is_journald_path(lower)) return "journald-binary";
    if (is_text_log_path(lower)) return "text-log";
    (void)fs;
    return "filesystem-consistency-candidate";
}

std::vector<LogCandidate> collect_log_candidates(const Engine& eng) {
    std::vector<LogCandidate> out;
    std::set<std::pair<std::string, u64>> seen;
    auto inodes = enumerate_cached_inodes(eng);
    for (const auto& ci : inodes) {
        if (ci.path.empty()) continue;
        const std::string norm_path = normalise_log_path(ci.path);
        const std::string lower = to_lower(norm_path);
        const std::string fs_lower = to_lower(ci.sb_fs);
        const bool wanted = is_text_log_path(lower) ||
                            is_journald_path(lower);
        if (!wanted) continue;
        if (!seen.insert({ci.path, ci.i_ino}).second) continue;

        LogCandidate lc{};
        lc.inode = ci;
        lc.kind = type_of_candidate(lower, fs_lower);
        lc.stats = recover_file_stats(eng, ci, true);
        lc.recovered_size = lc.stats.logical_size;
        lc.cached_bytes = lc.stats.pages_within_size * 4096ull;
        lc.state = describe_recovered_file_state(lc.stats);
        out.push_back(std::move(lc));
    }
    std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) {
        if (a.kind != b.kind) return a.kind < b.kind;
        return a.inode.path < b.inode.path;
    });
    return out;
}

SourceText get_dmesg_source(const Engine& eng) {
    SourceText s{};
    s.name = "/sys/dmesg";
    try {
        auto bytes = format_dmesg(eng);
        s.text.assign(bytes.begin(), bytes.end());
        if (s.text.empty()) {
            s.state = "unavailable: dmesg recovered as empty output";
        } else if (!s.text.empty() && s.text[0] == ';') {
            s.state = "unavailable: " + s.text.substr(0, std::min<std::size_t>(160, s.text.size()));
        } else {
            s.state = "checked: dmesg recovered and scanned";
            s.checked = true;
        }
    } catch (const std::exception& e) {
        s.state = fmt::format("unavailable: dmesg recovery failed: {}", e.what());
    } catch (...) {
        s.state = "unavailable: dmesg recovery failed";
    }
    return s;
}

std::vector<std::string> split_lines_limited(const std::string& text) {
    std::vector<std::string> lines;
    std::size_t pos = 0;
    while (pos < text.size()) {
        std::size_t eol = text.find('\n', pos);
        std::string line = text.substr(pos, eol == std::string::npos
                                            ? std::string::npos
                                            : eol - pos);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.size() > kMaxLineBytes) line.resize(kMaxLineBytes);
        lines.push_back(std::move(line));
        if (eol == std::string::npos) break;
        pos = eol + 1;
    }
    return lines;
}

std::string extract_dmesg_time(const std::string& line) {
    if (line.empty() || line[0] != '[') return "";
    auto close = line.find(']');
    if (close == std::string::npos) return "";
    return line.substr(0, close + 1);
}

CrashEvent classify_crash_line(const std::string& source,
                               const std::string& line) {
    const std::string lower = to_lower(line);
    CrashEvent ev{};
    ev.source = source;
    ev.time = extract_dmesg_time(line);
    ev.evidence = line;

    if (lower.find("kernel panic detection skipped") != std::string::npos ||
        lower.find("client bug:") != std::string::npos) {
        return ev;
    }

    if (contains_any(lower, {"kernel panic - not syncing", "panic:", "fatal exception"})) {
        ev.severity = "CRITICAL"; ev.category = "kernel-panic";
    } else if (contains_any(lower, {"oops:", "kernel bug", "kernel bug at",
                                    "unable to handle kernel",
                                    "null pointer dereference", "general protection fault"})) {
        ev.severity = "CRITICAL"; ev.category = "kernel-oops";
    } else if (contains_any(lower, {"call trace:", "rip:", "eip:"})) {
        ev.severity = "HIGH"; ev.category = "call-trace";
    } else if (contains_any(lower, {"hard lockup", "soft lockup", "hung task",
                                    "blocked for more than"})) {
        ev.severity = "HIGH"; ev.category = "lockup-or-hung-task";
    } else if (contains_any(lower, {"watchdog: bug", "watchdog: hard lockup",
                                    "watchdog: soft lockup"})) {
        ev.severity = "HIGH"; ev.category = "lockup-or-hung-task";
    } else if (contains_any(lower, {"ext4-fs error", "ext4-fs warning",
                                    "xfs error", "xfs corruption", "xfs internal error",
                                    "btrfs error", "btrfs warning", "btrfs critical",
                                    "jbd2: error", "journal abort",
                                    "aborting journal", "remounting filesystem read-only",
                                    "metadata corruption"})) {
        ev.severity = "HIGH"; ev.category = "filesystem-or-journal";
    } else if (contains_any(lower, {"out of memory", "oom-killer", "killed process",
                                    "segfault", "i/o error", "buffer i/o error"})) {
        ev.severity = "MEDIUM"; ev.category = "resource-or-io";
    }
    return ev;
}

std::vector<CrashEvent> scan_crash_events(const SourceText& src) {
    std::vector<CrashEvent> out;
    if (!src.checked) return out;
    for (const auto& line : split_lines_limited(src.text)) {
        auto ev = classify_crash_line(src.name, line);
        if (!ev.severity.empty()) out.push_back(std::move(ev));
    }
    return out;
}

std::string format_event_table(const std::vector<CrashEvent>& events) {
    std::string out;
    out += "# severity source time category evidence\n";
    out += "#--------+------+----+--------+---------\n";
    for (const auto& e : events) {
        out += fmt::format("{:<8} {:<18} {:<16} {:<24} {}\n",
                           e.severity, e.source, e.time.empty() ? "-" : e.time,
                           e.category, e.evidence);
    }
    return out;
}

std::string read_candidate_text(const Engine& eng, const LogCandidate& c) {
    if (c.cached_bytes == 0 || c.recovered_size == 0) return {};
    if (c.recovered_size > kMaxRecoveredLogBytes) return {};
    auto bytes = recover_file_with_stats(eng, c.inode).bytes;
    std::string text;
    text.reserve(bytes.size());
    for (u8 b : bytes) {
        if (b == 0) continue;
        if (b == '\r' || b == '\n' || b == '\t' || (b >= 0x20 && b < 0x7f))
            text.push_back(static_cast<char>(b));
        else
            text.push_back('.');
    }
    return text;
}

std::vector<SourceText> collect_text_log_sources(const Engine& eng) {
    std::vector<SourceText> out;
    for (const auto& c : collect_log_candidates(eng)) {
        if (c.kind != "text-log") continue;
        SourceText s{};
        s.name = normalise_log_path(c.inode.path);
        if (c.cached_bytes == 0) {
            s.state = "unavailable: text log inode found, but no cached content pages";
        } else if (c.recovered_size > kMaxRecoveredLogBytes) {
            s.state = fmt::format(
                "partial: text log candidate is {} bytes; v1 reader caps eager recovery at {} bytes",
                c.recovered_size, kMaxRecoveredLogBytes);
        } else {
            s.text = read_candidate_text(eng, c);
            if (s.text.empty()) {
                s.state = "unavailable: text log content recovered as empty";
            } else {
                s.state = c.state;
                s.checked = true;
                s.partial = !c.stats.complete();
            }
        }
        out.push_back(std::move(s));
    }
    return out;
}

std::vector<CrashEvent> collect_all_crash_events(const Engine& eng,
                                                 std::vector<std::string>* states = nullptr) {
    std::vector<CrashEvent> events;
    auto dm = get_dmesg_source(eng);
    if (states) states->push_back(dm.name + ": " + dm.state);
    auto dmev = scan_crash_events(dm);
    events.insert(events.end(), dmev.begin(), dmev.end());

    auto logs = collect_text_log_sources(eng);
    if (logs.empty() && states)
        states->push_back("/sys/journal/text_logs.txt: unavailable: no cached syslog-style text log candidates found");
    for (const auto& src : logs) {
        if (states) states->push_back(src.name + ": " + src.state);
        auto ev = scan_crash_events(src);
        events.insert(events.end(), ev.begin(), ev.end());
    }
    return events;
}

std::string summarise_consistency(const Engine& eng) {
    std::set<std::string> filesystems;
    auto inodes = enumerate_cached_inodes(eng);
    for (const auto& ci : inodes) {
        const std::string fs = to_lower(ci.sb_fs);
        if (fs == "ext4" || fs == "xfs" || fs == "btrfs")
            filesystems.insert(fs);
    }
    bool saw_jbd2_task = false;
    bool saw_btrfs_task = false;
    for (const auto& p : eng.processes()) {
        const std::string comm = to_lower(p.comm);
        if (comm.find("jbd2") != std::string::npos) saw_jbd2_task = true;
        if (comm.find("btrfs") != std::string::npos) saw_btrfs_task = true;
    }
    std::string out;
    out += "# filesystem consistency evidence\n";
    out += "state: unverified\n";
    out += "policy: inode/bitmap mismatches are not claimed unless inode metadata, allocation bitmap metadata, parser support, and reproducible mismatch evidence are all present.\n";
    if (filesystems.empty()) {
        out += "filesystems: unavailable: no ext4/xfs/btrfs journal or consistency metadata candidates recovered from page cache\n";
    } else {
        out += "filesystems:";
        for (const auto& fs : filesystems) out += " " + fs;
        out += "\n";
    }
    out += fmt::format("journal_worker_tasks: jbd2={} btrfs={}\n",
                       saw_jbd2_task ? "observed" : "not-observed",
                       saw_btrfs_task ? "observed" : "not-observed");
    out += "journal_metadata_candidates: unavailable: no filesystem journal metadata parser is active in this v1 report\n";
    out += "inode_bitmap_validation: unavailable: filesystem allocation bitmaps are not parsed in this v1 report\n";
    out += "journal_replay: unavailable: full ext4 JBD2/XFS/btrfs replay requires disk-image support or cached journal blocks plus filesystem-specific replay code\n";
    return out;
}

ByteBuf to_buf(const std::string& s) {
    return ByteBuf(s.begin(), s.end());
}

std::string printable_journal_fields(const std::string& text) {
    std::string out;
    std::string run;
    std::set<std::string> emitted_values;
    auto flush = [&]() {
        if (run.size() < 8) {
            run.clear();
            return;
        }
        const std::string lower = to_lower(run);
        const char* keys[] = {
            "message=", "_comm=", "_exe=", "_pid=", "syslog_identifier=",
            "priority=", "_transport=", "_source_realtime_timestamp=",
            "kernel panic", "oops", "ext4-fs", "xfs", "btrfs", "jbd2"
        };
        std::size_t pos = std::string::npos;
        for (const char* key : keys) {
            auto p = lower.find(key);
            if (p != std::string::npos)
                pos = std::min(pos, p);
        }
        if (pos != std::string::npos) {
            std::string value = run.substr(pos);
            if (value.size() > 180) value = value.substr(0, 180) + "...";
            if (emitted_values.insert(value).second && emitted_values.size() <= 40)
                out += value + "\n";
        }
        run.clear();
    };

    for (unsigned char ch : text) {
        if (ch >= 0x20 && ch < 0x7f) {
            run.push_back(static_cast<char>(ch));
            if (run.size() >= 512) flush();
        } else {
            flush();
        }
    }
    flush();
    return out;
}

bool range_covers_offset(const std::vector<RecoveredRange>& ranges, u64 offset) {
    for (const auto& r : ranges) {
        if (offset >= r.offset && offset < r.offset + r.length)
            return true;
    }
    return false;
}

} // anonymous

ByteBuf format_crash_summary(const Engine& eng) {
    std::vector<std::string> states;
    auto events = collect_all_crash_events(eng, &states);
    std::size_t critical = 0, high = 0, medium = 0;
    for (const auto& e : events) {
        if (e.severity == "CRITICAL") ++critical;
        else if (e.severity == "HIGH") ++high;
        else if (e.severity == "MEDIUM") ++medium;
    }

    std::string out;
    out += "# /sys/crash/summary.txt - crash and failure evidence triage\n";
    out += "# This report never treats missing evidence as proof of no crash.\n";
    out += "# Absence statements only apply to sources marked checked.\n\n";
    for (const auto& s : states) out += s + "\n";
    out += "\n";
    if (events.empty()) {
        bool any_checked = false;
        bool any_partial = false;
        for (const auto& s : states)
            if (s.find("checked:") != std::string::npos ||
                s.find("partial:") != std::string::npos)
                any_checked = true;
        for (const auto& s : states)
            if (s.find("partial:") != std::string::npos)
                any_partial = true;
        out += any_checked
            ? (any_partial
                ? "result: partial: no matching crash pattern found in recovered portions; missing gaps were not checked\n"
                : "result: checked: no matching crash pattern found in recovered sources\n")
            : "result: unavailable: no recoverable crash/log source could be checked\n";
    } else {
        bool any_partial = false;
        for (const auto& s : states)
            if (s.find("partial:") != std::string::npos)
                any_partial = true;
        out += fmt::format("result: {}: {} crash/failure event(s) matched{}\n",
                           any_partial ? "partial" : "checked",
                           events.size(),
                           any_partial ? " in recovered portions" : "");
        out += fmt::format("severity_counts: critical={} high={} medium={}\n",
                           critical, high, medium);
    }
    out += "\n";
    out += summarise_consistency(eng);
    return to_buf(out);
}

ByteBuf format_crash_events(const Engine& eng) {
    std::vector<std::string> states;
    auto events = collect_all_crash_events(eng, &states);
    std::string out;
    out += "# /sys/crash/events.txt - matched crash/failure evidence\n";
    out += "# Source states:\n";
    for (const auto& s : states) out += "# " + s + "\n";
    out += "\n";
    if (events.empty()) {
        bool any_partial = false;
        bool any_checked = false;
        for (const auto& s : states) {
            if (s.find("partial:") != std::string::npos) any_partial = true;
            if (s.find("checked:") != std::string::npos ||
                s.find("partial:") != std::string::npos) any_checked = true;
        }
        if (!any_checked)
            out += "unavailable: no recoverable crash/log source could be checked\n";
        else if (any_partial)
            out += "partial: no matching crash pattern found in recovered portions; missing gaps were not checked\n";
        else
            out += "checked: no matching crash pattern found in recovered sources\n";
    } else {
        out += format_event_table(events);
    }
    return to_buf(out);
}

ByteBuf format_crash_call_traces(const Engine& eng) {
    auto dm = get_dmesg_source(eng);
    std::string out;
    out += "# /sys/crash/call_traces.txt - panic/oops/call-trace blocks\n";
    out += "# " + dm.name + ": " + dm.state + "\n\n";
    if (!dm.checked) {
        out += "unavailable: dmesg could not be recovered, so call traces could not be checked\n";
        return to_buf(out);
    }

    auto lines = split_lines_limited(dm.text);
    std::size_t blocks = 0;
    for (std::size_t i = 0; i < lines.size(); ++i) {
        const std::string lower = to_lower(lines[i]);
        if (!contains_any(lower, {"call trace:", "kernel panic", "oops:", "bug:",
                                  "unable to handle kernel", "general protection fault"}))
            continue;
        ++blocks;
        out += fmt::format("## block {}\n", blocks);
        std::size_t begin = i > 3 ? i - 3 : 0;
        std::size_t end = std::min(lines.size(), i + 18);
        for (std::size_t j = begin; j < end; ++j)
            out += lines[j] + "\n";
        out += "\n";
    }
    if (blocks == 0)
        out += "checked: no panic/oops/call-trace block found in recovered dmesg\n";
    return to_buf(out);
}

ByteBuf format_journal_index(const Engine& eng) {
    auto candidates = collect_log_candidates(eng);
    std::string out;
    out += "# /sys/journal/index.txt - cached log/journal candidates\n";
    out += "# Missing candidates mean they were not recovered from memory page cache, not that they did not exist on disk.\n";
    out += "# kind state fs ino size expected seen copied dropped path\n";
    out += "#----+-----+--+---+----+--------+----+------+-------+----\n";
    if (candidates.empty()) {
        out += "unavailable: no cached syslog/journald/filesystem-journal candidates found\n";
    } else {
        for (const auto& c : candidates) {
            out += fmt::format("{:<32} {:<78} {:<8} {:>10} {:>12} {:>8} {:>6} {:>6} {:>7} {}\n",
                               c.kind, c.state, c.inode.sb_fs.empty() ? "?" : c.inode.sb_fs,
                               c.inode.i_ino, c.stats.logical_size,
                               c.stats.expected_pages, c.stats.pages_within_size,
                               c.stats.pages_copied, c.stats.pages_dropped,
                               normalise_log_path(c.inode.path));
        }
    }
    out += "\n";
    out += summarise_consistency(eng);
    return to_buf(out);
}

ByteBuf format_journal_text_logs(const Engine& eng) {
    auto logs = collect_text_log_sources(eng);
    std::string out;
    out += "# /sys/journal/text_logs.txt - recovered syslog-style text logs\n";
    out += "# Missing logs mean they were not recovered from page cache, not that they did not exist on disk.\n\n";
    if (logs.empty()) {
        out += "unavailable: no cached syslog-style text log candidates found\n";
        return to_buf(out);
    }
    for (const auto& src : logs) {
        out += fmt::format("## {}\n{}\n", src.name, src.state);
        if (!src.checked) {
            out += "\n";
            continue;
        }
        std::size_t count = 0;
        for (const auto& line : split_lines_limited(src.text)) {
            if (line.empty()) continue;
            out += line + "\n";
            if (++count >= 2000) {
                out += "; truncated: first 2000 non-empty lines shown from this recovered log\n";
                break;
            }
        }
        out += "\n";
    }
    return to_buf(out);
}

ByteBuf format_journald_entries(const Engine& eng) {
    auto candidates = collect_log_candidates(eng);
    std::string out;
    out += "# /sys/journal/journald.txt - best-effort cached journald evidence\n";
    out += "# This is not filesystem-journal replay. It only inspects recovered systemd journal files from page cache.\n\n";
    bool any = false;
    for (const auto& c : candidates) {
        if (c.kind != "journald-binary") continue;
        any = true;
        out += fmt::format("## {}\n{}\n", normalise_log_path(c.inode.path), c.state);
        if (c.cached_bytes == 0 || c.recovered_size == 0) {
            out += "\n";
            continue;
        }
        if (c.recovered_size > kMaxRecoveredLogBytes) {
            out += fmt::format(
                "entries: partial: journal candidate is {} bytes; v1 reader caps eager recovery at {} bytes\n\n",
                c.recovered_size, kMaxRecoveredLogBytes);
            continue;
        }
        auto rf = recover_file_with_stats(eng, c.inode);
        auto& bytes = rf.bytes;
        const bool page0_copied =
            rf.stats.logical_size != 0 &&
            !range_covers_offset(rf.stats.missing_ranges, 0) &&
            !range_covers_offset(rf.stats.dropped_ranges, 0);
        const bool magic = bytes.size() >= 8 &&
            page0_copied &&
            std::string(reinterpret_cast<const char*>(bytes.data()), 8) == "LPKSHHRH";
        if (magic) {
            out += rf.stats.complete()
                ? "format: checked: systemd journal header signature found\n"
                : "format: partial: systemd journal header signature found, but the recovered file has gaps\n";
        } else if (!page0_copied) {
            out += "format: unavailable: journal header page was not recovered; signature cannot be checked\n";
        } else {
            out += "format: partial: recovered header bytes do not start with a complete systemd journal signature\n";
        }
        std::string text = read_candidate_text(eng, c);
        auto fields = printable_journal_fields(text);
        if (fields.empty()) {
            out += "entries: unavailable: no printable journald fields recovered by v1 best-effort scanner\n\n";
        } else {
            out += "entries: partial: printable journald fields recovered; binary entry graph not replayed\n";
            out += fields + "\n";
        }
    }
    if (!any)
        out += "unavailable: journald file not present in recovered page cache\n";
    return to_buf(out);
}

std::vector<TimelineEvent> collect_crash_log_timeline_events(const Engine& eng) {
    std::vector<TimelineEvent> out;
    auto events = collect_all_crash_events(eng);
    for (const auto& ce : events) {
        if (ce.severity != "CRITICAL" && ce.severity != "HIGH") continue;
        TimelineEvent e{};
        if (!ce.time.empty() && ce.time.front() == '[') {
            std::string t = ce.time.substr(1, ce.time.size() - 2);
            auto dot = t.find('.');
            std::string sec = dot == std::string::npos ? t : t.substr(0, dot);
            std::string usec = dot == std::string::npos ? "0" : t.substr(dot + 1);
            while (!sec.empty() && sec.front() == ' ') sec.erase(sec.begin());
            while (sec.size() < 8) sec.insert(sec.begin(), '0');
            while (usec.size() < 6) usec.push_back('0');
            e.sort_key = "0000-boot+" + sec + "." + usec;
            e.display_time = "boot+" + sec + "." + usec + "s";
        } else {
            e.sort_key = "9999-crash-log";
            e.display_time = ce.time.empty() ? "unknown" : ce.time;
        }
        e.source = "crash";
        e.actor = ce.source;
        e.summary = ce.severity + " " + ce.category + ": " + ce.evidence;
        out.push_back(std::move(e));
    }
    return out;
}

} // namespace lmpfs::linux
