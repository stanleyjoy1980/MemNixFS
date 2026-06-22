// bash_history.cpp — see header.
//
// Bash's HIST_ENTRY struct (from lib/readline/history.h):
//
//   typedef struct _hist_entry {
//       char *line;          // the command text (NUL-terminated)
//       char *timestamp;     // optional, "#<unix_ts>" if HIST_TIMESTAMP
//       histdata_t data;     // bash-internal opaque pointer
//   } HIST_ENTRY;
//
// All three fields are pointers — typically into the bash heap. We
// scan the heap for 24-byte windows that look like { ptr, ptr, ptr }
// where:
//   - .line points to a printable ASCII NUL-terminated string of
//     length 1-1024
//   - .timestamp is either NULL OR points to a string starting with '#'
//     followed by 10 digits (a unix timestamp)
//
// References: Vol3 plugins/linux/bash.py uses the same shape.
//
// Beyond the bash heap scan, we recover history from EVERY common shell's
// on-disk history file when it survives in the page cache, with a stateful,
// format-aware parser (see parse_history_file): bash (#<epoch>), zsh extended
// (": <ts>:<dur>;cmd"), fish YAML ("- cmd:" + "when:"), tcsh/csh (#+<epoch>),
// ksh/mksh (binary), POSIX sh/dash/ash, and PowerShell (PSReadLine
// ConsoleHost_history.txt). The `source` column names the detected shell.
//
#include "os/linux/bash_history.h"
#include "app/engine.h"
#include "symbols/isf_symbols.h"
#include "arch/x86_64/paging.h"
#include "arch/x86_64/page_cache.h"
#include "formats/physical_layer.h"
#include "os/linux/kernel_resolver.h"
#include "os/linux/pagecache.h"
#include "os/linux/task_files.h"
#include "core/log.h"
#include <fmt/format.h>
#include <algorithm>
#include <cctype>
#include <ctime>
#include <iterator>
#include <string_view>
#include <set>
#include <cstring>
#include <sstream>
#include <unordered_set>

namespace lmpfs::linux {

namespace {

// Read user-space VA from a process via its mm->pgd page table.
// We rely on `Process` having `mm` filled, and walk the PGD ourselves.
bool uread(const Engine& eng, const Process& p, VAddr va,
           void* dst, std::size_t n,
           PAddr cached_pgd_pa = 0)
{
    if (p.mm == 0) return false;

    // Look up user PGD PA via the kernel direct map (mm.pgd is a kernel
    // VA, points to the user PGD's PA + direct_map_base).
    PAddr user_pgd_pa = cached_pgd_pa;
    if (user_pgd_pa == 0) {
        const auto& isf = eng.isf();
        u64 mm_pgd_off;
        try { mm_pgd_off = isf.field_offset("mm_struct", "pgd"); }
        catch (...) { return false; }

        VAddr pgd_va = 0;
        PAddr mm_pa = p.mm - eng.kernel().direct_map_base;
        if (eng.phys().read(mm_pa + mm_pgd_off, &pgd_va, 8) != 8) return false;
        user_pgd_pa = pgd_va - eng.kernel().direct_map_base;
    }

    x86_64::PageTable upt(eng.phys(), user_pgd_pa);
    return upt.read(va, dst, n) == n;
}

bool looks_like_command(const std::vector<u8>& s) {
    if (s.size() < 2 || s.size() > 1024) return false;
    // Allow whitespace + tabs + common shell chars
    for (u8 c : s) {
        if (c == 0) return false;
        if (c == '\t' || c == ' ') continue;
        if (c >= 0x20 && c < 0x7F) continue;
        return false;  // any other control / high-bit char → reject
    }
    // Heuristic: must contain at least one letter or '/' (filter out
    // pure-punctuation false positives).
    bool letter = false;
    for (u8 c : s) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
             c == '/' || c == '.')
        { letter = true; break; }
    }
    return letter;
}

std::vector<u8> uread_cstring(const Engine& eng, const Process& p,
                               PAddr cached_pgd_pa,
                               VAddr va, std::size_t maxlen)
{
    std::vector<u8> out;
    if (va == 0) return out;
    // Read in chunks (PGD walks are page-granular anyway).
    constexpr std::size_t kChunk = 256;
    std::vector<u8> buf(kChunk);
    VAddr cur = va;
    while (out.size() < maxlen) {
        std::size_t want = std::min(kChunk, maxlen - out.size());
        if (!uread(eng, p, cur, buf.data(), want, cached_pgd_pa)) break;
        for (std::size_t i = 0; i < want; ++i) {
            if (buf[i] == 0) {
                out.insert(out.end(), buf.begin(), buf.begin() + i);
                return out;
            }
        }
        out.insert(out.end(), buf.begin(), buf.begin() + want);
        cur += want;
    }
    return out;
}

bool is_heap_va(VAddr va, VAddr start_brk, VAddr brk) {
    return va >= start_brk && va < brk;
}

std::string trim(std::string s) {
    auto ws = [](unsigned char c) { return std::isspace(c) != 0; };
    while (!s.empty() && ws(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
    while (!s.empty() && ws(static_cast<unsigned char>(s.back()))) s.pop_back();
    return s;
}

bool contains_icase(const std::string& s, const std::string& needle) {
    auto it = std::search(s.begin(), s.end(), needle.begin(), needle.end(),
        [](char a, char b) {
            return std::tolower(static_cast<unsigned char>(a)) ==
                   std::tolower(static_cast<unsigned char>(b));
        });
    return it != s.end();
}

bool shell_like_process(const Engine& eng, const Process& p) {
    if (p.mm == 0) return false;
    if (p.comm == "bash" || p.comm == "zsh" || p.comm == "fish" ||
        p.comm == "sh" || p.comm == "dash" || p.comm == "ksh" ||
        p.comm == "mksh") return true;
    std::string meta;
    try {
        auto cmd = gen_cmdline(eng.phys(), eng.isf(), eng.kernel(), p);
        meta.append(reinterpret_cast<const char*>(cmd.data()), cmd.size());
    } catch (...) {}
    try {
        auto env = gen_environ(eng.phys(), eng.isf(), eng.kernel(), p);
        meta.append(reinterpret_cast<const char*>(env.data()), env.size());
    } catch (...) {}
    return meta.find("SHELL=") != std::string::npos ||
           meta.find("HISTFILE=") != std::string::npos ||
           meta.find("ZDOTDIR=") != std::string::npos ||
           contains_icase(meta, "bash") ||
           contains_icase(meta, "zsh") ||
           contains_icase(meta, "fish");
}

bool generic_heap_scan_allowed(const Engine& eng, const Process& p) {
    if (p.comm == "bash" || p.comm == "zsh" || p.comm == "fish" ||
        p.comm == "sh" || p.comm == "dash" || p.comm == "ksh" ||
        p.comm == "mksh") return true;

    std::string meta;
    try {
        auto cmd = gen_cmdline(eng.phys(), eng.isf(), eng.kernel(), p);
        meta.append(reinterpret_cast<const char*>(cmd.data()), cmd.size());
    } catch (...) {}
    try {
        auto env = gen_environ(eng.phys(), eng.isf(), eng.kernel(), p);
        meta.append(reinterpret_cast<const char*>(env.data()), env.size());
    } catch (...) {}

    return meta.find("HISTFILE=") != std::string::npos ||
           meta.find("ZDOTDIR=") != std::string::npos ||
           meta.find("fish_history") != std::string::npos ||
           contains_icase(meta, ".zsh_history") ||
           contains_icase(meta, ".bash_history");
}

bool read_process_heap(const Engine& eng, const Process& p,
                       std::vector<u8>& heap, VAddr& start_brk, VAddr& brk,
                       PAddr& user_pgd_pa) {
    heap.clear();
    start_brk = brk = 0;
    user_pgd_pa = 0;
    if (p.mm == 0 || p.task_va == 0) return false;
    const auto& isf = eng.isf();
    u64 mm_pgd_off = 0, mm_start_brk_off = 0, mm_brk_off = 0;
    try {
        mm_pgd_off       = isf.field_offset("mm_struct", "pgd");
        mm_start_brk_off = isf.field_offset("mm_struct", "start_brk");
        mm_brk_off       = isf.field_offset("mm_struct", "brk");
    } catch (...) { return false; }

    PAddr mm_pa = p.mm - eng.kernel().direct_map_base;
    VAddr pgd_va = 0;
    if (eng.phys().read(mm_pa + mm_pgd_off,       &pgd_va,    8) != 8) return false;
    if (eng.phys().read(mm_pa + mm_start_brk_off, &start_brk, 8) != 8) return false;
    if (eng.phys().read(mm_pa + mm_brk_off,       &brk,       8) != 8) return false;
    if (start_brk == 0 || brk <= start_brk) return false;
    const u64 heap_size = brk - start_brk;
    if (heap_size > 256ULL * 1024 * 1024) return false;
    user_pgd_pa = pgd_va - eng.kernel().direct_map_base;
    heap.assign(heap_size, 0);
    x86_64::PageTable upt(eng.phys(), user_pgd_pa);
    upt.read(start_brk, heap.data(), heap_size);
    return true;
}

std::string iso_from_epoch_string(const std::string& n) {
    try {
        std::time_t t = static_cast<std::time_t>(std::stoll(n));
        std::tm* tm = std::gmtime(&t);
        if (!tm) return {};
        char b[32];
        std::strftime(b, sizeof(b), "%Y-%m-%d %H:%M:%S UTC", tm);
        return b;
    } catch (...) {
        return {};
    }
}

bool parse_zsh_extended(const std::string& line,
                        std::string& ts, std::string& command) {
    if (line.size() < 8 || line[0] != ':' || line[1] != ' ') return false;
    std::size_t p = 2;
    std::size_t ts_start = p;
    while (p < line.size() && std::isdigit(static_cast<unsigned char>(line[p]))) ++p;
    if (p == ts_start || p >= line.size() || line[p] != ':') return false;
    std::size_t semi = line.find(';', p + 1);
    if (semi == std::string::npos || semi + 1 >= line.size()) return false;
    ts = iso_from_epoch_string(line.substr(ts_start, p - ts_start));
    command = trim(line.substr(semi + 1));
    return looks_like_command(ByteBuf(command.begin(), command.end()));
}

bool parse_fish_cmd(const std::string& line, std::string& command) {
    std::string t = trim(line);
    const std::string k1 = "- cmd:";
    const std::string k2 = "cmd:";
    if (t.rfind(k1, 0) == 0) command = trim(t.substr(k1.size()));
    else if (t.rfind(k2, 0) == 0) command = trim(t.substr(k2.size()));
    else return false;
    return looks_like_command(ByteBuf(command.begin(), command.end()));
}

std::vector<std::string> extract_printable_strings(const std::vector<u8>& buf,
                                                   std::size_t min_len = 4) {
    std::vector<std::string> out;
    std::string cur;
    for (u8 c : buf) {
        if (c == '\t' || (c >= 0x20 && c < 0x7f)) {
            cur.push_back(static_cast<char>(c));
            if (cur.size() > 4096) {
                out.push_back(std::move(cur));
                cur.clear();
            }
        } else {
            if (cur.size() >= min_len) out.push_back(std::move(cur));
            cur.clear();
        }
    }
    if (cur.size() >= min_len) out.push_back(std::move(cur));
    return out;
}

std::string path_basename(const std::string& path) {
    auto slash = path.find_last_of('/');
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

std::string lower_str(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

// Every shell-history format we understand. The `source` column names the
// detected shell, so an analyst can tell bash from zsh from PowerShell etc.
enum class ShellKind {
    Bash, Zsh, Fish, Tcsh, Ksh, PowerShell, Posix, Generic, Unknown
};

// Map a history *filename* to the shell that writes it. Generic = a real but
// ambiguous history file (".history"/".histfile") whose format we auto-detect.
ShellKind shell_kind_from_filename(const std::string& path) {
    std::string base = lower_str(path_basename(path));
    if (base == ".bash_history")                          return ShellKind::Bash;
    if (base == ".zsh_history" || base == ".zhistory")    return ShellKind::Zsh;
    if (base == "fish_history")                           return ShellKind::Fish;
    if (base == ".tcsh_history" || base == ".csh_history" ||
        base == "history.csh")                            return ShellKind::Tcsh;
    if (base == ".ksh_history" || base == ".sh_history" ||
        base == ".mksh_history" || base == "mksh_history")return ShellKind::Ksh;
    if (base == ".ash_history" || base == ".dash_history")return ShellKind::Posix;
    if (base == "consolehost_history.txt")                return ShellKind::PowerShell;
    if (base == ".history" || base == ".histfile")        return ShellKind::Generic;
    return ShellKind::Unknown;
}

const char* shell_name(ShellKind k) {
    switch (k) {
        case ShellKind::Bash:       return "bash";
        case ShellKind::Zsh:        return "zsh";
        case ShellKind::Fish:       return "fish";
        case ShellKind::Tcsh:       return "tcsh";
        case ShellKind::Ksh:        return "ksh";
        case ShellKind::PowerShell: return "powershell";
        case ShellKind::Posix:      return "sh";
        default:                    return "shell";
    }
}

bool history_filename(const std::string& path) {
    return shell_kind_from_filename(path) != ShellKind::Unknown;
}

// Infer the shell from a history filename so the `source` column can name the
// actual shell (bash/zsh/fish/…) instead of a generic mechanism.
std::string shell_from_history_filename(const std::string& path) {
    return shell_name(shell_kind_from_filename(path));
}

bool all_digits(const std::string& s) {
    if (s.empty()) return false;
    for (unsigned char c : s) if (c < '0' || c > '9') return false;
    return true;
}

// "#<digits>" (bash) or "#+<digits>" (tcsh) timestamp marker → digit string,
// or "" if the line isn't a timestamp marker. A bash epoch is ~10 digits.
std::string epoch_marker_digits(const std::string& line) {
    if (line.size() < 9 || line[0] != '#') return {};
    std::size_t p = 1;
    if (line[p] == '+') ++p;                       // tcsh "#+"
    std::string d = line.substr(p);
    while (!d.empty() && std::isspace(static_cast<unsigned char>(d.back()))) d.pop_back();
    if (d.size() < 8 || d.size() > 12 || !all_digits(d)) return {};
    return d;
}

std::string strip_bom(std::string s) {
    if (s.size() >= 3 && static_cast<u8>(s[0]) == 0xEF &&
        static_cast<u8>(s[1]) == 0xBB && static_cast<u8>(s[2]) == 0xBF)
        s.erase(0, 3);
    return s;
}

std::vector<std::string> split_lines(const std::string& content) {
    std::vector<std::string> lines;
    std::string cur;
    for (char c : content) {
        if (c == '\n')      { lines.push_back(std::move(cur)); cur.clear(); }
        else if (c != '\r') { cur.push_back(c); }     // tolerate CRLF (PowerShell)
    }
    if (!cur.empty()) lines.push_back(std::move(cur));
    return lines;
}

// Fish stores embedded newlines as literal "\n" and backslashes as "\\".
// Flatten to a single display line.
std::string unescape_fish(const std::string& s) {
    std::string o; o.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            char c = s[i + 1];
            if (c == 'n')  { o.push_back(' ');  ++i; continue; }
            if (c == '\\') { o.push_back('\\'); ++i; continue; }
        }
        o.push_back(s[i]);
    }
    return o;
}

// Stateful, format-aware parser for a recovered on-disk history file. Unlike a
// line-at-a-time scan, this pairs each command with the timestamp line that
// PRECEDES it (bash "#<ts>", tcsh "#+<ts>") or FOLLOWS it (fish "when:"), and
// understands binary ksh files. The `source` column is set to the *detected*
// shell so the analyst can tell formats apart. Everything from a genuine
// on-disk history file is high-confidence (note "high:") even without a
// timestamp; absent timestamps stay blank.
void parse_history_file(ShellKind kind, const std::string& basename,
                        const std::string& raw_content,
                        u32 pid, u32 uid, std::vector<ShellCmd>& out,
                        std::size_t cap = 5000) {
    const std::string content = strip_bom(raw_content);
    std::size_t n = 0;
    auto emit = [&](const char* shell, const std::string& ts,
                    const std::string& cmd, const std::string& note) {
        if (n >= cap) return;
        std::string c = trim(cmd);
        if (c.empty() || c.size() > 4096) return;
        if (!looks_like_command(ByteBuf(c.begin(), c.end()))) return;
        out.push_back({std::string(shell) + "/" + basename, pid, uid, ts, c, note});
        ++n;
    };

    // ---- fish: YAML records ("- cmd:" then optional "when:") ----
    if (kind == ShellKind::Fish) {
        std::string pc, pts; bool have = false;
        auto flush = [&]() {
            if (have)
                emit("fish", pts, pc,
                     pts.empty() ? "high: fish_history"
                                 : "high: fish_history (when: timestamped)");
            have = false; pc.clear(); pts.clear();
        };
        for (auto& l : split_lines(content)) {
            if (n >= cap) break;
            std::string t = trim(l);
            if (t.rfind("- cmd:", 0) == 0) {
                flush();
                pc = unescape_fish(trim(t.substr(6)));
                have = true;
            } else if (have && t.rfind("when:", 0) == 0) {
                std::string d = trim(t.substr(5));
                if (all_digits(d)) pts = iso_from_epoch_string(d);
            }
        }
        flush();
        return;
    }

    // ---- ksh/mksh: frequently a *binary* file; extract printable runs ----
    if (kind == ShellKind::Ksh) {
        for (auto& s : extract_printable_strings(
                 ByteBuf(content.begin(), content.end()), 3)) {
            if (n >= cap) break;
            emit("ksh", "", s, "high: ksh/mksh history file");
        }
        return;
    }

    // ---- line-oriented: bash / zsh / tcsh / posix / powershell / generic ----
    const bool try_zsh = (kind == ShellKind::Zsh || kind == ShellKind::Generic);
    std::string pend_ts;
    for (auto& l : split_lines(content)) {
        if (n >= cap) break;
        std::string t = trim(l);
        if (t.empty()) continue;

        // zsh extended-history takes precedence (": <ts>:<dur>;cmd").
        std::string zts, zcmd;
        if (try_zsh && parse_zsh_extended(t, zts, zcmd)) {
            emit("zsh", zts, zcmd, "high: zsh extended-history (timestamped)");
            pend_ts.clear();
            continue;
        }

        // bash "#<epoch>" / tcsh "#+<epoch>" marker applies to the NEXT command.
        std::string ep = epoch_marker_digits(t);
        if (!ep.empty()) { pend_ts = iso_from_epoch_string(ep); continue; }

        const char* shell = "shell";
        std::string note  = "high: shell history file";
        switch (kind) {
            case ShellKind::Bash:
                shell = "bash";
                note  = pend_ts.empty() ? "high: .bash_history"
                                        : "high: .bash_history (timestamped)";
                break;
            case ShellKind::Zsh:
                shell = "zsh";
                note  = "high: .zsh_history";
                break;
            case ShellKind::Tcsh:
                shell = "tcsh";
                note  = pend_ts.empty() ? "high: tcsh/csh history"
                                        : "high: tcsh/csh history (timestamped)";
                break;
            case ShellKind::PowerShell:
                shell = "powershell";
                note  = "high: PSReadLine ConsoleHost_history";
                break;
            case ShellKind::Posix:
                shell = "sh";
                note  = "high: POSIX shell history (dash/ash/sh)";
                break;
            default:  // Generic / Unknown
                shell = "shell";
                note  = pend_ts.empty() ? "high: shell history file"
                                        : "high: shell history file (timestamped)";
                break;
        }
        emit(shell, pend_ts, t, note);
        pend_ts.clear();
    }
}

bool generic_command_candidate(const std::string& t) {
    if (t.size() < 6 || t.size() > 512) return false;
    if (t.front() == '/' && t.find(' ') == std::string::npos) return false;
    std::istringstream ss(t);
    std::string first;
    ss >> first;
    if (first.empty()) return false;
    bool first_ok = false;
    for (unsigned char c : first) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            c == '/' || c == '.' || c == '_') {
            first_ok = true;
            continue;
        }
        if (c >= '0' && c <= '9') continue;
        return false;
    }
    if (!first_ok) return false;
    static const char* kKnown[] = {
        "sudo", "su", "cd", "ls", "cat", "grep", "find", "chmod", "chown",
        "cp", "mv", "rm", "mkdir", "dnf", "yum", "apt", "curl", "wget",
        "ssh", "scp", "git", "python", "python3", "bash", "zsh", "fish",
        "sh", "./", "/"
    };
    for (const char* k : kKnown)
        if (t.rfind(k, 0) == 0) return true;
    return t.find(' ') != std::string::npos &&
           (t.find('/') != std::string::npos ||
            t.find("--") != std::string::npos ||
            t.find("|") != std::string::npos ||
            t.find(">") != std::string::npos);
}

// The `source` column is "<shell>/<origin>" where origin is "heap" or a real
// history filename (e.g. "bash/.bash_history", "zsh/heap").
std::string source_origin(const ShellCmd& e) {
    auto slash = e.source.find('/');
    return slash == std::string::npos ? std::string() : e.source.substr(slash + 1);
}

bool high_confidence_history(const ShellCmd& e) {
    // Explicit confidence in the note wins.
    if (e.note.rfind("high:", 0) == 0) return true;
    if (e.note.rfind("low:",  0) == 0) return false;
    // Any recovered timestamp → high.
    if (!e.timestamp.empty()) return true;
    // No timestamp: high-confidence ONLY if it came from a real on-disk history
    // file (a genuine .bash_history/.zsh_history line is reliable even without
    // a timestamp). A heap-shape match with no timestamp is only medium — it
    // belongs in the lower-confidence section, NOT high. (Previously every
    // bash/zsh/fish heap hit was classified high regardless of timestamp.)
    const std::string origin = source_origin(e);
    return !origin.empty() && origin != "heap";
}

} // anon

std::vector<ShellCmd> parse_history_bytes(const std::string& filename,
                                          const std::string& content) {
    std::vector<ShellCmd> out;
    parse_history_file(shell_kind_from_filename(filename),
                       path_basename(filename), content, 0, 0, out);
    return out;
}

std::vector<BashCmd> scan_bash_history(const Engine& eng, const Process& p) {
    std::vector<BashCmd> out;
    if (p.mm == 0 || p.task_va == 0) return out;
    if (p.comm != "bash") return out;   // skip non-bash processes

    const auto& isf = eng.isf();

    // Look up mm_struct fields
    u64 mm_pgd_off, mm_start_brk_off, mm_brk_off;
    try {
        mm_pgd_off       = isf.field_offset("mm_struct", "pgd");
        mm_start_brk_off = isf.field_offset("mm_struct", "start_brk");
        mm_brk_off       = isf.field_offset("mm_struct", "brk");
    } catch (...) { return out; }

    PAddr mm_pa = p.mm - eng.kernel().direct_map_base;
    VAddr pgd_va = 0, start_brk = 0, brk = 0;
    if (eng.phys().read(mm_pa + mm_pgd_off,       &pgd_va,    8) != 8) return out;
    if (eng.phys().read(mm_pa + mm_start_brk_off, &start_brk, 8) != 8) return out;
    if (eng.phys().read(mm_pa + mm_brk_off,       &brk,       8) != 8) return out;

    PAddr user_pgd_pa = pgd_va - eng.kernel().direct_map_base;
    if (start_brk == 0 || brk <= start_brk) return out;

    const u64 heap_size = brk - start_brk;
    if (heap_size > 256ULL * 1024 * 1024) {
        log::warn("bash_history: pid {} heap too large ({} MB) — skipping",
                  p.pid, heap_size >> 20);
        return out;
    }

    log::info("bash_history: pid {} scanning heap [{:#x}..{:#x}] ({} KB)",
              p.pid, start_brk, brk, heap_size >> 10);

    // Read the whole heap in 64 KB chunks via the user PGD.
    std::vector<u8> heap(heap_size, 0);
    x86_64::PageTable upt(eng.phys(), user_pgd_pa);
    upt.read(start_brk, heap.data(), heap_size);

    // Now scan 8-byte aligned positions for HIST_ENTRY-shaped windows:
    //   { line_ptr (heap addr), timestamp_ptr (NULL OR heap addr), data_ptr (any) }
    std::set<VAddr> seen_line_ptrs;   // dedupe re-discovered entries
    for (std::size_t i = 0; i + 24 <= heap.size(); i += 8) {
        VAddr line_ptr, ts_ptr, data_ptr;
        std::memcpy(&line_ptr,  heap.data() + i,      8);
        std::memcpy(&ts_ptr,    heap.data() + i + 8,  8);
        std::memcpy(&data_ptr,  heap.data() + i + 16, 8);

        if (!is_heap_va(line_ptr, start_brk, brk)) continue;
        if (seen_line_ptrs.count(line_ptr)) continue;

        // data_ptr in a real HIST_ENTRY is usually NULL (set to 0 unless
        // bash has annotated the entry — rare). Reject entries with a
        // non-NULL data pointer to drop pointer-array false positives.
        if (data_ptr != 0) continue;

        // ts_ptr must be either NULL or a heap-VA pointing to a valid
        // "#<unix_ts>" string. Anything else is a false positive (e.g.
        // envp arrays that happen to have a string pointer in slot 2).
        std::vector<u8> ts_bytes;
        if (ts_ptr != 0) {
            if (!is_heap_va(ts_ptr, start_brk, brk)) continue;
            std::size_t ts_off = ts_ptr - start_brk;
            if (ts_off >= heap.size()) continue;
            for (std::size_t j = ts_off;
                 j < heap.size() && j - ts_off < 32;
                 ++j)
            {
                if (heap[j] == 0) break;
                ts_bytes.push_back(heap[j]);
            }
            if (ts_bytes.size() < 2 || ts_bytes[0] != '#' ||
                ts_bytes.size() > 16) continue;
            bool digits = true;
            for (std::size_t j = 1; j < ts_bytes.size(); ++j)
                if (ts_bytes[j] < '0' || ts_bytes[j] > '9')
                { digits = false; break; }
            if (!digits) continue;
        }

        // Read what line_ptr points to (the command text).
        std::size_t line_off = line_ptr - start_brk;
        if (line_off >= heap.size()) continue;
        std::vector<u8> line_bytes;
        for (std::size_t j = line_off; j < heap.size() && j - line_off < 1024; ++j) {
            if (heap[j] == 0) break;
            line_bytes.push_back(heap[j]);
        }
        if (!looks_like_command(line_bytes)) continue;

        // Reject env-var-style strings (FOO=bar where FOO is all-upper).
        // Real shell commands rarely start with all-upper followed by '='.
        {
            std::size_t eq = 0;
            while (eq < line_bytes.size() && line_bytes[eq] != '=') ++eq;
            if (eq > 0 && eq < line_bytes.size()) {
                bool allcaps_or_digit = true;
                for (std::size_t j = 0; j < eq; ++j) {
                    u8 c = line_bytes[j];
                    if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_')) {
                        allcaps_or_digit = false; break;
                    }
                }
                if (allcaps_or_digit && eq <= 32) continue;
            }
        }

        // Convert the validated timestamp string (if any) for display.
        std::string ts_str;
        if (!ts_bytes.empty()) {
            std::string num((char*)ts_bytes.data() + 1, ts_bytes.size() - 1);
            try {
                std::time_t t = std::stoll(num);
                std::tm* tm = std::gmtime(&t);
                if (tm) {
                    char b[32];
                    std::strftime(b, sizeof(b),
                                  "%Y-%m-%d %H:%M:%S UTC", tm);
                    ts_str = b;
                }
            } catch (...) {}
        }

        BashCmd c;
        c.command = std::string((char*)line_bytes.data(), line_bytes.size());
        c.timestamp = std::move(ts_str);
        c.heap_va = start_brk + i;
        out.push_back(std::move(c));
        seen_line_ptrs.insert(line_ptr);
    }

    log::info("bash_history: pid {} recovered {} candidate command(s)",
              p.pid, out.size());
    return out;
}

std::vector<ShellCmd> scan_shell_history(const Engine& eng, const Process& p) {
    std::vector<ShellCmd> out;

    if (p.comm == "bash") {
        auto cmds = scan_bash_history(eng, p);
        for (auto& c : cmds) {
            if (c.timestamp.empty() && !generic_command_candidate(c.command))
                continue;
            out.push_back({"bash/heap", p.pid, p.uid, std::move(c.timestamp),
                           std::move(c.command),
                           c.timestamp.empty()
                               ? "medium: bash HIST_ENTRY heap shape (no timestamp)"
                               : "high: bash HIST_ENTRY timestamped"});
        }
    }

    if (!shell_like_process(eng, p)) return out;

    std::vector<u8> heap;
    VAddr start_brk = 0, brk = 0;
    PAddr user_pgd_pa = 0;
    if (!read_process_heap(eng, p, heap, start_brk, brk, user_pgd_pa))
        return out;

    std::unordered_set<std::string> seen;
    for (const auto& c : out) seen.insert(c.command);

    std::size_t generic_added = 0;
    const bool allow_generic = generic_heap_scan_allowed(eng, p);
    for (const auto& s : extract_printable_strings(heap, 4)) {
        std::string ts, cmd;
        bool zsh = parse_zsh_extended(s, ts, cmd);
        bool fish = false;
        if (!zsh) fish = parse_fish_cmd(s, cmd);

        if (zsh || fish) {
            if (seen.insert(cmd).second) {
                out.push_back({zsh ? "zsh/heap" : "fish/heap",
                               p.pid, p.uid, ts, cmd,
                               zsh ? "medium: zsh extended-history string in heap"
                                   : "medium: fish history string in heap"});
            }
            continue;
        }

        if (!allow_generic) continue;
        if (generic_added >= 25) continue;
        std::string t = trim(s);
        if (!looks_like_command(ByteBuf(t.begin(), t.end()))) continue;
        if (!generic_command_candidate(t)) continue;
        if (seen.insert(t).second) {
            // Unknown shell, heap-derived, no timestamp → genuinely low.
            out.push_back({"shell?/heap", p.pid, p.uid, {}, t,
                           "low: printable command-like string in shell heap"});
            ++generic_added;
        }
    }
    return out;
}

ByteBuf format_shell_history(const Engine& eng, const Process& p) {
    auto cmds = scan_shell_history(eng, p);
    if (cmds.empty()) {
        std::string s = fmt::format(
            "; no shell history recovered for pid {} ({}).\n"
            "; The process may not be a shell, the heap may be non-resident, "
            "or no history-like strings survived in RAM.\n",
            p.pid, p.comm);
        return ByteBuf(s.begin(), s.end());
    }
    std::string out;
    out.reserve(16 * 1024);
    out += fmt::format("# shell history recovered from pid {} ({})\n", p.pid, p.comm);
    std::vector<ShellCmd> high, low;
    for (const auto& e : cmds) {
        if (high_confidence_history(e))
            high.push_back(e);
        else
            low.push_back(e);
    }
    out += fmt::format("# {} candidate(s): {} high-confidence, {} lower-confidence.\n",
                       cmds.size(), high.size(), low.size());

    auto append_section = [&](std::string_view title,
                              const std::vector<ShellCmd>& rows) {
        out += fmt::format("#\n# === {} ===\n", title);
        if (rows.empty()) {
            out += "; none\n";
            return;
        }
        out += "# source               timestamp                  command\n"
               "#--------------------+--------------------------+--------\n";
        for (const auto& e : rows) {
            out += fmt::format("{:<20} {:<26} {}\n",
                               e.source,
                               e.timestamp.empty() ? "-" : e.timestamp,
                               e.command);
        }
    };
    append_section("High-Confidence Entries", high);
    append_section("Lower-Confidence Candidates", low);
    return ByteBuf(out.begin(), out.end());
}

ByteBuf format_global_shell_history(const Engine& eng) {
    std::vector<ShellCmd> all;
    struct UnavailableHistoryFile {
        std::string path;
        std::string fs;
        u64 ino = 0;
        u64 size = 0;
        u64 cached_pages = 0;
        std::string reason;
    };
    std::vector<UnavailableHistoryFile> unavailable_files;
    for (const auto& p : eng.processes()) {
        try {
            auto cmds = scan_shell_history(eng, p);
            all.insert(all.end(),
                       std::make_move_iterator(cmds.begin()),
                       std::make_move_iterator(cmds.end()));
        } catch (...) {}
    }

    // Add cached on-disk history files. The stateful, format-aware parser
    // names the source by the *detected* shell + file (e.g. "bash/.bash_history",
    // "fish/fish_history", "powershell/ConsoleHost_history.txt") and recovers
    // each format's timestamps (bash #<epoch>, zsh extended, fish when:, tcsh
    // #+<epoch>). Cap input size so a giant sparse file can't blow up output.
    try {
        auto inodes = enumerate_cached_inodes(eng);
        for (const auto& ci : inodes) {
            if ((ci.i_mode & 0170000) != 0100000) continue;
            if (!history_filename(ci.path)) continue;
            u64 sz = recover_file_size(eng, ci);
            if (sz == 0) {
                unavailable_files.push_back({ci.path, ci.sb_fs, ci.i_ino, ci.i_size,
                                             ci.nr_cached,
                                             "zero logical size recovered"});
                continue;
            }
            if (ci.nr_cached == 0) {
                unavailable_files.push_back({ci.path, ci.sb_fs, ci.i_ino, ci.i_size,
                                             ci.nr_cached,
                                             "inode metadata recovered, but no cached content pages"});
                continue;
            }
            if (sz > 2ULL * 1024 * 1024) {
                unavailable_files.push_back({ci.path, ci.sb_fs, ci.i_ino, ci.i_size,
                                             ci.nr_cached,
                                             "history file larger than 2 MiB parser cap"});
                continue;
            }
            auto bytes = recover_file(eng, ci);
            std::string text(reinterpret_cast<const char*>(bytes.data()), bytes.size());
            parse_history_file(shell_kind_from_filename(ci.path),
                               path_basename(ci.path), text, 0, 0, all);
        }
    } catch (const std::exception& e) {
        log::debug("shell_history: cached history file scan failed: {}", e.what());
    }

    std::unordered_set<std::string> seen;
    std::vector<ShellCmd> deduped;
    deduped.reserve(all.size());
    for (auto& e : all) {
        std::string key = fmt::format("{}\x1f{}\x1f{}\x1f{}\x1f{}\x1f{}",
                                      e.source, e.pid, e.uid, e.timestamp,
                                      e.note, e.command);
        if (seen.insert(std::move(key)).second)
            deduped.push_back(std::move(e));
    }
    all = std::move(deduped);

    std::sort(all.begin(), all.end(),
        [](const ShellCmd& a, const ShellCmd& b) {
            if (a.timestamp.empty() != b.timestamp.empty())
                return !a.timestamp.empty();
            if (a.timestamp != b.timestamp) return a.timestamp < b.timestamp;
            if (a.pid != b.pid) return a.pid < b.pid;
            return a.command < b.command;
        });

    std::vector<ShellCmd> high, low;
    for (const auto& e : all) {
        if (high_confidence_history(e))
            high.push_back(e);
        else
            low.push_back(e);
    }

    std::string out;
    out.reserve(128 * 1024);
    out += fmt::format(
        "# /sys/shell_history.txt - aggregate shell history recovery\n"
        "# {} candidate command(s). Sources: on-disk history files recovered from\n"
        "# the page cache -- bash, zsh, fish, tcsh/csh, ksh/mksh, dash/ash/sh, and\n"
        "# PowerShell Core (pwsh on Linux) -- plus per-process heap scans.\n"
        "# {} high-confidence; {} lower-confidence.\n"
        "# High-confidence includes known history files/formats even when timestamps are absent.\n"
        "# Low-confidence generic heap strings need analyst review.\n"
        "#\n",
        all.size(), high.size(), low.size());

    auto append_section = [&](std::string_view title,
                              const std::vector<ShellCmd>& rows) {
        out += fmt::format("# === {} ===\n", title);
        if (rows.empty()) {
            out += "; none\n#\n";
            return;
        }
        out += "# source               pid    uid   timestamp                  command\n"
               "#--------------------+------+------+--------------------------+--------\n";
        for (const auto& e : rows) {
            out += fmt::format("{:<20} {:>6} {:>6} {:<26} {}\n",
                               e.source,
                               e.pid,
                               e.uid,
                               e.timestamp.empty() ? "-" : e.timestamp,
                               e.command);
        }
        out += "#\n";
    };

    append_section("High-Confidence Entries", high);
    append_section("Lower-Confidence Candidates", low);
    out += "# === History Files Found But Content Unavailable ===\n";
    if (unavailable_files.empty()) {
        out += "; none\n#\n";
    } else {
        out += "# fs       ino        size       cached  path reason\n"
               "#--------+----------+----------+-------+----+------\n";
        for (const auto& f : unavailable_files) {
            out += fmt::format("{:<8} {:>10} {:>10} {:>7} {} - {}\n",
                               f.fs.empty() ? "?" : f.fs,
                               f.ino,
                               f.size,
                               f.cached_pages,
                               f.path.empty() ? "(unresolved)" : f.path,
                               f.reason);
        }
        out += "#\n";
    }
    if (all.empty()) {
        out += "; no shell history candidates recovered. Try checking /fs for cached "
               "history files and /proc/<pid>/strings.txt for individual shells.\n";
    }
    return ByteBuf(out.begin(), out.end());
}

} // namespace lmpfs::linux
