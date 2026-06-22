// bash_history.h — recover bash command history from a process's heap.
//
// Bash stores its history as a global linked list (`history_list`) of
// `HIST_ENTRY` structs in heap memory. We don't have bash's symbol
// table, so we use Volatility 3's heuristic: scan the heap for the
// shape of a HIST_ENTRY (three pointers: line, data, timestamp),
// validate the pointed-to strings look like shell commands.
//
// Forensic value: this is often THE smoking-gun artefact in an
// incident response. Recovers the commands an attacker ran, even
// if they cleared `.bash_history` on disk.
//
// References:
//   bash source: lib/readline/history.h (HIST_ENTRY struct)
//   vol3:        framework/plugins/linux/bash.py (the heuristic)
//
#pragma once
#include "core/types.h"
#include "os/linux/process.h"
#include <string>
#include <vector>

namespace lmpfs {
class Engine;
}

namespace lmpfs::linux {

struct BashCmd {
    std::string command;
    std::string timestamp;   // ISO-ish "YYYY-MM-DD HH:MM:SS" — from the
                             // optional timestamp field if present
    VAddr       heap_va;     // where in the heap we found it
};

struct ShellCmd {
    std::string source;
    u32         pid = 0;
    u32         uid = 0;
    std::string timestamp;
    std::string command;
    std::string note;
};

// Scan a process's heap for HIST_ENTRY-shaped records. Best-effort —
// returns whatever survives validation.
std::vector<BashCmd> scan_bash_history(const Engine& eng, const Process& p);

// Broader shell-history scan. Keeps bash HIST_ENTRY results, then adds
// zsh/fish/POSIX history strings and tagged low-confidence heap candidates.
std::vector<ShellCmd> scan_shell_history(const Engine& eng, const Process& p);

// /proc/<pid>/shell_history.txt file content.
ByteBuf format_shell_history(const Engine& eng, const Process& p);

// /sys/shell_history.txt aggregate view.
ByteBuf format_global_shell_history(const Engine& eng);

// Parse raw on-disk history-file content (as recovered from the page cache)
// with the stateful, format-aware logic used by the aggregate view. `filename`
// only selects the shell/format: ".bash_history", ".zsh_history", "fish_history",
// ".tcsh_history", ".sh_history"/".ksh_history", ".dash_history", and
// PowerShell's "ConsoleHost_history.txt" are all recognised. Exposed for unit
// testing and for callers that already hold the file bytes.
std::vector<ShellCmd> parse_history_bytes(const std::string& filename,
                                          const std::string& content);

} // namespace lmpfs::linux
