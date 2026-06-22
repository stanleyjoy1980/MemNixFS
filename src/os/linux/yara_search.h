// yara_search.h — YARA rule-scanning over user-process memory.
//
// Two surfaces:
//
//   /search/yara.txt           Global scan across every user task's
//                              readable VMAs. Output groups hits by
//                              rule, then by PID; each row shows the
//                              VMA, offset within the VMA, and a short
//                              hex-preview of the match site.
//
//   /proc/<pid>/yara.txt       Same scanner, scoped to one process.
//
// Rule sources (loaded once at engine init, cached for every scan):
//
//   1. Built-in default rules. Compiled in from `default_rules.inc`
//      (loaded via header text constant). Covers EICAR, common
//      shellcode markers, Mimikatz strings, Cobalt Strike beacons,
//      meterpreter, common packer signatures.
//
//   2. $LMPFS_YARA_RULES — colon-separated list of .yar / .yara files
//      or directories. Each .yar file is compiled into the same
//      ruleset. Bad rules are skipped with a warning.
//
//   3. %LOCALAPPDATA%/MemNixFS/yara/*.yar — default user drop-in dir.
//
// Build:
//   This file is built only when LMPFS_HAS_YARA is defined (set by
//   CMake when libyara is found). Otherwise the format_* functions
//   return a one-line "(YARA support not built into this binary)"
//   message.
//
// References:
//   MemProcFS:  m_searchyara.c + vmmyarautil.c
//   vol3:       vmayarascan.py
//
#pragma once
#include "core/types.h"
#include "core/stream.h"
#include "os/linux/process.h"

namespace lmpfs { class Engine; }

namespace lmpfs::linux {

// /search/yara.txt — global scan, all rules, all processes, one file.
ByteBuf format_yara_global(const Engine& eng);

// /proc/<pid>/yara.txt — per-process scope.
ByteBuf format_yara_per_pid(const Engine& eng, const Process& p);

// Per-rule subdir contents (v0.25). Each rule from the loaded ruleset
// gets its own file under /search/yara/<rule>.txt, with ONLY that rule's
// matches. Surfaced through these accessors:
//
//   list_yara_rule_names()     — names known to the loaded ruleset (or
//                                empty if YARA isn't built into this
//                                binary, OR rule compilation failed).
//   format_yara_per_rule(name) — same scan run as the global one, but
//                                filtered to rule == `name`. Returns a
//                                short "(no matches)" body when clean.
std::vector<std::string> list_yara_rule_names(const Engine& eng);
ByteBuf format_yara_per_rule(const Engine& eng, const std::string& rule);

} // namespace lmpfs::linux
