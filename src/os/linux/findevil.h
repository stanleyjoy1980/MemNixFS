// findevil.h — Threat-hunt heuristics over the dump.
//
// Three plugins, all under `/sys/findevil/`:
//
//   malfind        — anonymous executable VMAs (classic shellcode-injection
//                    detector). Per-process and aggregated. vol3:
//                    `linux.malfind.Malfind`.
//
//   psscan         — scan physical memory for `task_struct` signatures and
//                    diff against the official `init_task.tasks` walk.
//                    Entries that exist only in the scan are processes a
//                    rootkit has unlinked from the visible list. vol3:
//                    `linux.psscan.PsScan`.
//
//   hidden_modules — scan the module-memory region (vmalloc) for `struct
//                    module` signatures and diff against the `modules` list
//                    walk. Same idea for kernel modules. vol3:
//                    `linux.hidden_modules.Hidden_modules`.
//
// Output design: each plugin emits a flat text file with one row per
// finding plus a clear "(0 findings)" message when nothing's suspicious —
// so analysts can ignore the file entirely on a clean box.
#pragma once
#include "core/types.h"
#include "core/stream.h"
#include "os/linux/vma.h"
#include "os/linux/process.h"
#include <string>
#include <vector>

namespace lmpfs { class Engine; }

namespace lmpfs::linux {

// ---------------- malfind ----------------

struct MalfindHit {
    VAddr       vm_start = 0;
    VAddr       vm_end   = 0;
    u64         vm_flags = 0;
    std::string reason;          // human-readable verdict
    bool        high_severity = false;  // true for RWX / exec stack — actually likely-malicious
    std::string content_hint;    // "non-zero [48 89 e5 ...]" / "zero-filled" / "unreadable"
};

// Find suspicious VMAs in a single process. Returns empty for kernel threads.
std::vector<MalfindHit> find_malfind(const Engine& eng, const Process& p);

// MemProcFS-style normalized indicator row. Detailed raw plugins remain
// available, but triage and exports use this common model.
struct Finding {
    std::string severity;             // HIGH, MEDIUM, REVIEW, INFO
    std::string confidence;           // high, medium, low
    std::string type;                 // stable indicator type
    std::string source;               // producing check
    u32         pid = 0;
    u32         tgid = 0;
    u32         uid = 0;
    std::string comm;
    std::string summary;
    std::string evidence;
    std::string false_positive_note;
    std::string next_step;
};

int severity_rank(const std::string& severity);
std::vector<Finding> collect_findevil_indicators(const Engine& eng);

// One file per process — `/proc/<pid>/malfind.txt`.
ByteBuf format_proc_malfind(const Engine& eng, const Process& p);

// Aggregated — `/sys/findevil/malfind.txt`. One section per PID with hits.
ByteBuf format_findevil_malfind(const Engine& eng);
ByteBuf format_findevil_indicators_txt(const Engine& eng);
ByteBuf format_findevil_indicators_csv(const Engine& eng);
ByteBuf format_findevil_indicators_json(const Engine& eng);

// `/sys/findevil/triage.txt` — ranked analyst entry point that correlates the
// highest-signal checks with process context.
ByteBuf format_findevil_triage(const Engine& eng);

// ---------------- psscan ----------------

struct PsScanHit {
    PAddr       task_pa  = 0;
    VAddr       task_va  = 0;     // if directly derivable
    u32         pid      = 0;
    u32         tgid     = 0;
    std::string comm;
    bool        on_official_list = false;   // false = HIDDEN suspect
};

std::vector<PsScanHit> scan_for_tasks(const Engine& eng);

// `/sys/findevil/psscan.txt`. Lists every task found by physical-memory
// scan, with a column flagging entries missing from the official list.
ByteBuf format_findevil_psscan(const Engine& eng);

// ---------------- hidden_modules ----------------

struct HiddenModuleHit {
    VAddr       mod_va   = 0;
    std::string name;
    bool        on_official_list = false;
};

std::vector<HiddenModuleHit> scan_for_modules(const Engine& eng);

// `/sys/findevil/hidden_modules.txt`.
ByteBuf format_findevil_hidden_modules(const Engine& eng);

// ---------------- aggregated ----------------

// `/sys/findevil/findevil.txt` — one-stop "is this box compromised?"
// summary. Combines malfind + psscan + hidden_modules into a single
// readable report. (MemProcFS's `m_fc_findevil.c` mood.)
ByteBuf format_findevil_summary(const Engine& eng);

} // namespace lmpfs::linux
