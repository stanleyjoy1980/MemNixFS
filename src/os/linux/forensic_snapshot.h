// forensic_snapshot.h — one-stop environmental + threat-hunt summary.
//
// `/forensic/snapshot.txt` and `/forensic/snapshot.json` are wider in
// scope than `/sys/findevil/findevil.txt`: in addition to every threat-
// hunt check's counts, they include the box's environmental fingerprint
// — process count by uid, network state, mount count, page-cache size,
// kernel build, etc.  This is the file you read first when triaging a
// new dump.
//
// MPFS analog: `m_fc_*.c` plugins write to /forensic/<plugin>/, with a
// top-level summary doing roughly what this snapshot does. We collapse
// the per-plugin files into a single multi-section text report (and a
// flat JSON sibling for ingestion).
//
#pragma once
#include "core/types.h"
#include "core/stream.h"

namespace lmpfs { class Engine; }

namespace lmpfs::linux {

// Text form — one section per category (env, processes, network,
// threat-hunt, av_edr). Designed for human triage.
ByteBuf format_forensic_snapshot_txt(const Engine& eng);

// JSON form — same fields, machine-readable. One top-level object with
// `env`, `processes`, `network`, `threat_hunt`, `av_edr` sub-objects.
ByteBuf format_forensic_snapshot_json(const Engine& eng);

} // namespace lmpfs::linux
