// csv_export.h — CSV renderings of high-value plugins for SIEM ingestion.
//
// Every plugin already emits human-readable text at `/sys/.../*.txt`.
// CSV adds a structured-data sibling so analysts can pipe these into
// jq / pandas / SIEM ingest with no parsing acrobatics.
//
// The CSV format follows RFC 4180:
//   - Comma separator, CRLF row terminator (Excel-friendly).
//   - Fields containing comma / double-quote / CR / LF are double-quoted;
//     internal double-quotes are doubled (`"foo""bar"`).
//   - First row is the header.
//
// Files:
//   /sys/processes/pslist.csv         pid, ppid, tgid, uid, comm, cmdline
//   /sys/net/tcp.csv                  state, family, local_ip, local_port,
//                                     remote_ip, remote_port, sock_va
//   /sys/net/udp.csv                  same shape as tcp.csv
//   /sys/findevil/malfind.csv         pid, comm, vm_start, vm_end, perms,
//                                     size, severity, reason
//   /sys/findevil/findevil.csv        the verdict + per-check counts in
//                                     one row per dump (single row, but
//                                     SIEM-friendly)
//
// MPFS: `m_fc_csv.c` exposes every plugin in CSV — we cover the most-
// used subset; the rest follow the same pattern.
#pragma once
#include "core/types.h"
#include "core/stream.h"

namespace lmpfs { class Engine; }

namespace lmpfs::linux {

// Quote a field for RFC 4180. Returns the field unchanged if no escape
// is needed.
std::string csv_quote(std::string s);

ByteBuf format_pslist_csv      (const Engine& eng);
ByteBuf format_tcp_csv         (const Engine& eng);
ByteBuf format_udp_csv         (const Engine& eng);
ByteBuf format_malfind_csv     (const Engine& eng);
ByteBuf format_findevil_csv    (const Engine& eng);

} // namespace lmpfs::linux
