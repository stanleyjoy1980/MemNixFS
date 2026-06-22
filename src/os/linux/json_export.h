// json_export.h — JSON renderings of high-value plugins.
//
// Sibling of csv_export.{h,cpp}: same set of plugins, same data, but
// emitted as JSON (one array per file, each row an object) instead of
// RFC 4180 CSV. Use these when:
//
//   * the consumer is jq / Python / Splunk and CSV escaping is a pain
//     (commas in cmdlines, embedded NULs, etc.);
//   * you want nested fields (e.g. malfind's `perms` rendered as
//     `{"r": true, "w": true, "x": true}` instead of "rwx");
//   * you're feeding an LLM that prefers JSON over CSV.
//
// Format follows the JSON-lines-style "one big array" convention used
// by most SIEMs — `[{...}, {...}, ...]\n`. Pretty-printed with 2-space
// indent so the files are human-readable in an editor; jq doesn't
// care about whitespace.
//
// Files:
//   /sys/processes/pslist.json    pid, ppid, tgid, uid, comm, cmdline
//   /sys/net/tcp.json             proto, state, family, local_ip,
//                                 local_port, remote_ip, remote_port, sock_va
//   /sys/net/udp.json             same shape as tcp.json
//   /sys/findevil/malfind.json    pid, comm, vm_start, vm_end, size,
//                                 perms (object), severity, reason
//   /sys/findevil/findevil.json   single object: aggregated counts
//
// MPFS: `m_fc_json.c` is the analogue — every plugin gets a JSON sibling.
#pragma once
#include "core/types.h"
#include "core/stream.h"

namespace lmpfs { class Engine; }

namespace lmpfs::linux {

ByteBuf format_pslist_json   (const Engine& eng);
ByteBuf format_tcp_json      (const Engine& eng);
ByteBuf format_udp_json      (const Engine& eng);
ByteBuf format_malfind_json  (const Engine& eng);
ByteBuf format_findevil_json (const Engine& eng);

} // namespace lmpfs::linux
