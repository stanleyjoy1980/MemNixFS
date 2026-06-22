// ebpf.h — enumerate every loaded eBPF program.
//
// eBPF programs live in `prog_idr` (kernel/bpf/syscall.c) — an `idr`,
// which on modern kernels is a thin wrapper around an `xarray`. Each
// leaf is a `struct bpf_prog *`.
//
// For each program we surface:
//   * id            (bpf_prog_aux.id; matches `bpftool prog show`)
//   * type          (enum bpf_prog_type — KPROBE / TRACEPOINT / XDP / TC / ...)
//   * tag           (8-byte SHA-1 truncation of the program's bytecode)
//   * name          (bpf_prog_aux.name[16] — set via prog_aux->name or LIBBPF)
//   * load_time     (jiffies-ish since boot when the prog was loaded)
//   * bpf_func      (pointer to the JITed code; in module/vmalloc range)
//
// Forensic value: an eBPF-based rootkit (kprobes attaching to syscall
// entry, XDP filters dropping connections, etc.) only shows up here —
// they don't appear in /proc, modules, or sockets. The forensic
// community has been calling out eBPF rootkits as the next major
// attack-surface gap; vol3 added `linux.ebpf` in 2024.
//
// Cross-ref: vol3 `linux.ebpf`; MemProcFS has no Windows equivalent.
#pragma once
#include "core/types.h"
#include "core/stream.h"
#include <string>
#include <vector>

namespace lmpfs { class Engine; }

namespace lmpfs::linux {

struct BpfProgInfo {
    u32         id        = 0;
    u32         type      = 0;      // bpf_prog_type enum
    u32         jited_len = 0;
    std::string tag_hex;             // 8-byte SHA-1 tag → 16 hex chars
    std::string name;                // up to 16 chars
    u64         load_time_ns = 0;
    VAddr       bpf_func   = 0;     // JITed code entry
    VAddr       prog_va    = 0;
};

std::vector<BpfProgInfo> enumerate_bpf_programs(const Engine& eng);

// /sys/findevil/ebpf.txt
ByteBuf format_ebpf_programs(const Engine& eng);

// Human-readable bpf_prog_type name.
const char* bpf_prog_type_name(u32 t);

} // namespace lmpfs::linux
