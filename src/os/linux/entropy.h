// entropy.h — Shannon-entropy scan for packed / encrypted code.
//
// Shellcode loaders, encrypted droppers, and packed malware (UPX, ASPack,
// custom packers) all have one observable: their executable byte content
// is high-entropy (close to uniform random). Honest x86_64 machine code
// is ~5.5-6.0 bits/byte. Encrypted blobs are 7.8-8.0.
//
// We walk every user task's executable VMAs, sample some pages of each,
// compute Shannon entropy, and flag any VMA above the threshold (7.0
// default — well outside the legit-code distribution).
//
// Per-process file:  /proc/<pid>/entropy.txt
// Aggregated:        /sys/findevil/entropy.txt   (high-entropy hits only)
//
// Cross-ref: MemProcFS `m_evil_entropy.c`. vol3 doesn't have a direct
// equivalent (it's adjacent to `linux.malfind`).
#pragma once
#include "core/types.h"
#include "core/stream.h"
#include "os/linux/process.h"
#include <string>
#include <vector>

namespace lmpfs { class Engine; }

namespace lmpfs::linux {

struct EntropyHit {
    VAddr   vm_start = 0;
    VAddr   vm_end   = 0;
    u64     vm_flags = 0;
    bool    anonymous = false;
    double  entropy   = 0.0;       // bits per byte, 0..8
    std::size_t bytes_sampled = 0;
};

std::vector<EntropyHit> scan_entropy(const Engine& eng, const Process& p);

// /proc/<pid>/entropy.txt — every exec VMA + its entropy
ByteBuf format_proc_entropy(const Engine& eng, const Process& p);

// /sys/findevil/entropy.txt — only HIGH-entropy hits across every task
ByteBuf format_findevil_entropy(const Engine& eng);

} // namespace lmpfs::linux
