// elf_core_stream.h — per-process proc.dmp as a StreamReader.
//
// Replaces the eager `build_elf_core()` for the streaming path. Construction
// only computes the layout (ELF header + program headers + segment file
// offsets); no process memory is touched. Each `read(off, len)` translates the
// byte range into "serve header bytes from this region" / "walk user PGD for
// VMA #i offset X length Y" and copies only those bytes out.
//
// Eliminates:
//   * the 256 MiB build cap
//   * upfront latency on first read (was several seconds for big processes)
//   * peak RAM proportional to dump size (we only keep header + a small LRU
//     page cache live)
//
// References:
//   MemProcFS:  m_proc_minidump.c (streaming minidump pattern)
//   Volatility: framework/plugins/linux/elfs.py (PT_LOAD layout)
//
#pragma once
#include "core/stream.h"
#include "core/types.h"
#include "formats/physical_layer.h"
#include "arch/x86_64/paging.h"
#include "arch/x86_64/page_cache.h"
#include "os/linux/vma.h"
#include "os/linux/process.h"
#include <memory>
#include <mutex>
#include <vector>

namespace lmpfs::linux {

class ElfCoreStream : public StreamReader {
public:
    // `phys` and `pt` must outlive this object. `vmas` is moved in.
    ElfCoreStream(const PhysicalLayer&        phys,
                  const x86_64::PageTable&    user_pt,
                  Process                     process,
                  std::vector<Vma>            vmas);

    u64         size() const override { return total_size_; }
    std::size_t read(u64 offset, void* out, std::size_t len) override;

private:
    struct PlannedSegment {
        u64 file_off;       // byte offset where this segment's data starts in the ELF file
        u64 file_len;       // bytes of process memory in the file (filesz)
        u64 vm_start;       // user VA where the segment's first byte lives
    };

    void plan();

    const PhysicalLayer*       phys_;
    const x86_64::PageTable*   user_pt_;
    Process                    p_;
    std::vector<Vma>           vmas_;

    std::vector<u8>            header_blob_;   // precomputed ELF header + PHDRs + padding
    std::vector<PlannedSegment> segs_;
    u64                        total_size_ = 0;

    // Per-process page cache (~16 MiB by default). Cache instance is owned
    // by the stream so it lives exactly as long as the proc.dmp node, and the
    // entries don't cross processes (different PGDs). Internally locked, so
    // we don't need to serialize at this layer.
    mutable x86_64::UserPageCache page_cache_{ 16 * 1024 * 1024 };
};

#undef LMPFS_KEEP_READ_MUTEX

} // namespace lmpfs::linux
