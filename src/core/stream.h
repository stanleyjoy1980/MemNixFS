// stream.h — abstract byte-range producer for huge VFS files.
//
// Every file that's too big to materialize in memory (proc.dmp, phys.raw,
// kern_va.raw, future kernel-stack walks) implements StreamReader instead of
// the eager `LazyFileNode` pattern. WinFsp dispatches concurrent reads on
// a single open handle, so implementations MUST be thread-safe.
//
// Design notes:
//   * `size()` is expected to be O(1) — it gets called on every directory
//     listing and FileInfo query. Pre-compute in the constructor.
//   * `read(off, buf, len)` returns the byte count actually written. Holes /
//     unmapped pages must be zero-filled and INCLUDED in the count — never
//     leave the caller's buffer with uninitialized memory.
//   * Reads past size() should write zeros and return len (matches POSIX
//     read() into a sparse file). This keeps editors that probe past EOF
//     happy.
//
#pragma once
#include "core/types.h"
#include <cstddef>
#include <memory>

namespace lmpfs {

class StreamReader {
public:
    virtual ~StreamReader() = default;

    // O(1) virtual file size (no I/O).
    virtual u64 size() const = 0;

    // Reads up to `len` bytes starting at `offset` into `out`. Returns the
    // number of bytes written (must always equal `len` unless `offset` is
    // past size()). Thread-safe.
    virtual std::size_t read(u64 offset, void* out, std::size_t len) = 0;
};

using StreamReaderPtr = std::shared_ptr<StreamReader>;

} // namespace lmpfs
