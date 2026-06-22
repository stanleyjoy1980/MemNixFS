#pragma once
#include "core/types.h"
#include "io/memory_source.h"
#include <memory>
#include <vector>
#include <string>

namespace lmpfs {

// A PhysicalLayer exposes a flat physical address space, possibly sparse,
// backed by a MemorySource that may need decoding (LiME headers, AVML snappy).
class PhysicalLayer {
public:
    struct Range {
        PAddr start = 0;
        u64   length = 0;
    };

    virtual ~PhysicalLayer() = default;

    // Largest physical address that has data + 1 (exclusive upper bound).
    virtual PAddr max_address() const = 0;

    // Reads physical memory. Returns number of bytes read.
    // Implementations zero-fill holes in `out` for caller convenience, but
    // holes and unreadable bytes are NOT counted in the return value.
    // Throws on hard I/O errors only.
    virtual std::size_t read(PAddr pa, void* out, std::size_t len) const = 0;

    virtual const std::string& format_name() const = 0;
    virtual const std::string& source_name() const = 0;

    // Captured physical ranges, when the format can report them cheaply.
    // Sparse stream views such as /mem/phys.raw may zero-fill everything
    // outside these ranges; that zero-fill is not forensic evidence.
    virtual std::vector<Range> ranges() const { return {}; }

    // Convenience.
    bool read_exact(PAddr pa, void* out, std::size_t len) const {
        return read(pa, out, len) == len;
    }
    template <typename T>
    bool read_pod(PAddr pa, T& v) const {
        static_assert(std::is_trivially_copyable_v<T>);
        return read_exact(pa, &v, sizeof(T));
    }
};

} // namespace lmpfs
