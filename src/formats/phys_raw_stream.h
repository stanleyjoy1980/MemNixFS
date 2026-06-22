// phys_raw_stream.h — exposes the entire physical address space as a single
// huge file (`/mem/phys.raw`). Presents physical memory as a CONTIGUOUS sparse
// image: interior gaps read as zeros and a windowed read returns the full
// requested length up to max_address, so `cat`/`dd`/HxD stream the whole image
// without stopping at the first hole.
//
// (The underlying PhysicalLayer::read returns only the real frame-backed byte
// count — honest, so MemRead can distinguish mapped vs unmapped. The
// zero-filled contiguous view is layered on here.)
//
// References:
//   MemProcFS: m_vfsroot.c registers `/pmem` similarly.
//
#pragma once
#include "core/stream.h"
#include "formats/physical_layer.h"
#include <algorithm>
#include <cstring>

namespace lmpfs {

class PhysRawStream : public StreamReader {
public:
    explicit PhysRawStream(const PhysicalLayer& phys) : phys_(phys) {}

    u64 size() const override { return phys_.max_address(); }
    std::size_t read(u64 offset, void* out, std::size_t len) override {
        std::memset(out, 0, len);                 // gaps stay zero-filled
        const u64 max = phys_.max_address();
        if (offset >= max) return 0;              // past end of RAM → EOF
        phys_.read(static_cast<PAddr>(offset), out, len);   // fills real bytes
        return static_cast<std::size_t>(std::min<u64>(len, max - offset));
    }

private:
    const PhysicalLayer& phys_;
};

} // namespace lmpfs
