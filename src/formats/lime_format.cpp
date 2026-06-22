#include "formats/format_factory.h"
#include "core/error.h"
#include "core/log.h"
#include <algorithm>
#include <cstring>
#include <vector>

namespace lmpfs {
namespace {

// LiME header: u32 magic, u32 version, u64 start, u64 end, u64 reserved.
// Each segment is followed by (end - start + 1) bytes of raw data, then the
// next header. Holes in physical address space are simply skipped (no segment).
struct LimeHeader {
    u32 magic;
    u32 version;
    u64 start;
    u64 end;
    u64 reserved;
};
static_assert(sizeof(LimeHeader) == 32, "LiME header must be 32 bytes");

struct LimeSegment {
    PAddr pa_start;     // physical address of first byte
    u64   pa_length;    // size in physical space
    u64   file_offset;  // file offset of segment data (post-header)
};

class LimePhysical : public PhysicalLayer {
public:
    explicit LimePhysical(std::unique_ptr<MemorySource> src)
        : src_(std::move(src)), fmt_("lime"), name_(src_->name())
    {
        load_segments();
    }

    PAddr max_address() const override { return max_addr_; }
    const std::string& format_name() const override { return fmt_; }
    const std::string& source_name() const override { return name_; }
    std::vector<Range> ranges() const override {
        std::vector<Range> out;
        out.reserve(segs_.size());
        for (const auto& s : segs_)
            out.push_back({s.pa_start, s.pa_length});
        return out;
    }

    std::size_t read(PAddr pa, void* out, std::size_t len) const override {
        u8* dst = static_cast<u8*>(out);
        std::memset(dst, 0, len);
        std::size_t total = 0;
        PAddr cur = pa, end = pa + len;
        for (const auto& s : segs_) {
            PAddr s_end = s.pa_start + s.pa_length;
            if (s_end <= cur) continue;
            if (s.pa_start >= end) break;
            PAddr rs = std::max(cur, s.pa_start);
            PAddr re = std::min(end, s_end);
            std::size_t n = static_cast<std::size_t>(re - rs);
            u64 file_off = s.file_offset + (rs - s.pa_start);
            std::size_t got = src_->read(file_off, dst + (rs - pa), n);
            total += got;
            cur = re;
        }
        return total;
    }

private:
    void load_segments() {
        u64 off = 0;
        u64 file_size = src_->size();
        PAddr prev_end = 0;
        while (off + sizeof(LimeHeader) <= file_size) {
            LimeHeader h;
            if (src_->read(off, &h, sizeof(h)) != sizeof(h))
                throw_error("LiME: short read for header at {:#x}", off);
            if (h.magic != 0x4C694D45)
                throw_error("LiME: bad magic {:#x} at offset {:#x}", h.magic, off);
            if (h.version != 1)
                throw_error("LiME: unsupported version {} at offset {:#x}", h.version, off);
            if (h.end < h.start)
                throw_error("LiME: bad range {:#x}-{:#x}", h.start, h.end);
            if (h.start < prev_end)
                throw_error("LiME: out-of-order segment {:#x}", h.start);

            u64 len = h.end - h.start + 1;
            u64 data_off = off + sizeof(LimeHeader);
            u64 remaining = file_size - data_off;
            if (len > remaining) {
                throw_error("LiME: truncated segment {} at offset {:#x}: "
                            "PA range {:#x}-{:#x} needs {:#x} bytes, "
                            "but file has only {:#x} bytes remaining",
                            segs_.size(), off, h.start, h.end, len, remaining);
            }

            LimeSegment s{ h.start, len, data_off };
            segs_.push_back(s);
            prev_end = h.end + 1;
            off = data_off + len;
        }
        if (off != file_size)
            throw_error("LiME: trailing partial header/data at offset {:#x} "
                        "({:#x} byte file)", off, file_size);
        if (segs_.empty()) throw_error("LiME: no segments");
        max_addr_ = segs_.back().pa_start + segs_.back().pa_length;
        log::info("LiME: {} segments, max PA = {:#x}", segs_.size(), max_addr_);
    }

    std::unique_ptr<MemorySource> src_;
    std::vector<LimeSegment>      segs_;
    PAddr                         max_addr_ = 0;
    std::string                   fmt_, name_;
};

} // anonymous

std::unique_ptr<PhysicalLayer> open_lime_physical(std::unique_ptr<MemorySource> src) {
    return std::make_unique<LimePhysical>(std::move(src));
}

} // namespace lmpfs
