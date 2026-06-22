#include "formats/format_factory.h"
#include "core/error.h"
#include "core/log.h"
#include <snappy.h>
#include <algorithm>
#include <cstring>
#include <list>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace lmpfs {
namespace {

// AVML v2 layout:
//   For each chunk:
//     chunk_header { u32 magic='AVML', u32 version=2, u64 start, u64 end, u64 padding } (32 bytes)
//     framed-snappy stream covering [start, end) physical
//     8 bytes trailer
// The framed-snappy stream is a sequence of frames:
//   frame_header { u8 type, u24 size_le }  (4 bytes)
//     type 0xFF: stream identifier, payload "sNaPpY"
//     type 0x00: compressed data, payload = u32 CRC + snappy-compressed bytes
//     type 0x01: uncompressed data, payload = u32 CRC + raw bytes

constexpr u32 kAvmlMagic = 0x4C4D5641; // 'AVML'

// Upper bound on a single frame's decompressed size. Real framed-snappy
// chunks cap uncompressed data at 64 KiB; AVML stays within that. We allow a
// very generous 64 MiB so no legitimate capture is rejected, while preventing
// a crafted snappy length header from driving a multi-GB allocation
// (a "snappy bomb" — tiny compressed payload claiming an enormous output).
constexpr u64 kMaxFrameDecompressed = 64ULL * 1024 * 1024;

struct AvmlChunkHeader {
    u32 magic, version;
    u64 start, end, padding;
};
static_assert(sizeof(AvmlChunkHeader) == 32, "");

struct AvmlFrame {
    PAddr pa_start;       // physical address of first byte of this frame
    u64   pa_length;      // decompressed length
    u64   file_offset;    // file offset of the compressed payload (after CRC)
    u32   payload_size;   // size of payload at file_offset (== pa_length when uncompressed)
    bool  compressed;
};

class FrameCache {
public:
    explicit FrameCache(std::size_t max_bytes) : max_bytes_(max_bytes) {}

    // Returns pointer to decompressed bytes for the frame keyed by frame_index.
    // The pointer is valid until the next get() that triggers eviction; callers
    // should copy out promptly. We serialize through mu_.
    const u8* get(std::size_t frame_index,
                  const AvmlFrame& f,
                  const MemorySource& src)
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = map_.find(frame_index);
        if (it != map_.end()) {
            order_.splice(order_.begin(), order_, it->second.it);
            return it->second.bytes.data();
        }
        std::vector<u8> raw(f.payload_size);
        if (src.read(f.file_offset, raw.data(), raw.size()) != raw.size())
            throw_error("AVML: short read of frame {} at {:#x}", frame_index, f.file_offset);

        std::vector<u8> out;
        if (f.compressed) {
            std::size_t ulen = 0;
            if (!snappy::GetUncompressedLength(reinterpret_cast<const char*>(raw.data()),
                                               raw.size(), &ulen))
                throw_error("AVML: snappy length probe failed (frame {})", frame_index);
            // Must match the length validated (and bounded) at parse time —
            // reject before allocating so a tampered payload can't resize huge.
            if (ulen != f.pa_length)
                throw_error("AVML: frame {} length probe ({}) disagrees with "
                            "parsed length ({})", frame_index, ulen, f.pa_length);
            out.resize(ulen);
            if (!snappy::RawUncompress(reinterpret_cast<const char*>(raw.data()),
                                       raw.size(),
                                       reinterpret_cast<char*>(out.data())))
                throw_error("AVML: snappy decompression failed (frame {})", frame_index);
        } else {
            out = std::move(raw);
        }
        if (out.size() != f.pa_length)
            throw_error("AVML: frame {} length mismatch ({} vs expected {})",
                        frame_index, out.size(), f.pa_length);

        order_.push_front(frame_index);
        Entry e{ order_.begin(), std::move(out) };
        auto [ins, _] = map_.emplace(frame_index, std::move(e));
        cur_bytes_ += ins->second.bytes.size();
        evict_if_needed();
        return ins->second.bytes.data();
    }

private:
    void evict_if_needed() {
        while (cur_bytes_ > max_bytes_ && !order_.empty()) {
            std::size_t victim = order_.back();
            auto it = map_.find(victim);
            if (it != map_.end()) {
                cur_bytes_ -= it->second.bytes.size();
                map_.erase(it);
            }
            order_.pop_back();
        }
    }

    struct Entry {
        std::list<std::size_t>::iterator it;
        std::vector<u8>                  bytes;
    };
    std::mutex                                          mu_;
    std::list<std::size_t>                              order_;
    std::unordered_map<std::size_t, Entry>              map_;
    std::size_t                                         cur_bytes_ = 0;
    std::size_t                                         max_bytes_;
};

class AvmlPhysical : public PhysicalLayer {
public:
    explicit AvmlPhysical(std::unique_ptr<MemorySource> src)
        : src_(std::move(src))
        , cache_(128ULL * 1024 * 1024) // 128 MB
        , fmt_("avml")
        , name_(src_->name())
    {
        load_chunks();
    }

    PAddr max_address() const override { return max_addr_; }
    const std::string& format_name() const override { return fmt_; }
    const std::string& source_name() const override { return name_; }
    std::vector<Range> ranges() const override {
        std::vector<Range> out;
        out.reserve(frames_.size());
        for (const auto& f : frames_)
            out.push_back({f.pa_start, f.pa_length});
        return out;
    }

    std::size_t read(PAddr pa, void* out, std::size_t len) const override {
        u8* dst = static_cast<u8*>(out);
        std::memset(dst, 0, len);
        if (len == 0) return 0;
        PAddr end = pa + len;
        std::size_t total = 0;

        // Binary search for first frame whose end > pa.
        auto it = std::upper_bound(
            frames_.begin(), frames_.end(), pa,
            [](PAddr a, const AvmlFrame& f) { return a < f.pa_start + f.pa_length; });

        for (; it != frames_.end() && it->pa_start < end; ++it) {
            const auto& f = *it;
            PAddr f_end = f.pa_start + f.pa_length;
            PAddr rs = std::max(pa, f.pa_start);
            PAddr re = std::min(end, f_end);
            std::size_t n = static_cast<std::size_t>(re - rs);
            std::size_t frame_idx = static_cast<std::size_t>(&f - &frames_[0]);
            const u8* data = cache_.get(frame_idx, f, *src_);
            std::memcpy(dst + (rs - pa), data + (rs - f.pa_start), n);
            total += n;
        }
        // Return the count of REAL (frame-backed) bytes. The buffer is still
        // zero-filled for gaps (memset above), but the return value stays
        // honest so callers can distinguish mapped from unmapped — e.g.
        // VMMDLL_MemRead returns FALSE for a fully-unmapped read (total == 0),
        // matching MemProcFS semantics. The CONTIGUOUS zero-filled image view
        // (for `cat /mem/phys.raw`, dd, HxD) is layered on top in
        // PhysRawStream, which zero-fills gaps and returns the full length.
        return total;
    }

private:
    void load_chunks() {
        u64 file_size = src_->size();
        u64 off = 0;
        while (off + sizeof(AvmlChunkHeader) <= file_size) {
            AvmlChunkHeader h{};
            if (src_->read(off, &h, sizeof(h)) != sizeof(h))
                throw_error("AVML: short read at {:#x}", off);
            if (h.magic != kAvmlMagic)
                throw_error("AVML: bad magic at chunk offset {:#x}", off);
            if (h.version != 2)
                throw_error("AVML: unsupported version {} at {:#x}", h.version, off);
            if (h.end <= h.start)
                throw_error("AVML: bad chunk range {:#x}-{:#x}", h.start, h.end);

            u64 chunk_decompressed_len = h.end - h.start;
            u64 chunk_data_off  = off + sizeof(AvmlChunkHeader);
            u64 chunk_data_max  = file_size - chunk_data_off;
            u64 consumed = parse_snappy_frames(
                chunk_data_off, chunk_data_max, chunk_decompressed_len, h.start);
            off = chunk_data_off + consumed + 8; // skip 8-byte trailer
        }
        if (frames_.empty()) throw_error("AVML: no frames decoded");
        max_addr_ = frames_.back().pa_start + frames_.back().pa_length;
        log::info("AVML: {} chunk-frames, max PA = {:#x}", frames_.size(), max_addr_);
    }

    // Walks the framed-snappy stream starting at `file_off`, producing frames
    // whose decompressed bytes map to physical addresses [chunk_pa_start, ...].
    // Returns the number of compressed bytes consumed from the file.
    u64 parse_snappy_frames(u64 file_off, u64 max_consumable,
                            u64 expected_decompressed, PAddr chunk_pa_start)
    {
        u64 consumed = 0;
        u64 decompressed = 0;
        while (decompressed < expected_decompressed && consumed + 4 <= max_consumable) {
            u32 fh = 0;
            if (src_->read(file_off + consumed, &fh, 4) != 4)
                throw_error("AVML: short read at frame header");
            u32 ftype = fh & 0xFF;
            u32 fsize = fh >> 8;
            u64 payload_off = file_off + consumed + 4;
            if (consumed + 4 + fsize > max_consumable)
                throw_error("AVML: frame at {:#x} runs past chunk end", payload_off);

            if (ftype == 0xFF) {
                // Stream identifier; payload "sNaPpY".
                char tag[6] = {};
                src_->read(payload_off, tag, std::min<u32>(fsize, 6));
                if (std::memcmp(tag, "sNaPpY", 6) != 0)
                    throw_error("AVML: missing sNaPpY tag at {:#x}", payload_off);
            } else if (ftype == 0x00 || ftype == 0x01) {
                // 4-byte CRC then data
                if (fsize < 4) throw_error("AVML: tiny frame at {:#x}", payload_off);
                u64 data_off = payload_off + 4;
                u32 data_sz  = fsize - 4;

                u64 dec_len = 0;
                if (ftype == 0x00) {
                    std::vector<u8> buf(data_sz);
                    src_->read(data_off, buf.data(), buf.size());
                    std::size_t ulen = 0;
                    if (!snappy::GetUncompressedLength(
                            reinterpret_cast<const char*>(buf.data()), buf.size(), &ulen))
                        throw_error("AVML: bad snappy frame at {:#x}", data_off);
                    dec_len = ulen;
                } else {
                    dec_len = data_sz;
                }

                // Reject a frame claiming an implausible decompressed size.
                // This is the real DoS guard: it bounds the per-frame buffer in
                // FrameCache::get so a tiny crafted payload can't claim a
                // multi-GB output ("snappy bomb"). We deliberately do NOT clamp
                // to (expected_decompressed - decompressed): a valid AVML last
                // frame can legitimately overshoot the chunk's declared range.
                if (dec_len > kMaxFrameDecompressed)
                    throw_error("AVML: frame at {:#x} claims implausible "
                                "decompressed size {}", data_off, dec_len);

                AvmlFrame f{};
                f.pa_start      = chunk_pa_start + decompressed;
                f.pa_length     = dec_len;
                f.file_offset   = data_off;
                f.payload_size  = data_sz;
                f.compressed    = (ftype == 0x00);
                frames_.push_back(f);
                decompressed += dec_len;
            } else if (ftype >= 0x02 && ftype < 0x80) {
                throw_error("AVML: unskippable snappy chunk type {:#x}", ftype);
            } // 0x80-0xFE = skippable, just skip

            consumed += 4 + fsize;
        }
        return consumed;
    }

    std::unique_ptr<MemorySource> src_;
    std::vector<AvmlFrame>        frames_;
    mutable FrameCache            cache_;
    PAddr                         max_addr_ = 0;
    std::string                   fmt_, name_;
};

} // anonymous

std::unique_ptr<PhysicalLayer> open_avml_physical(std::unique_ptr<MemorySource> src) {
    return std::make_unique<AvmlPhysical>(std::move(src));
}

} // namespace lmpfs
