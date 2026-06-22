// btf_probe.cpp — see header.
#include "os/linux/btf_probe.h"
#include "core/log.h"
#include <algorithm>
#include <cstring>
#include <vector>

namespace lmpfs::linux {

namespace {

#pragma pack(push, 1)
struct BtfHeader {
    u16 magic;        // 0xEB9F
    u8  version;      // 1
    u8  flags;
    u32 hdr_len;      // typically 24
    u32 type_off;     // offset within blob to type info
    u32 type_len;
    u32 str_off;
    u32 str_len;
};
#pragma pack(pop)
static_assert(sizeof(BtfHeader) == 24, "BtfHeader must be 24 bytes");

constexpr u16 kBtfMagic = 0xEB9F;

// Sanity-check a candidate BTF header read at `pa`. We require:
//   * magic == 0xEB9F
//   * version == 1
//   * type_off + type_len <= str_off + str_len (sections fit)
//   * total size in a sensible kernel range (1 KiB .. 64 MiB)
bool plausible(const BtfHeader& h, u64 dump_max, u64 pa) {
    if (h.magic != kBtfMagic) return false;
    if (h.version != 1)        return false;
    if (h.hdr_len < sizeof(BtfHeader) || h.hdr_len > 256) return false;
    // Widen to u64 — `type_off + type_len` as u32 can wrap and sneak a bogus
    // header past the size gate.
    u64 total = u64(h.hdr_len) + std::max(u64(h.type_off) + h.type_len,
                                          u64(h.str_off)  + h.str_len);
    if (total < 1024 || total > 64ULL * 1024 * 1024)      return false;
    if (pa + total > dump_max)                            return false;
    if (h.type_len == 0 || h.str_len == 0)                return false;
    return true;
}

} // anonymous

std::vector<BtfInfo> probe_btf_all(const PhysicalLayer& phys) {
    constexpr std::size_t kChunk = 4 * 1024 * 1024;
    std::vector<u8>       buf(kChunk + 32);
    std::vector<BtfInfo>  hits;

    PAddr pa = 0;
    const PAddr maxa = phys.max_address();
    while (pa < maxa) {
        std::size_t want = std::min<u64>(kChunk + 32, maxa - pa);
        std::size_t got  = phys.read(pa, buf.data(), want);
        if (got < sizeof(BtfHeader)) { pa += kChunk; continue; }
        for (std::size_t i = 0; i + sizeof(BtfHeader) <= got; ++i) {
            if (buf[i] != 0x9F || buf[i + 1] != 0xEB) continue;
            BtfHeader h;
            std::memcpy(&h, buf.data() + i, sizeof(h));
            if (!plausible(h, maxa, pa + i)) continue;
            BtfInfo info;
            info.offset_pa = pa + i;
            info.size      = u64(h.hdr_len) +
                             std::max(u64(h.type_off) + h.type_len,
                                      u64(h.str_off)  + h.str_len);
            info.version   = (u32(h.version) << 16) | h.flags;
            hits.push_back(info);
        }
        pa += kChunk;
    }

    // Sort by size descending — kernel main BTF is typically the largest.
    std::sort(hits.begin(), hits.end(),
              [](const BtfInfo& a, const BtfInfo& b) { return a.size > b.size; });
    if (!hits.empty()) {
        log::info("BTF scan: {} blob(s) found; largest = {} bytes @ PA {:#x}",
                  hits.size(), hits.front().size, hits.front().offset_pa);
    }
    return hits;
}

std::optional<BtfInfo> probe_btf(const PhysicalLayer& phys) {
    auto all = probe_btf_all(phys);
    if (all.empty()) return std::nullopt;
    return all.front();
}

ByteBuf read_btf(const PhysicalLayer& phys, const BtfInfo& info) {
    ByteBuf b(info.size);
    std::size_t got = phys.read(info.offset_pa, b.data(), b.size());
    if (got < info.size) b.resize(got);
    return b;
}

} // namespace lmpfs::linux
