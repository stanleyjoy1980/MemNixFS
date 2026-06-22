#include "arch/x86_64/paging.h"
#include "core/log.h"
#include <algorithm>
#include <cstring>

namespace lmpfs::x86_64 {

namespace {
constexpr u64 kPresent  = 1ULL << 0;
constexpr u64 kPSBit    = 1ULL << 7;        // PS bit: PDPT=1GB, PD=2MB
constexpr u64 kAddrMask = 0x000ffffffffff000ULL;
constexpr u64 kAddr2MB  = 0x000fffffffe00000ULL;
constexpr u64 kAddr1GB  = 0x000fffffc0000000ULL;

inline u64 idx(VAddr va, int shift) { return (va >> shift) & 0x1FF; }
} // anonymous

std::optional<PAddr> PageTable::translate(VAddr va) const {
    u64 e = 0;

    // PML4
    PAddr pml4e_pa = dtb_ + idx(va, 39) * 8;
    if (!phys_.read_pod(pml4e_pa, e) || !(e & kPresent)) return std::nullopt;

    // PDPT
    PAddr pdpte_pa = (e & kAddrMask) + idx(va, 30) * 8;
    if (!phys_.read_pod(pdpte_pa, e) || !(e & kPresent)) return std::nullopt;
    if (e & kPSBit) {
        return (e & kAddr1GB) | (va & 0x3FFFFFFFULL);
    }

    // PD
    PAddr pde_pa = (e & kAddrMask) + idx(va, 21) * 8;
    if (!phys_.read_pod(pde_pa, e) || !(e & kPresent)) return std::nullopt;
    if (e & kPSBit) {
        return (e & kAddr2MB) | (va & 0x1FFFFFULL);
    }

    // PT
    PAddr pte_pa = (e & kAddrMask) + idx(va, 12) * 8;
    if (!phys_.read_pod(pte_pa, e) || !(e & kPresent)) return std::nullopt;
    return (e & kAddrMask) | (va & 0xFFFULL);
}

std::size_t PageTable::read(VAddr va, void* out, std::size_t len) const {
    u8* dst = static_cast<u8*>(out);
    std::memset(dst, 0, len);
    std::size_t total = 0;
    while (len > 0) {
        u64 page_off = va & (kPageSize - 1);
        u64 page     = va & kPageMask;
        auto pa_opt  = translate(page);
        std::size_t chunk = std::min<std::size_t>(len, static_cast<std::size_t>(kPageSize - page_off));
        if (pa_opt) {
            std::size_t got = phys_.read(*pa_opt + page_off, dst, chunk);
            total += got;
        }
        dst += chunk; va += chunk; len -= chunk;
    }
    return total;
}

} // namespace lmpfs::x86_64
