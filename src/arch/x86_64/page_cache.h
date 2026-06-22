// page_cache.h — LRU of decoded 4 KiB pages from a process's PGD.
//
// Why: WinFsp dispatches many parallel small reads against proc.dmp; the same
// 4 KiB user page often gets hit repeatedly (think Notepad++ scrolling). Each
// hit otherwise pays for:
//   1) one PML4 walk (4 phys reads per VA: PML4 -> PDPT -> PD -> PT),
//   2) AVML/LiME segment lookup + Snappy decompression (~tens of µs per page).
// With this cache, repeated reads of recently-seen pages are pure memcpy.
//
// The cache is keyed by (pgd_pa, page_va_aligned). Sized in bytes (default
// 64 MiB → ~16384 pages). Pages we couldn't translate (unmapped) are cached
// as a sentinel so we don't re-walk for them either.
//
// Thread safety: a single mutex guards both the LRU list and the map. WinFsp
// dispatcher threads typically request disjoint ranges, so contention is
// minimal. (If it becomes a bottleneck we can shard.)
//
#pragma once
#include "core/types.h"
#include "arch/x86_64/paging.h"
#include "formats/physical_layer.h"
#include <array>
#include <cstdint>
#include <list>
#include <memory>
#include <mutex>
#include <unordered_map>

namespace lmpfs::x86_64 {

class UserPageCache {
public:
    explicit UserPageCache(std::size_t max_bytes = 64 * 1024 * 1024)
        : max_bytes_(max_bytes) {}

    // Reads `len` bytes at `va` through `pt`. Returns bytes written; holes
    // are zero-filled (and counted). Uses the cache where possible.
    std::size_t read(const PageTable& pt, VAddr va, void* out, std::size_t len);

private:
    struct Page {
        bool mapped = false;
        std::array<u8, 4096> bytes{};
    };
    struct Entry {
        std::list<u64>::iterator lru_it;
        std::shared_ptr<Page>    page;
    };

    static u64 key(PAddr pgd, VAddr page_va) {
        // 52-bit PA + 48-bit VA: fold into a 64-bit hash key.
        return (pgd >> 12) ^ ((va_bits(page_va) >> 12) * 0x9E3779B97F4A7C15ULL);
    }
    static u64 va_bits(VAddr v) { return v & 0x0000FFFFFFFFFFFFULL; }

    std::shared_ptr<Page> fetch(const PageTable& pt, VAddr page_va);
    void evict_locked();

    std::size_t                                  max_bytes_;
    std::size_t                                  cur_bytes_ = 0;
    std::mutex                                   mu_;
    std::list<u64>                               lru_;
    std::unordered_map<u64, Entry>               map_;
};

} // namespace lmpfs::x86_64
