// page_cache.cpp — see header for design notes.
#include "arch/x86_64/page_cache.h"
#include <algorithm>
#include <cstring>

namespace lmpfs::x86_64 {

std::shared_ptr<UserPageCache::Page>
UserPageCache::fetch(const PageTable& pt, VAddr page_va) {
    const u64 k = key(pt.dtb(), page_va);
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = map_.find(k);
        if (it != map_.end()) {
            // Promote in LRU.
            lru_.splice(lru_.begin(), lru_, it->second.lru_it);
            return it->second.page;
        }
    }

    // Walk + decode (lock released; this is the expensive part).
    auto page = std::make_shared<Page>();
    auto pa = pt.translate(page_va);
    if (pa) {
        page->mapped = true;
        // PageTable doesn't expose phys directly; replay via read().
        pt.read(page_va, page->bytes.data(), 4096);
    }

    // Insert + evict.
    std::lock_guard<std::mutex> lk(mu_);
    auto it2 = map_.find(k);
    if (it2 != map_.end()) {
        // Race: someone else inserted while we were decoding. Drop ours.
        lru_.splice(lru_.begin(), lru_, it2->second.lru_it);
        return it2->second.page;
    }
    lru_.push_front(k);
    Entry e{ lru_.begin(), std::move(page) };
    auto [ins, _] = map_.emplace(k, std::move(e));
    cur_bytes_ += sizeof(Page);
    evict_locked();
    return ins->second.page;
}

void UserPageCache::evict_locked() {
    while (cur_bytes_ > max_bytes_ && !lru_.empty()) {
        const u64 victim = lru_.back();
        lru_.pop_back();
        auto it = map_.find(victim);
        if (it != map_.end()) {
            cur_bytes_ -= sizeof(Page);
            map_.erase(it);
        }
    }
}

std::size_t UserPageCache::read(const PageTable& pt, VAddr va, void* out_v, std::size_t len) {
    u8* out = static_cast<u8*>(out_v);
    std::memset(out, 0, len);
    std::size_t total = 0;
    while (len > 0) {
        const VAddr page_va  = va & ~u64(0xFFF);
        const u64   page_off = va & 0xFFF;
        const std::size_t chunk =
            std::min<std::size_t>(len, static_cast<std::size_t>(0x1000 - page_off));
        auto page = fetch(pt, page_va);
        if (page->mapped) {
            std::memcpy(out, page->bytes.data() + page_off, chunk);
            total += chunk;
        }
        out += chunk; va += chunk; len -= chunk;
    }
    return total;
}

} // namespace lmpfs::x86_64
