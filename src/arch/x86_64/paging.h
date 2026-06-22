#pragma once
#include "core/types.h"
#include "formats/physical_layer.h"
#include <optional>

namespace lmpfs::x86_64 {

// 4-level page tables (PML4 -> PDPT -> PD -> PT) with PSE huge-page support.
class PageTable {
public:
    PageTable(const PhysicalLayer& phys, PAddr dtb) : phys_(phys), dtb_(dtb) {}

    // Translate a virtual address to physical. Returns nullopt for unmapped.
    std::optional<PAddr> translate(VAddr va) const;

    // Read len bytes of virtual memory into out. Returns bytes actually read
    // (holes/unmapped ranges are zero-filled and NOT counted, mirroring our
    // PhysicalLayer::read contract on success-with-holes).
    std::size_t read(VAddr va, void* out, std::size_t len) const;

    template <typename T>
    bool read_pod(VAddr va, T& v) const {
        static_assert(std::is_trivially_copyable_v<T>);
        return read(va, &v, sizeof(T)) == sizeof(T);
    }

    PAddr dtb() const { return dtb_; }

private:
    const PhysicalLayer& phys_;
    PAddr                dtb_;
};

} // namespace lmpfs::x86_64
