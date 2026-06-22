#include "formats/format_factory.h"
#include "core/error.h"
#include "core/log.h"
#include <cstring>

namespace lmpfs {

namespace {
constexpr u32 kLimeMagic = 0x4C694D45; // "LiME"
constexpr u32 kAvmlMagic = 0x4C4D5641; // "AVML"
constexpr u32 kElfMagic  = 0x464C457F; // "\x7fELF" little-endian u32
} // anonymous

std::unique_ptr<PhysicalLayer> open_physical_layer(std::unique_ptr<MemorySource> src) {
    u32 magic = 0;
    src->read(0, &magic, sizeof(magic));
    if (magic == kAvmlMagic) {
        log::note("Format: AVML (Microsoft Azure Memory Loader)");
        return open_avml_physical(std::move(src));
    }
    if (magic == kLimeMagic) {
        log::note("Format: LiME");
        return open_lime_physical(std::move(src));
    }
    if (magic == kElfMagic) {
        // ELF magic — likely a kdump-format dump (ELF64 ET_CORE). The
        // kdump factory validates ET_CORE / ELF64 / x86_64 before
        // committing; on mismatch we'd want to fall back, but currently
        // we just propagate the error (no other ELF flavour is a memory
        // dump in our world). If you hit this with a non-kdump ELF, the
        // error message will tell you which check failed.
        log::note("Format: ELF (probable kdump ET_CORE)");
        return open_kdump_physical(std::move(src));
    }
    log::note("Format: raw (no recognized header at offset 0)");
    return open_raw_physical(std::move(src));
}

} // namespace lmpfs
