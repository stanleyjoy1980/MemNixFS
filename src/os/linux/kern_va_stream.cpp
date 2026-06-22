// kern_va_stream.cpp — see header.
#include "os/linux/kern_va_stream.h"
#include "os/linux/kva_reader.h"
#include "app/engine.h"
#include <algorithm>
#include <cstring>

namespace lmpfs::linux {

std::size_t KernVaRawStream::read(u64 offset, void* out, std::size_t len) {
    u8* p = static_cast<u8*>(out);

    // Reads past the file end → pure zeros (sparse-file POSIX semantics; also
    // what /mem/phys.raw does via PhysicalLayer).
    if (offset >= kSpan) {
        std::memset(p, 0, len);
        return len;
    }
    if (offset + len > kSpan) {
        // Clamp + tail-zero so the caller sees exactly `len` bytes.
        std::size_t clamped = static_cast<std::size_t>(kSpan - offset);
        if (clamped < len) std::memset(p + clamped, 0, len - clamped);
        len = clamped;
    }

    // Pre-zero the whole buffer so any 4-KiB page that fails to resolve is
    // already correctly zero-filled — keeps the per-page logic branch-free
    // for the success path.
    std::memset(p, 0, len);

    constexpr u64 kPage = 4096;
    u64 done = 0;
    while (done < len) {
        VAddr va = kBase + offset + done;
        u64 page_off = va & (kPage - 1);
        std::size_t chunk = static_cast<std::size_t>(
            std::min<u64>(kPage - page_off, len - done));
        // Best-effort: failure leaves the pre-zeroed bytes in place.
        // kva_read is all-or-nothing per call, so we honor that per-page.
        (void)kva_read(eng_, va, p + done, chunk);
        done += chunk;
    }
    return len;
}

} // namespace lmpfs::linux
