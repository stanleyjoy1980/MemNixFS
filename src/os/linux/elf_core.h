#pragma once
#include "core/types.h"
#include "formats/physical_layer.h"
#include "arch/x86_64/paging.h"
#include "os/linux/vma.h"
#include "os/linux/process.h"
#include <vector>

namespace lmpfs::linux {

// Default cap on per-process dump size. Building the full core blocks the
// WinFsp dispatcher thread, so we keep it modest until streaming reads land.
// Default cap on per-process ELF core size. The first read blocks for the
// duration of the build (no streaming yet), so values above a few hundred MB
// risk WinFsp IRP timeout. 256 MiB lets most user processes round-trip in
// 1–3 seconds while still capturing the heap and major shared libraries.
constexpr u64 kDefaultElfCoreMaxBytes = 256ULL * 1024 * 1024;

// Build an ELF64 core dump for the given process by walking its VMAs through
// the user PGD. Unmapped pages within readable VMAs are zero-filled.
// Returns the full file contents as bytes.
ByteBuf build_elf_core(const PhysicalLayer&     phys,
                      const x86_64::PageTable& user_pt,
                      const Process&           p,
                      const std::vector<Vma>&  vmas,
                      u64                      max_bytes = kDefaultElfCoreMaxBytes);

// Estimate the ELF core dump size *without* reading process memory.
// Cheap: just walks VMA metadata.
u64 estimate_elf_core_size(const std::vector<Vma>& vmas,
                           u64                     max_bytes = kDefaultElfCoreMaxBytes);

} // namespace lmpfs::linux
