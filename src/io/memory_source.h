#pragma once
#include "core/types.h"
#include <filesystem>
#include <memory>

namespace lmpfs {

// Abstracts the byte storage backing a memory dump.
// For now it's only file-backed, but this lets us swap in mmap, http, etc.
class MemorySource {
public:
    virtual ~MemorySource() = default;

    // Total size in bytes (the file size).
    virtual u64 size() const = 0;

    // Read [offset, offset+len) into out. Returns bytes actually read.
    // Throws on I/O error. If len > size()-offset, returns fewer bytes.
    virtual std::size_t read(u64 offset, void* out, std::size_t len) const = 0;

    // Friendly name for diagnostics.
    virtual const std::string& name() const = 0;
};

std::unique_ptr<MemorySource> open_file_memory_source(const std::filesystem::path& p);

// Try to memory-map the file; returns nullptr (no exception) if mmap isn't
// possible (e.g. file too large for VA, network filesystem refusing maps).
// Caller should fall back to open_file_memory_source().
std::unique_ptr<MemorySource> try_open_mmap_memory_source(const std::filesystem::path& p);

// Try mmap first; on failure, fall back to file-based source. Use this from
// the engine — it gets the fast path for free.
inline std::unique_ptr<MemorySource> open_best_memory_source(const std::filesystem::path& p) {
    if (auto m = try_open_mmap_memory_source(p)) return m;
    return open_file_memory_source(p);
}

} // namespace lmpfs
