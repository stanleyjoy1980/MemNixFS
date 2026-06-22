// mmap_memory_source.cpp — Windows MapViewOfFile-backed MemorySource.
//
// Why: AVML and similar formats issue many small reads of compressed frames
// scattered across the dump file. `fread`/`fseek` round-trips the kernel and
// flushes the file pointer; a memory-mapped view turns each read into a plain
// `memcpy` from the OS page cache (page-fault on first touch, ~free after).
//
// We map the entire file when possible (single VirtualAlloc reservation up to
// the host's process address space — ~128 TiB on x64). If mmap fails (out of
// VA, FS doesn't support, etc.) the caller falls back to FileMemorySource.
//
// References:
//   MemProcFS: leechcore device backends use Win32 mmap for the same reason.
//
#include "io/memory_source.h"
#include "core/error.h"
#include "core/log.h"

#ifdef _WIN32
#  include <windows.h>
#endif

#include <cstring>
#include <filesystem>

namespace lmpfs {

#ifdef _WIN32
namespace {

class MmapMemorySource : public MemorySource {
public:
    explicit MmapMemorySource(const std::filesystem::path& p) : name_(p.string()) {
        file_ = CreateFileW(p.wstring().c_str(),
                            GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            nullptr, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                            nullptr);
        if (file_ == INVALID_HANDLE_VALUE)
            throw_error("MmapMemorySource: CreateFile failed on '{}'", name_);

        LARGE_INTEGER sz{};
        if (!GetFileSizeEx(file_, &sz)) {
            CloseHandle(file_);
            throw_error("MmapMemorySource: GetFileSizeEx failed");
        }
        size_ = static_cast<u64>(sz.QuadPart);
        if (size_ == 0) {
            CloseHandle(file_);
            throw_error("MmapMemorySource: zero-byte file '{}'", name_);
        }

        mapping_ = CreateFileMappingW(file_, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!mapping_) {
            CloseHandle(file_);
            throw_error("MmapMemorySource: CreateFileMapping failed (size={})", size_);
        }

        view_ = MapViewOfFile(mapping_, FILE_MAP_READ, 0, 0, 0);
        if (!view_) {
            CloseHandle(mapping_);
            CloseHandle(file_);
            throw_error("MmapMemorySource: MapViewOfFile failed (size={})", size_);
        }

        log::info("Mapped '{}' ({} bytes) into process address space at {}",
                  name_, size_, view_);
    }

    ~MmapMemorySource() override {
        if (view_)    UnmapViewOfFile(view_);
        if (mapping_) CloseHandle(mapping_);
        if (file_ != INVALID_HANDLE_VALUE) CloseHandle(file_);
    }

    u64 size() const override { return size_; }
    const std::string& name() const override { return name_; }

    std::size_t read(u64 offset, void* out, std::size_t len) const override {
        if (offset >= size_) return 0;
        // Overflow-safe clamp: `offset + len` can wrap for a huge len and skip
        // the bound, letting memcpy read past the mapped view (OOB). offset <
        // size_ here, so `size_ - offset` is always a safe positive bound.
        if (len > size_ - offset) len = static_cast<std::size_t>(size_ - offset);
        // Page-fault on demand; OS prefetcher handles streaming patterns.
        std::memcpy(out, static_cast<const u8*>(view_) + offset, len);
        return len;
    }

private:
    std::string name_;
    HANDLE      file_    = INVALID_HANDLE_VALUE;
    HANDLE      mapping_ = nullptr;
    void*       view_    = nullptr;
    u64         size_    = 0;
};

} // anonymous

std::unique_ptr<MemorySource> try_open_mmap_memory_source(const std::filesystem::path& p) {
    try {
        return std::make_unique<MmapMemorySource>(p);
    } catch (const std::exception& e) {
        log::warn("mmap source failed ({}); falling back to file source", e.what());
        return nullptr;
    }
}

#else // _WIN32

std::unique_ptr<MemorySource> try_open_mmap_memory_source(const std::filesystem::path&) {
    // POSIX builds fall back to the buffered FileMemorySource (returning
    // nullptr selects it). A mmap(2)-backed source could be added here if
    // profiling shows the read path is I/O-bound on Linux.
    return nullptr;
}

#endif // _WIN32

} // namespace lmpfs
