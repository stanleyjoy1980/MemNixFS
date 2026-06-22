#include "io/memory_source.h"
#include "core/error.h"
#include "core/log.h"
#include <cstdio>
#include <mutex>

#ifdef _WIN32
#  define LMPFS_FOPEN64(p) ::_wfopen(p.wstring().c_str(), L"rb")
#  define LMPFS_FSEEK64    ::_fseeki64
#  define LMPFS_FTELL64    ::_ftelli64
#else
#  define LMPFS_FOPEN64(p) ::fopen(p.string().c_str(), "rb")
#  define LMPFS_FSEEK64    ::fseeko
#  define LMPFS_FTELL64    ::ftello
#endif

namespace lmpfs {
namespace {

class FileMemorySource : public MemorySource {
public:
    explicit FileMemorySource(const std::filesystem::path& p)
        : name_(p.string())
    {
        fp_ = LMPFS_FOPEN64(p);
        if (!fp_) throw_error("Cannot open dump file: {}", p.string());
        LMPFS_FSEEK64(fp_, 0, SEEK_END);
        size_ = static_cast<u64>(LMPFS_FTELL64(fp_));
        LMPFS_FSEEK64(fp_, 0, SEEK_SET);
        log::debug("Opened dump source '{}' ({} bytes)", name_, size_);
    }
    ~FileMemorySource() override { if (fp_) std::fclose(fp_); }

    u64 size() const override { return size_; }
    const std::string& name() const override { return name_; }

    std::size_t read(u64 offset, void* out, std::size_t len) const override {
        if (offset >= size_) return 0;
        // Overflow-safe clamp (offset < size_ guaranteed above, so the
        // subtraction can't underflow); `offset + len` could wrap for huge len.
        if (len > size_ - offset) len = static_cast<std::size_t>(size_ - offset);
        std::lock_guard<std::mutex> lk(mu_);
        if (LMPFS_FSEEK64(fp_, static_cast<i64>(offset), SEEK_SET) != 0)
            throw_error("seek({}) failed in {}", offset, name_);
        std::size_t got = std::fread(out, 1, len, fp_);
        if (got != len && std::ferror(fp_))
            throw_error("read({},{}) failed in {}", offset, len, name_);
        return got;
    }

private:
    std::FILE*  fp_   = nullptr;
    u64         size_ = 0;
    std::string name_;
    mutable std::mutex mu_;
};

} // anonymous

std::unique_ptr<MemorySource> open_file_memory_source(const std::filesystem::path& p) {
    return std::make_unique<FileMemorySource>(p);
}

} // namespace lmpfs
