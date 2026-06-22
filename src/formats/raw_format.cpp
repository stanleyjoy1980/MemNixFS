#include "formats/format_factory.h"
#include "core/error.h"
#include <algorithm>
#include <cstring>

namespace lmpfs {
namespace {

class RawPhysical : public PhysicalLayer {
public:
    explicit RawPhysical(std::unique_ptr<MemorySource> src)
        : src_(std::move(src)), fmt_("raw"), name_(src_->name()) {}

    PAddr max_address() const override { return src_->size(); }
    const std::string& format_name() const override { return fmt_; }
    const std::string& source_name() const override { return name_; }
    std::vector<Range> ranges() const override {
        return src_->size() == 0 ? std::vector<Range>{}
                                 : std::vector<Range>{{0, src_->size()}};
    }

    std::size_t read(PAddr pa, void* out, std::size_t len) const override {
        if (pa >= src_->size()) {
            std::memset(out, 0, len);
            return 0;
        }
        std::size_t want = std::min<u64>(len, src_->size() - pa);
        std::size_t got  = src_->read(pa, out, want);
        if (got < len)
            std::memset(static_cast<u8*>(out) + got, 0, len - got);
        return got;
    }

private:
    std::unique_ptr<MemorySource> src_;
    std::string fmt_, name_;
};

} // anonymous

std::unique_ptr<PhysicalLayer> open_raw_physical(std::unique_ptr<MemorySource> src) {
    return std::make_unique<RawPhysical>(std::move(src));
}

} // namespace lmpfs
