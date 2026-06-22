#include "symbols/xz_decompress.h"
#include "core/error.h"
#include "core/log.h"
#include <lzma.h>
#include <cstdio>
#include <vector>

namespace lmpfs {

namespace {
ByteBuf read_whole_file(const std::filesystem::path& p) {
#ifdef _WIN32
    std::FILE* fp = ::_wfopen(p.wstring().c_str(), L"rb");
#else
    std::FILE* fp = std::fopen(p.string().c_str(), "rb");
#endif
    if (!fp) throw_error("Cannot open {}", p.string());
    std::fseek(fp, 0, SEEK_END);
    long sz = std::ftell(fp);
    std::fseek(fp, 0, SEEK_SET);
    ByteBuf b(static_cast<std::size_t>(sz));
    std::size_t got = std::fread(b.data(), 1, b.size(), fp);
    std::fclose(fp);
    if (got != b.size()) throw_error("Short read of {}", p.string());
    return b;
}
} // anonymous

ByteBuf xz_decompress(const u8* data, std::size_t len) {
    lzma_stream strm = LZMA_STREAM_INIT;
    if (lzma_stream_decoder(&strm, UINT64_MAX, LZMA_CONCATENATED) != LZMA_OK)
        throw_error("lzma: stream init failed");

    ByteBuf out;
    out.reserve(len * 4);
    constexpr std::size_t kChunk = 256 * 1024;
    std::vector<u8> chunk(kChunk);

    strm.next_in  = data;
    strm.avail_in = len;
    strm.next_out = chunk.data();
    strm.avail_out = chunk.size();

    while (true) {
        lzma_ret ret = lzma_code(&strm, LZMA_FINISH);
        std::size_t produced = chunk.size() - strm.avail_out;
        if (produced) out.insert(out.end(), chunk.begin(), chunk.begin() + produced);
        strm.next_out = chunk.data();
        strm.avail_out = chunk.size();
        if (ret == LZMA_STREAM_END) break;
        if (ret != LZMA_OK) {
            lzma_end(&strm);
            throw_error("lzma: decode error {}", static_cast<int>(ret));
        }
    }
    lzma_end(&strm);
    return out;
}

ByteBuf xz_decompress_file(const std::filesystem::path& p) {
    log::info("Decompressing symbols: {}", p.string());
    auto raw = read_whole_file(p);
    return xz_decompress(raw.data(), raw.size());
}

} // namespace lmpfs
