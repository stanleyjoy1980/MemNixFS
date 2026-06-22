#pragma once
#include "core/types.h"
#include <filesystem>

namespace lmpfs {

// Reads a .xz file from disk and returns the decompressed bytes.
ByteBuf xz_decompress_file(const std::filesystem::path& p);

// Decompress an in-memory xz blob.
ByteBuf xz_decompress(const u8* data, std::size_t len);

} // namespace lmpfs
