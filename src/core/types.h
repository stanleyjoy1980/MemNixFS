#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace lmpfs {

using u8  = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using i32 = std::int32_t;
using i64 = std::int64_t;

using PAddr = u64; // physical address
using VAddr = u64; // virtual address (kernel or user)
using ByteBuf = std::vector<u8>;

constexpr u64 kPageSize  = 0x1000;
constexpr u64 kPageMask  = ~(kPageSize - 1);
constexpr u64 kPageShift = 12;

inline PAddr page_align_down(u64 a) { return a & kPageMask; }
inline PAddr page_align_up  (u64 a) { return (a + kPageSize - 1) & kPageMask; }

} // namespace lmpfs
