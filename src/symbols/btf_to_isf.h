// btf_to_isf.h — convert a BTF blob (from the kernel's .BTF section, found
// in any dump of a kernel built with CONFIG_DEBUG_INFO_BTF=y) into a
// Volatility-3 ISF JSON file.
//
// This unlocks **true offline symbol generation**: no vmlinux, no apt-get,
// no network. BTF alone carries types but no symbol addresses — so an
// optional `KallsymsResult` may be supplied to fill the `symbols` section
// (extracted by `lmpfs::linux::extract_kallsyms()`). When both are present,
// the resulting ISF is functionally complete: the engine's `init_task`,
// `linux_banner`, `init_top_pgt`, etc. lookups all succeed without an
// external ISF or vmlinux file.
//
// BTF spec: include/uapi/linux/btf.h in the Linux kernel tree.
//
#pragma once
#include "core/types.h"
#include "symbols/kallsyms.h"
#include <filesystem>
#include <optional>
#include <string>

namespace lmpfs {

struct BtfIsfResult {
    bool                  ok = false;
    std::filesystem::path path;          // where the ISF was written
    std::size_t           type_count = 0;
    std::size_t           symbol_count = 0;
    std::size_t           string_table_bytes = 0;
    std::string           error;
};

// Converts `btf_blob` to a Volatility-3-format ISF JSON file at `out_path`.
// The file is written uncompressed if `out_path` ends in .json, else xz-
// compressed if it ends in .json.xz.
//
// If `kallsyms` is non-null AND `kallsyms->relative_base != 0` (i.e. the
// extractor found real addresses, not a names-only degraded result), the
// ISF's `symbols` section is populated from it. Symbols are filtered to
// keep only those with names that look like valid C identifiers (a small
// pass that avoids polluting the ISF with `__pfx_*` and similar build
// artefacts that are noise to consumers).
BtfIsfResult btf_to_isf(const ByteBuf&              btf_blob,
                        const std::string&          kernel_release,
                        const std::filesystem::path& out_path,
                        const linux::KallsymsResult* kallsyms = nullptr);

} // namespace lmpfs
