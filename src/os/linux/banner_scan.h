// banner_scan.h — find the canonical Linux banner in a dump WITHOUT needing
// an ISF symbol table. The dump always contains "Linux version <release> ..."
// near the top of the kernel image, so a plain physical-memory scan suffices
// to identify which kernel built it.
//
// Used by the symbol-resolution pipeline so we can pick (or auto-fetch) the
// matching ISF without any user input.
//
#pragma once
#include "core/types.h"
#include "formats/physical_layer.h"
#include <string>
#include <vector>

namespace lmpfs::linux {

struct BannerCandidate {
    PAddr       pa = 0;
    std::string banner;
    std::string release;
    int         score = 0;
};

// Scans `phys` for every "Linux version " string and scores each candidate.
// Invalid/template strings are retained in the returned vector with a negative
// score so callers can diagnose them without using them for symbol selection.
std::vector<BannerCandidate> scan_banner_candidates(const PhysicalLayer& phys);

// Selects the best canonical kernel banner from already-read candidates.
// Returns empty string when no kernel-looking candidate is present.
std::string select_canonical_banner(const std::vector<std::string>& banners);

// Scans `phys` for "Linux version " and returns the selected canonical banner.
std::string find_banner_in_dump(const PhysicalLayer& phys);

// Pulls the kernel release out of a banner like
//   "Linux version 6.14.0-36-generic (buildd@...) (gcc ...) ..."
// → "6.14.0-36-generic"
// Returns empty string if not parseable.
std::string parse_kernel_release(const std::string& banner);

// Heuristic distro detection from the banner. Returns "ubuntu", "debian",
// "rhel", "arch", "unknown".
std::string parse_distro(const std::string& banner);

} // namespace lmpfs::linux
