// symbol_cache_http.h — fetch an ISF from a community symbol mirror by
// banner-hash lookup, without needing local toolchain or distro packages.
//
// Many distro kernels have been seen + indexed by community symbol caches
// (e.g. github.com/Abyss-W4tcher/volatility3-symbols, vol3's own caches).
// Each ISF is published keyed by a hash of the kernel banner string. So we
// can hit a URL like:
//
//   https://<mirror>/banners/<sha256(banner)>.json.xz
//
// download it, validate it (release matches), and cache locally — all without
// any of the distro-specific apt/dnf machinery.
//
// Configurable mirror list via $LMPFS_ISF_MIRRORS (colon-separated), falling
// back to a built-in default. Works on Windows (WinHTTP) and Unix (libcurl /
// wget shell-out).
//
#pragma once
#include "core/types.h"
#include <filesystem>
#include <string>
#include <vector>

namespace lmpfs {

struct HttpFetchResult {
    bool                  ok = false;
    std::filesystem::path path;        // where the downloaded ISF was saved
    std::string           from_url;    // which mirror produced it
    std::string           error;
};

// Compute the banner-keyed cache filename. The exact format is determined by
// what the upstream mirrors use — currently sha256(banner)[:64].
std::string banner_cache_key(const std::string& banner);

// List of mirror URL templates. Each template has "{KEY}" replaced with the
// cache key and "{RELEASE}" with the kernel release. Multiple templates are
// tried in order until one returns 200.
std::vector<std::string> default_isf_mirrors();

// Try to download an ISF from the configured mirrors. Saves to `cache_dir/
// <release>.json.xz` on success. Returns ok=false (with `error` set) on any
// failure (network, 404, validation).
HttpFetchResult fetch_isf_from_mirrors(const std::string&            banner,
                                       const std::string&            release,
                                       const std::filesystem::path&  cache_dir,
                                       const std::vector<std::string>& mirrors);

} // namespace lmpfs
