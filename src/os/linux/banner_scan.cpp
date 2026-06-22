// banner_scan.cpp — see header.
#include "os/linux/banner_scan.h"
#include "core/log.h"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <unordered_map>
#include <vector>

namespace lmpfs::linux {
namespace {

bool contains_ci(const std::string& s, const char* needle) {
    std::string lo = s;
    std::transform(lo.begin(), lo.end(), lo.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return lo.find(needle) != std::string::npos;
}

bool looks_like_kernel_release(const std::string& release) {
    if (release.size() < 3) return false;
    if (!std::isdigit(static_cast<unsigned char>(release[0]))) return false;

    bool saw_dot = false;
    bool saw_digit_after_dot = false;
    for (std::size_t i = 0; i < release.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(release[i]);
        if (std::isdigit(c)) {
            if (saw_dot) saw_digit_after_dot = true;
            continue;
        }
        if (release[i] == '.') {
            saw_dot = true;
            continue;
        }
        if (std::isalpha(c) || release[i] == '-' || release[i] == '_' ||
            release[i] == '+' || release[i] == '~') {
            continue;
        }
        return false;
    }
    return saw_dot && saw_digit_after_dot;
}

int score_banner(const std::string& banner, const std::string& release,
                 int release_count) {
    if (release.empty() || !looks_like_kernel_release(release)) return -1000;
    if (banner.find('%') != std::string::npos) return -1000;
    if (contains_ci(banner, "linux version of ")) return -1000;
    if (contains_ci(banner, "linux version wasn't tested")) return -1000;
    if (contains_ci(banner, "linux version is unaffected")) return -1000;

    int score = 100;
    score += std::min<int>(release_count, 8) * 20;
    score += std::min<int>(static_cast<int>(banner.size()), 220) / 8;
    if (banner.find(" #") != std::string::npos) score += 20;
    if (contains_ci(banner, "smp")) score += 10;
    if (contains_ci(banner, "preempt")) score += 10;
    if (contains_ci(banner, "gcc")) score += 8;
    if (contains_ci(banner, "gnu ld")) score += 4;
    if (contains_ci(banner, "kali") || contains_ci(banner, "ubuntu") ||
        contains_ci(banner, "debian") || contains_ci(banner, "fedora") ||
        contains_ci(banner, "red hat") || contains_ci(banner, "arch")) {
        score += 8;
    }
    return score;
}

std::string read_banner_at(const PhysicalLayer& phys, PAddr pa) {
    std::vector<u8> str(512);
    std::size_t got = phys.read(pa, str.data(), str.size());
    std::size_t n = 0;
    while (n < got && str[n] != 0 && str[n] != '\n' && str[n] != '\r') ++n;
    return std::string(reinterpret_cast<char*>(str.data()), n);
}

} // anonymous

std::vector<BannerCandidate> scan_banner_candidates(const PhysicalLayer& phys) {
    constexpr std::size_t kChunk = 4 * 1024 * 1024;
    std::vector<u8>       buf(kChunk + 32);
    const char* needle = "Linux version ";
    const std::size_t    nlen = std::strlen(needle);

    std::vector<BannerCandidate> out;
    std::unordered_map<std::string, int> release_counts;
    PAddr pa = 0;
    const PAddr maxa = phys.max_address();
    while (pa < maxa) {
        std::size_t want = std::min<u64>(kChunk + 32, maxa - pa);
        std::size_t got  = phys.read(pa, buf.data(), want);
        if (got < nlen) { pa += kChunk; continue; }
        for (std::size_t i = 0; i + nlen <= got; ++i) {
            if (std::memcmp(buf.data() + i, needle, nlen) != 0) continue;
            BannerCandidate cand;
            cand.pa = pa + i;
            cand.banner = read_banner_at(phys, cand.pa);
            cand.release = parse_kernel_release(cand.banner);
            if (!cand.release.empty()) ++release_counts[cand.release];
            out.push_back(std::move(cand));
        }
        pa += kChunk;
    }
    for (auto& cand : out) {
        int count = 0;
        if (auto it = release_counts.find(cand.release); it != release_counts.end())
            count = it->second;
        cand.score = score_banner(cand.banner, cand.release, count);
    }
    return out;
}

std::string select_canonical_banner(const std::vector<std::string>& banners) {
    std::unordered_map<std::string, int> release_counts;
    std::vector<BannerCandidate> cands;
    cands.reserve(banners.size());
    for (const auto& banner : banners) {
        BannerCandidate cand;
        cand.banner = banner;
        cand.release = parse_kernel_release(banner);
        if (!cand.release.empty()) ++release_counts[cand.release];
        cands.push_back(std::move(cand));
    }
    const BannerCandidate* best = nullptr;
    for (auto& cand : cands) {
        int count = 0;
        if (auto it = release_counts.find(cand.release); it != release_counts.end())
            count = it->second;
        cand.score = score_banner(cand.banner, cand.release, count);
        if (cand.score < 0) continue;
        if (!best || cand.score > best->score ||
            (cand.score == best->score && cand.banner.size() > best->banner.size())) {
            best = &cand;
        }
    }
    return best ? best->banner : std::string{};
}

std::string find_banner_in_dump(const PhysicalLayer& phys) {
    auto cands = scan_banner_candidates(phys);
    const BannerCandidate* best = nullptr;
    for (const auto& cand : cands) {
        if (cand.score < 0) continue;
        if (!best || cand.score > best->score ||
            (cand.score == best->score && cand.banner.size() > best->banner.size())) {
            best = &cand;
        }
    }
    if (best) {
        log::debug("banner_scan: selected '{}' (score={}, {} candidates)",
                   best->banner.substr(0, std::min<std::size_t>(80, best->banner.size())),
                   best->score, cands.size());
        return best->banner;
    }
    log::debug("banner_scan: no canonical banner among {} candidates", cands.size());
    return {};
}

std::string parse_kernel_release(const std::string& banner) {
    // Format: "Linux version 6.14.0-36-generic (...) (...) #...  ..."
    constexpr const char* prefix = "Linux version ";
    auto p = banner.find(prefix);
    if (p == std::string::npos) return {};
    p += std::strlen(prefix);
    auto e = banner.find(' ', p);
    if (e == std::string::npos) return {};
    return banner.substr(p, e - p);
}

std::string parse_distro(const std::string& banner) {
    // Ubuntu banners contain "Ubuntu" or "ubuntu" in build info, plus
    //   "(buildd@..."   for official ubuntu builds.
    // Debian banners say "(Debian X.Y.Z-N) ".
    // RHEL banners say  "(Red Hat ...)" or include "el8"/"el9" in the release.
    // Arch banners say  "(Arch Linux)" or include "-arch" in the release.
    auto contains_ci = [&banner](const char* s) {
        std::string lo = banner;
        std::transform(lo.begin(), lo.end(), lo.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        return lo.find(s) != std::string::npos;
    };
    if (contains_ci("ubuntu") || contains_ci("buildd@"))    return "ubuntu";
    if (contains_ci("debian"))                              return "debian";
    if (contains_ci("red hat") || contains_ci("centos")
        || contains_ci("rocky") || contains_ci("alma"))     return "rhel";
    if (contains_ci("arch"))                                return "arch";
    return "unknown";
}

} // namespace lmpfs::linux
