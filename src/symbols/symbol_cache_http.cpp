// symbol_cache_http.cpp — see header for design notes.
#include "symbols/symbol_cache_http.h"
#include "symbols/isf_symbols.h"
#include "core/error.h"
#include "core/log.h"
#include <fstream>
#include <cstdio>
#include <iomanip>
#include <sstream>

#ifdef _WIN32
#  include <windows.h>
#  include <winhttp.h>
#  pragma comment(lib, "winhttp.lib")
#endif

// Minimal SHA-256 (public domain implementation). Used only to hash the
// banner string — we don't depend on it for security.
namespace {
struct Sha256 {
    uint32_t h[8] = { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                      0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 };
    uint8_t  buf[64]; std::size_t n = 0; uint64_t tot = 0;
    static uint32_t rotr(uint32_t x, int n) { return (x>>n)|(x<<(32-n)); }
    void block() {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (uint32_t(buf[i*4])<<24)|(uint32_t(buf[i*4+1])<<16)
                 | (uint32_t(buf[i*4+2])<<8)|uint32_t(buf[i*4+3]);
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3);
            uint32_t s1 = rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10);
            w[i] = w[i-16]+s0+w[i-7]+s1;
        }
        static const uint32_t k[64] = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
        };
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rotr(e,6)^rotr(e,11)^rotr(e,25);
            uint32_t ch = (e&f)^((~e)&g);
            uint32_t T1 = hh + S1 + ch + k[i] + w[i];
            uint32_t S0 = rotr(a,2)^rotr(a,13)^rotr(a,22);
            uint32_t mj = (a&b)^(a&c)^(b&c);
            uint32_t T2 = S0 + mj;
            hh = g; g = f; f = e; e = d + T1;
            d = c; c = b; b = a; a = T1 + T2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    void update(const void* p, std::size_t l) {
        const uint8_t* b = static_cast<const uint8_t*>(p);
        tot += l;
        while (l) {
            std::size_t r = std::min<std::size_t>(64 - n, l);
            std::memcpy(buf + n, b, r);
            n += r; b += r; l -= r;
            if (n == 64) { block(); n = 0; }
        }
    }
    std::string hex_final() {
        uint64_t bits = tot * 8;
        uint8_t pad = 0x80; update(&pad, 1);
        while (n != 56) { uint8_t z = 0; update(&z, 1); }
        for (int i = 7; i >= 0; --i) {
            uint8_t b = (bits >> (i * 8)) & 0xff;
            update(&b, 1);
        }
        std::ostringstream os;
        os << std::hex << std::setfill('0');
        for (int i = 0; i < 8; ++i) os << std::setw(8) << h[i];
        return os.str();
    }
};
}

namespace lmpfs {

std::string banner_cache_key(const std::string& banner) {
    Sha256 s; s.update(banner.data(), banner.size());
    return s.hex_final();
}

std::vector<std::string> default_isf_mirrors() {
    if (const char* env = std::getenv("LMPFS_ISF_MIRRORS")) {
        std::vector<std::string> out;
        std::string s = env;
        std::size_t pos = 0;
        while (pos < s.size()) {
            // mirror URLs commonly contain ':' (https://), so split on ';' instead.
            auto nxt = s.find(';', pos);
            out.push_back(s.substr(pos, nxt == std::string::npos ? std::string::npos : nxt - pos));
            if (nxt == std::string::npos) break;
            pos = nxt + 1;
        }
        return out;
    }
    return {
        // Volatility 3 ISFs by banner hash. URL template — {KEY} is the
        // SHA-256 of the banner string.
        "https://raw.githubusercontent.com/Abyss-W4tcher/volatility3-symbols/master/banners/{KEY}.json.xz",
        // Alternative layout (some mirrors split on first 2 hex chars).
        "https://raw.githubusercontent.com/Abyss-W4tcher/volatility3-symbols/master/{KEY:0:2}/{KEY}.json.xz",
    };
}

namespace {

// Expand {KEY} and {KEY:0:2} placeholders in a URL template.
std::string render_template(const std::string& tmpl, const std::string& key) {
    std::string out = tmpl;
    auto replace_all = [&out](const std::string& tok, const std::string& val) {
        std::size_t pos = 0;
        while ((pos = out.find(tok, pos)) != std::string::npos) {
            out.replace(pos, tok.size(), val);
            pos += val.size();
        }
    };
    replace_all("{KEY:0:2}", key.substr(0, 2));
    replace_all("{KEY}",     key);
    return out;
}

#ifdef _WIN32
// Parse an https URL into (host, path). Crude but enough for the mirrors we use.
bool split_https_url(const std::string& url, std::wstring& host, std::wstring& path) {
    const std::string p = "https://";
    if (url.rfind(p, 0) != 0) return false;
    auto slash = url.find('/', p.size());
    std::string h = url.substr(p.size(), slash - p.size());
    std::string a = (slash == std::string::npos) ? "/" : url.substr(slash);
    host.assign(h.begin(), h.end());
    path.assign(a.begin(), a.end());
    return true;
}

// Synchronous WinHTTP GET. Writes response body to `out` on 200; returns
// (http_status, error string).
std::pair<int, std::string>
winhttp_get(const std::string& url, std::vector<uint8_t>& body) {
    std::wstring host, path;
    if (!split_https_url(url, host, path)) return { -1, "bad URL" };

    HINTERNET hSession = WinHttpOpen(L"MemNixFS/0.1",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return { -2, "WinHttpOpen failed" };
    HINTERNET hConn = WinHttpConnect(hSession, host.c_str(),
                                     INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConn) { WinHttpCloseHandle(hSession); return { -3, "WinHttpConnect failed" }; }
    HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", path.c_str(), nullptr,
                                        WINHTTP_NO_REFERER,
                                        WINHTTP_DEFAULT_ACCEPT_TYPES,
                                        WINHTTP_FLAG_SECURE);
    if (!hReq) { WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSession); return { -4, "WinHttpOpenRequest failed" }; }

    BOOL ok = WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                 WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
           && WinHttpReceiveResponse(hReq, nullptr);
    int status = -5;
    std::string err;
    if (ok) {
        DWORD code = 0, sz = sizeof(code);
        WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &code, &sz, WINHTTP_NO_HEADER_INDEX);
        status = static_cast<int>(code);
        if (code == 200 || code == 302 || code == 301) {
            // follow redirect once if needed
            // (WinHttp follows by default; we keep this simple)
            for (;;) {
                DWORD avail = 0;
                if (!WinHttpQueryDataAvailable(hReq, &avail)) break;
                if (avail == 0) break;
                std::vector<uint8_t> chunk(avail);
                DWORD read = 0;
                if (!WinHttpReadData(hReq, chunk.data(), avail, &read)) break;
                body.insert(body.end(), chunk.begin(), chunk.begin() + read);
            }
        }
    } else {
        err = "WinHttpSendRequest/ReceiveResponse failed";
    }
    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);
    WinHttpCloseHandle(hSession);
    return { status, err };
}
#else
// Non-Windows: shell out to curl/wget. Same return contract.
std::pair<int, std::string>
winhttp_get(const std::string& url, std::vector<uint8_t>& body) {
    std::string cmd = "curl -fsSL --max-time 30 -o /dev/stdout " + url;
    FILE* p = popen(cmd.c_str(), "r");
    if (!p) return { -1, "popen failed" };
    char buf[8192]; std::size_t n;
    while ((n = fread(buf, 1, sizeof(buf), p)) > 0)
        body.insert(body.end(), buf, buf + n);
    int rc = pclose(p);
    return { rc == 0 ? 200 : 404, rc == 0 ? "" : "curl failed" };
}
#endif

bool validate_downloaded_isf(const std::filesystem::path& p, const std::string& expect_release) {
    try {
        auto isf = IsfSymbols::load(p);
        if (isf->kernel_release() != expect_release) {
            log::warn("Downloaded ISF release '{}' != expected '{}'",
                      isf->kernel_release(), expect_release);
            return false;
        }
        return true;
    } catch (const std::exception& e) {
        log::warn("Downloaded ISF failed to parse: {}", e.what());
        return false;
    }
}

} // anonymous

HttpFetchResult fetch_isf_from_mirrors(const std::string&            banner,
                                       const std::string&            release,
                                       const std::filesystem::path&  cache_dir,
                                       const std::vector<std::string>& mirrors)
{
    HttpFetchResult r;
    if (banner.empty()) { r.error = "empty banner"; return r; }
    std::filesystem::create_directories(cache_dir);
    std::filesystem::path dst = cache_dir / (release + ".json.xz");

    std::string key = banner_cache_key(banner);
    log::info("Symbol-cache fetch: banner sha256[:16]={}... release={}",
              key.substr(0, 16), release);

    for (const auto& tmpl : mirrors) {
        std::string url = render_template(tmpl, key);
        log::info("  trying mirror: {}", url);
        std::vector<uint8_t> body;
        auto [status, err] = winhttp_get(url, body);
        if (status != 200) {
            log::debug("    HTTP {} {}", status, err);
            continue;
        }
        if (body.size() < 1024) {
            log::debug("    body too small ({} bytes)", body.size());
            continue;
        }
        std::ofstream out(dst, std::ios::binary);
        out.write(reinterpret_cast<const char*>(body.data()), body.size());
        out.close();
        if (!validate_downloaded_isf(dst, release)) {
            std::filesystem::remove(dst);
            continue;
        }
        r.ok       = true;
        r.path     = dst;
        r.from_url = url;
        log::info("  OK ({} bytes) -> {}", body.size(), dst.string());
        return r;
    }
    r.error = "no mirror returned a matching ISF";
    return r;
}

} // namespace lmpfs
