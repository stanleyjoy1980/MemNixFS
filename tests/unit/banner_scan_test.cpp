#include "os/linux/banner_scan.h"

#include <cstdio>
#include <string>
#include <vector>

using lmpfs::linux::parse_kernel_release;
using lmpfs::linux::select_canonical_banner;

static int g_failures = 0;

#define CHECK(cond, msg)                                      \
    do {                                                      \
        if (cond) {                                           \
            std::printf("  ok: %s\n", (msg));                 \
        } else {                                              \
            std::printf("FAIL: %s\n", (msg));                 \
            ++g_failures;                                     \
        }                                                     \
    } while (0)

static bool contains(const std::string& s, const std::string& n) {
    return s.find(n) != std::string::npos;
}

int main() {
    const std::string tmpl = "Linux version %s (%s)";
    const std::string cve =
        "Linux version of udadmin_server, which is an RPC service that comes "
        "with the Rocket Software UniData server.";
    const std::string kali619 =
        "Linux version 6.19.14+kali-amd64 (devel@kali.org) "
        "(x86_64-linux-gnu-gcc-15 (Debian 15.2.0-17) 15.2.0, GNU ld "
        "(GNU Binutils for Debian) 2.46) #1 SMP PREEMPT_DYNAMIC Kali "
        "6.19.14-1+kali1 (2026-05-05)";
    const std::string kali612 =
        "Linux version 6.12.38+kali-amd64 (devel@kali.org) "
        "(x86_64-linux-gnu-gcc-14 (Debian 14.2.0-19) 14.2.0, GNU ld "
        "(GNU Binutils for Debian) 2.44) #1 SMP PREEMPT_DYNAMIC Kali "
        "6.12.38-1kali1 (2025-08-12)";
    const std::string fedora =
        "Linux version 6.19.10-300.fc44.x86_64 (mockbuild@bkernel01.iad2.fedoraproject.org) "
        "(gcc (GCC) 15.1.1 20250521 (Red Hat 15.1.1-2), GNU ld version "
        "2.44-3.fc44) #1 SMP PREEMPT_DYNAMIC Fedora 6.19.10-300.fc44.x86_64";

    CHECK(parse_kernel_release(tmpl) == "%s", "template release still parses as raw token");
    CHECK(parse_kernel_release(cve) == "of", "article text release still parses as raw token");

    {
        auto best = select_canonical_banner({tmpl, cve, kali619});
        CHECK(best == kali619, "reject template and article text");
        CHECK(parse_kernel_release(best) == "6.19.14+kali-amd64",
              "select Kali 6.19 release");
    }

    {
        auto best = select_canonical_banner({tmpl, cve, kali612, kali619,
                                             kali619, kali619});
        CHECK(best == kali619, "prefer repeated current banner over stale cached banner");
    }

    {
        auto best = select_canonical_banner({cve, fedora, tmpl});
        CHECK(best == fedora, "select Fedora kernel banner");
        CHECK(contains(best, "Fedora"), "selected banner keeps distro build details");
    }

    {
        auto best = select_canonical_banner({tmpl, cve, "Linux version wasn't tested."});
        CHECK(best.empty(), "return empty when no canonical banner exists");
    }

    std::printf("== %d failure(s) ==\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
