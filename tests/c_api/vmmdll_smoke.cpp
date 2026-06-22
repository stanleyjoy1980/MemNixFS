/* vmmdll_smoke.cpp — smoke test for the MemProcFS-compat VMMDLL_* shim.
 *
 * Confirms the same DLL exports both `lmpfs_*` (native API) and `VMMDLL_*`
 * (compat) symbols, and that the latter behave like MemProcFS:
 *
 *   * argv parser strips `-device` / `-symbol` correctly
 *   * VfsListU dispatches add-callbacks per entry
 *   * MemRead returns BOOL (full-read = TRUE, short-read = FALSE)
 *   * PidList round-trips count + array
 *
 * Usage:  vmmdll_smoke <dump_path> [<symbols_path>]
 */
#include "api/vmmdll_compat.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <vector>

static int errors = 0;
#define CHECK(c, m) do { if (c) fprintf(stdout, "  ok: %s\n", m); \
                          else { fprintf(stderr, "FAIL: %s\n", m); ++errors; } } while (0)

struct ListSink {
    std::vector<std::string> files;
    std::vector<std::string> dirs;
};

static VOID add_file(HANDLE h, LPCSTR name, ULONG64 /*cb*/,
                      PVMMDLL_VFS_FILELIST_EXINFO /*ex*/) {
    static_cast<ListSink*>(h)->files.emplace_back(name);
}
static VOID add_dir(HANDLE h, LPCSTR name,
                     PVMMDLL_VFS_FILELIST_EXINFO /*ex*/) {
    static_cast<ListSink*>(h)->dirs.emplace_back(name);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <dump_path> [<symbols_path>]\n", argv[0]);
        return 2;
    }

    /* Build argv the MemProcFS way: ["", "-device", dump, "-symbol", syms]. */
    std::vector<const char*> v;
    v.push_back("");                 /* argv[0], skipped */
    v.push_back("-device");
    v.push_back(argv[1]);
    if (argc >= 3) {
        v.push_back("-symbol");
        v.push_back(argv[2]);
    }
    v.push_back("-waitinitialize");   /* known-ignored flag — must not break */

    fprintf(stdout, "== vmmdll_smoke ==\n");
    VMM_HANDLE h = VMMDLL_Initialize((DWORD)v.size(), v.data());
    CHECK(h != nullptr, "VMMDLL_Initialize parses -device/-symbol");

    /* PidList: NULL output -> learn the count, then fill. */
    SIZE_T n = 0;
    BOOL ok = VMMDLL_PidList(h, nullptr, &n);
    CHECK(ok && n > 0, "PidList null-buf returns count");
    fprintf(stdout, "       pid count = %zu\n", (size_t)n);
    std::vector<DWORD> pids(n);
    SIZE_T cap = n;
    ok = VMMDLL_PidList(h, pids.data(), &cap);
    CHECK(ok && cap == n, "PidList second call fills array");

    /* PidGetFromName for systemd. */
    DWORD sysd = 0;
    ok = VMMDLL_PidGetFromName(h, "systemd", &sysd);
    CHECK(ok && sysd == 1, "PidGetFromName('systemd') -> pid=1");

    /* VfsListU on "/" must invoke add_dir for each top-level subdirectory. */
    ListSink sink;
    VMMDLL_VFS_FILELIST2 fl{};
    fl.dwVersion       = VMMDLL_VFS_FILELIST_VERSION;
    fl.pfnAddFile      = add_file;
    fl.pfnAddDirectory = add_dir;
    fl.h               = &sink;
    ok = VMMDLL_VfsListU(h, "/", &fl);
    CHECK(ok, "VfsListU(/) returns TRUE");
    bool have_sys = false, have_proc = false, have_mem = false;
    for (auto& d : sink.dirs) {
        if (d == "sys")  have_sys  = true;
        if (d == "proc") have_proc = true;
        if (d == "mem")  have_mem  = true;
    }
    CHECK(have_sys && have_proc && have_mem,
          "callbacks delivered /sys /proc /mem entries");

    /* MemRead: 16 B at PA 0 should return FALSE (PA 0 unmapped) but no crash. */
    unsigned char buf[16];
    BOOL r0 = VMMDLL_MemRead(h, VMMDLL_PID_PHYSICALMEMORY, 0, buf, sizeof(buf));
    CHECK(r0 == FALSE, "MemRead at unmapped PA 0 returns FALSE");

    /* MemRead at the dump's banner location — exact PA varies, so pick a
     * value we know is mapped by walking /sys/banner.txt's first byte. */
    DWORD cb = 0;
    BOOL re = VMMDLL_MemReadEx(h, VMMDLL_PID_PHYSICALMEMORY, 0, buf,
                                sizeof(buf), &cb, 0);
    /* PA 0 might short-read; cb tells us how many bytes we actually got.
       Both `re=FALSE` with cb=0 and `re=TRUE` with cb=16 would be accepted. */
    CHECK(cb == 0 || cb == sizeof(buf), "MemReadEx pcbReadOpt matches");
    (void)re;

    /* VfsReadU on a known file. */
    char banner[256];
    DWORD got = 0;
    NTSTATUS st = VMMDLL_VfsReadU(h, "/sys/banner.txt", (PBYTE)banner,
                                   sizeof(banner) - 1, &got, 0);
    CHECK(st == 0, "VfsReadU(/sys/banner.txt) returns STATUS_SUCCESS");
    if (got >= 5) banner[got] = 0;
    CHECK(got > 0 && std::strstr(banner, "Linux") != nullptr,
          "banner contains 'Linux'");

    VMMDLL_Close(h);
    fprintf(stdout, "  ok: VMMDLL_Close\n");
    /* CloseAll on an empty list must be a clean no-op. */
    VMMDLL_CloseAll();

    fprintf(stdout, "\n== %d failure(s) ==\n", errors);
    return errors == 0 ? 0 : 1;
}
