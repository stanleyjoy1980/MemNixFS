/* c_api_smoke.c — minimal C consumer of memnixfs_dll.
 *
 * Pure C99. Walks every entry point at least once on a real dump:
 *   - open / version / kernel banner
 *   - process_count + first 5 processes + find by name + by pid
 *   - vfs_list("/") + vfs_size + vfs_read on a known file
 *   - mem_read_phys + mem_read_kva (translation sanity)
 *   - last_error after a deliberate failure
 *   - close
 *
 * Usage:  c_api_smoke <dump_path> [<symbols_path>]
 *
 * Build: linked against memnixfs_dll.lib (or directly via LoadLibrary if you
 * prefer; this test uses the import-lib path for simplicity).
 */
#include "api/lmpfs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

static int errors = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); ++errors; } \
    else         { fprintf(stdout, "  ok: %s\n",  msg); } \
} while (0)

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <dump_path> [<symbols_path>]\n", argv[0]);
        return 2;
    }
    const char* dump = argv[1];
    const char* syms = argc >= 3 ? argv[2] : NULL;

    /* ---- version + last_error baseline ---- */
    const char* v = lmpfs_version();
    printf("== c_api_smoke: lmpfs_version=%s ==\n", v ? v : "(null)");
    CHECK(v && v[0], "lmpfs_version returns non-empty");
    CHECK(lmpfs_last_error()[0] == '\0', "last_error empty before any op");

    /* ---- open ---- */
    lmpfs_handle_t h = lmpfs_open(dump, syms);
    if (!h) {
        fprintf(stderr, "FAIL: lmpfs_open: %s\n", lmpfs_last_error());
        return 1;
    }
    printf("  ok: lmpfs_open returned handle\n");

    /* ---- kernel banner ---- */
    char banner[1024];
    int n = lmpfs_kernel_banner(h, banner, sizeof(banner));
    CHECK(n > 0, "lmpfs_kernel_banner > 0 bytes");
    printf("       kernel banner (truncated to first 80): %.80s%s\n",
           banner, n > 80 ? "…" : "");

    uint64_t dmap = lmpfs_kernel_direct_map_base(h);
    CHECK(dmap != 0, "direct_map_base resolved");
    printf("       direct_map_base = 0x%" PRIx64 "\n", dmap);

    int64_t kaslr = lmpfs_kernel_kaslr_phys_shift(h);
    printf("       kaslr_phys_shift = 0x%" PRIx64 "\n", (uint64_t)kaslr);

    /* ---- process enumeration ---- */
    int pc = lmpfs_process_count(h);
    CHECK(pc > 0, "process_count > 0");
    printf("       process_count = %d\n", pc);

    lmpfs_process_t p;
    int got_first = lmpfs_process_get(h, 0, &p);
    CHECK(got_first, "process_get(0) succeeds");
    if (got_first) {
        printf("       proc[0]:  pid=%u  ppid=%u  uid=%u  comm=%s\n",
               p.pid, p.ppid, p.uid, p.comm);
    }

    /* Out-of-range index → 0 + last_error set. */
    lmpfs_process_t junk;
    int oob = lmpfs_process_get(h, pc + 99, &junk);
    CHECK(!oob, "process_get out-of-range returns 0");
    CHECK(lmpfs_last_error()[0] != '\0', "last_error set after out-of-range");
    printf("       (deliberate out-of-range error: %s)\n", lmpfs_last_error());

    /* Find by comm — pid 1 is usually "systemd" on Linux desktops. */
    if (lmpfs_process_find_by_name(h, "systemd", &p)) {
        printf("       found by name systemd → pid=%u\n", p.pid);
        CHECK(p.pid > 0, "systemd has nonzero pid");
    } else {
        printf("       (no 'systemd' on this dump — that's okay)\n");
    }

    /* Find by PID 1 — should be init regardless of comm. */
    if (lmpfs_process_find_by_pid(h, 1, &p)) {
        printf("       found by pid=1 → comm=%s\n", p.comm);
        CHECK(p.pid == 1, "pid-1 lookup returns pid=1");
    } else {
        fprintf(stderr, "FAIL: pid 1 not found?\n"); ++errors;
    }

    /* ---- VFS ---- */
    lmpfs_dir_entry_t* root = NULL;
    int rcount = 0;
    int rok = lmpfs_vfs_list(h, "/", &root, &rcount);
    CHECK(rok, "vfs_list(/) succeeds");
    printf("       / has %d entries\n", rcount);
    int found_sys = 0, found_proc = 0, found_mem = 0, found_search = 0;
    for (int i = 0; i < rcount; ++i) {
        if (!strcmp(root[i].name, "sys"))    found_sys    = 1;
        if (!strcmp(root[i].name, "proc"))   found_proc   = 1;
        if (!strcmp(root[i].name, "mem"))    found_mem    = 1;
        if (!strcmp(root[i].name, "search")) found_search = 1;
    }
    CHECK(found_sys,    "/sys exists");
    CHECK(found_proc,   "/proc exists");
    CHECK(found_mem,    "/mem exists");
    CHECK(found_search, "/search exists");
    lmpfs_vfs_list_free(root);

    /* read a small known file */
    int64_t sz = lmpfs_vfs_size(h, "/sys/banner.txt");
    CHECK(sz > 0, "/sys/banner.txt has nonzero size");
    if (sz > 0) {
        char* buf = (char*)malloc((size_t)sz + 1);
        int64_t got = lmpfs_vfs_read(h, "/sys/banner.txt", 0, buf, (size_t)sz);
        CHECK(got == sz, "vfs_read full banner");
        buf[got >= 0 ? got : 0] = '\0';
        printf("       /sys/banner.txt (first 60): %.60s%s\n",
               buf, got > 60 ? "…" : "");
        free(buf);
    }

    /* deliberate missing-path error */
    int64_t miss = lmpfs_vfs_size(h, "/does/not/exist");
    CHECK(miss < 0, "vfs_size on missing path returns -1");
    CHECK(lmpfs_last_error()[0] != '\0', "last_error set on missing path");

    /* ---- raw memory ----
     *
     * kaslr_phys_shift is a SHIFT (often negative), not a physical address, so
     * don't use it as a PA. PA 0 and many low PAs are unmapped holes. Probe a
     * few candidate PAs and use the first that's fully backed (the physical
     * layer reports the real frame-backed byte count, so a mapped 16-byte
     * window returns 16 and a hole returns < 16). */
    (void)kaslr;
    static const uint64_t cand[] = {
        0x1000000, 0x2000000, 0x4000000, 0x8000000,
        0x10000000, 0x800000, 0x100000
    };
    uint8_t mem[16] = { 0 };
    uint64_t known_pa = 0;
    int64_t mread = -1;
    for (size_t ci = 0; ci < sizeof(cand) / sizeof(cand[0]); ++ci) {
        int64_t r = lmpfs_mem_read_phys(h, cand[ci], mem, sizeof(mem));
        if (r == (int64_t)sizeof(mem)) { known_pa = cand[ci]; mread = r; break; }
    }
    CHECK(known_pa != 0, "found a mapped physical address by probing");
    CHECK(mread == (int64_t)sizeof(mem), "mem_read_phys 16 B at a mapped PA");

    /* Read the same bytes via kva at the direct-map alias of that same PA
     * and compare — direct-map VA = direct_map_base + PA. */
    if (dmap != 0 && mread == (int64_t)sizeof(mem)) {
        uint8_t mem2[16] = { 0 };
        uint64_t kva = dmap + known_pa;
        int64_t kread = lmpfs_mem_read_kva(h, kva, mem2, sizeof(mem2));
        CHECK(kread == (int64_t)sizeof(mem2), "mem_read_kva 16 B at direct-map alias");
        if (kread == (int64_t)sizeof(mem2)) {
            int identical = memcmp(mem, mem2, sizeof(mem)) == 0;
            CHECK(identical, "phys[PA] == kva[direct_map_base+PA] (translation OK)");
        }
    }
    /* Unmapped read should return 0 — NOT an error. */
    uint8_t unused[8];
    int64_t zread = lmpfs_mem_read_phys(h, 0, unused, sizeof(unused));
    CHECK(zread >= 0, "mem_read_phys on unmapped PA returns >= 0 (not error)");

    /* ---- close ---- */
    lmpfs_close(h);
    printf("  ok: lmpfs_close\n");

    printf("\n== %d failure(s) ==\n", errors);
    return errors == 0 ? 0 : 1;
}
