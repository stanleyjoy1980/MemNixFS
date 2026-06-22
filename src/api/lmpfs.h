/* lmpfs.h — public C API for MemNixFS.
 *
 * Lets any language with C FFI (Python ctypes, Rust bindgen, .NET P/Invoke,
 * Java JNA, native C/C++) drive the same engine that powers the WinFsp
 * mount + CLI.
 *
 * MemProcFS's `vmm.dll`-style `VMMDLL_*` compatibility shim is a thin wrapper
 * over this API.
 *
 * Threading: the engine itself is thread-safe (WinFsp dispatches concurrent
 * reads against it). All handle operations are thread-safe; `lmpfs_last_error`
 * is THREAD-LOCAL — call it from the thread that just got a failure return.
 *
 * Error convention: functions return < 0 on failure, ≥ 0 on success.
 * Specifically:
 *    pointer-returning  (lmpfs_open, lmpfs_version)   NULL on failure
 *    bool-shaped int    (lmpfs_process_get, …)        0 on failure, 1 on OK
 *    byte-count int64_t (lmpfs_vfs_read, mem_read_*)  -1 on failure, ≥ 0 = bytes
 *    enum-style int     (lmpfs_process_count, …)      -1 on failure, ≥ 0 = count
 *
 * After any failure, call `lmpfs_last_error()` for a human-readable message.
 */
#ifndef LMPFS_H
#define LMPFS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- DLL export decoration ---------------------------------------------
 *
 * When BUILDING the DLL itself (CMake sets LMPFS_API_BUILDING),
 * each exported function is marked __declspec(dllexport).
 *
 * When CONSUMING the DLL, no special decoration is needed on MSVC ≥ 2015
 * because we ship a .lib import library — but pure-C consumers using
 * LoadLibrary() / GetProcAddress() see the symbol by its plain name
 * thanks to extern "C" + __stdcall NOT being applied.
 */
#if defined(_WIN32) && defined(LMPFS_API_BUILDING)
#  define LMPFS_API __declspec(dllexport)
#elif defined(_WIN32)
#  define LMPFS_API __declspec(dllimport)
#else
#  define LMPFS_API
#endif

/* ---- Opaque handle ------------------------------------------------------ */
typedef struct lmpfs_handle_impl* lmpfs_handle_t;

/* ---- Plain-old-data structs (kept ABI-stable) -------------------------- */
typedef struct lmpfs_process {
    uint32_t pid;
    uint32_t tgid;
    uint32_t ppid;
    uint32_t uid;
    /* TASK_COMM_LEN = 16 on Linux. NUL-terminated. */
    char     comm[16];
    /* mm_struct kernel VA (0 = kernel thread). */
    uint64_t mm_va;
    /* task_struct kernel VA + PA. */
    uint64_t task_va;
    uint64_t task_pa;
} lmpfs_process_t;

typedef struct lmpfs_dir_entry {
    /* Component name (no path separators). Up to 255 chars + NUL. */
    char     name[256];
    int      is_dir;     /* 0 = file, 1 = directory */
    uint64_t size;       /* file size in bytes; 0 for directories */
} lmpfs_dir_entry_t;

/* ---- Library-wide functions -------------------------------------------- */

/* Returns a const, NUL-terminated build-version string. Never NULL. */
LMPFS_API const char* lmpfs_version(void);

/* Returns the last error message that occurred on THIS THREAD, or "" if
 * there's nothing to report. The pointer is valid until the next call
 * on the same thread. Never NULL. */
LMPFS_API const char* lmpfs_last_error(void);

/* ---- Handle lifecycle -------------------------------------------------- */

/* Open a memory dump and resolve symbols.
 *
 *   dump_path     Path to the dump file. Required.
 *   symbols_path  Path to an ISF .json[.xz] file, a directory to auto-
 *                 discover from, or NULL/"" for built-in auto resolution
 *                 (BTF in dump → ISF cache → community mirror).
 *
 * Returns a handle on success; NULL on failure (see lmpfs_last_error).
 *
 * This is the same code path as `memnixfs --dump … --symbols …`.
 * Expect 10-60 seconds on a typical desktop dump (ISF decompression
 * + KASLR scan + process enumeration + inode-hashtable walk).
 */
LMPFS_API lmpfs_handle_t lmpfs_open(const char* dump_path,
                                    const char* symbols_path);

/* Close a handle. Safe to pass NULL (no-op). */
LMPFS_API void lmpfs_close(lmpfs_handle_t h);

/* ---- Process enumeration ----------------------------------------------- */

/* Number of processes visible via init_task.tasks walk. -1 on bad handle. */
LMPFS_API int lmpfs_process_count(lmpfs_handle_t h);

/* Fill `*out` with the process at the given index (0-based).
 * Returns 1 on success, 0 on out-of-bounds or bad handle. */
LMPFS_API int lmpfs_process_get(lmpfs_handle_t h, int index,
                                lmpfs_process_t* out);

/* Find the FIRST process whose comm equals `name`. Case-sensitive.
 * Returns 1 on hit, 0 on miss. */
LMPFS_API int lmpfs_process_find_by_name(lmpfs_handle_t h, const char* name,
                                          lmpfs_process_t* out);

/* Find process by PID. Returns 1 on hit, 0 on miss. */
LMPFS_API int lmpfs_process_find_by_pid(lmpfs_handle_t h, uint32_t pid,
                                         lmpfs_process_t* out);

/* ---- VFS access -------------------------------------------------------- */

/* List entries at `path` (which must be a directory; "/" for root).
 *
 * On success: *entries points to a heap-allocated array of `*count` entries.
 *             The caller MUST free it with lmpfs_vfs_list_free.
 * On failure: returns 0; *entries is set to NULL and *count to 0.
 *
 * Returns 1 on success, 0 on failure.
 */
LMPFS_API int lmpfs_vfs_list(lmpfs_handle_t h, const char* path,
                              lmpfs_dir_entry_t** entries, int* count);

/* Free the array returned by lmpfs_vfs_list. Safe to pass NULL. */
LMPFS_API void lmpfs_vfs_list_free(lmpfs_dir_entry_t* entries);

/* Get the size of a VFS file in bytes. -1 on error (e.g. not a file). */
LMPFS_API int64_t lmpfs_vfs_size(lmpfs_handle_t h, const char* path);

/* Read up to `len` bytes from a VFS file starting at `offset`. Returns:
 *    > 0 : number of bytes actually written to `buf`
 *    = 0 : EOF reached at this offset
 *    < 0 : error (see lmpfs_last_error)
 *
 * For huge sparse files (/mem/phys.raw, /mem/kern_va.raw, proc.dmp) this
 * is the only sane way to read — list_size + chunked read.
 */
LMPFS_API int64_t lmpfs_vfs_read(lmpfs_handle_t h, const char* path,
                                  uint64_t offset, void* buf, size_t len);

/* ---- Raw memory access ------------------------------------------------- */

/* Read physical memory.  Returns bytes actually read (-1 on error).
 * Out-of-range / unmapped reads return zero bytes per page (sparse
 * semantics; same contract as /mem/phys.raw). */
LMPFS_API int64_t lmpfs_mem_read_phys(lmpfs_handle_t h, uint64_t pa,
                                       void* buf, size_t len);

/* Read kernel virtual memory — picks the right strategy per page
 * (direct-map / kernel-image / vmalloc-PGD with init_mm.pgd fallback).
 * Same path as `kva_read` in the engine. Pages that don't resolve come
 * back as zeros (sparse-file semantics). Returns bytes written. */
LMPFS_API int64_t lmpfs_mem_read_kva(lmpfs_handle_t h, uint64_t va,
                                      void* buf, size_t len);

/* ---- Kernel context ---------------------------------------------------- */

/* Copy the kernel banner string into `out` (up to `out_size`-1 chars,
 * always NUL-terminated). Returns the number of bytes written (excluding
 * NUL), -1 on error. */
LMPFS_API int lmpfs_kernel_banner(lmpfs_handle_t h, char* out, size_t out_size);

/* Return the kernel's direct_map_base VA (0 if unresolved). */
LMPFS_API uint64_t lmpfs_kernel_direct_map_base(lmpfs_handle_t h);

/* Return the kernel's KASLR physical shift in bytes. */
LMPFS_API int64_t  lmpfs_kernel_kaslr_phys_shift(lmpfs_handle_t h);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* LMPFS_H */
