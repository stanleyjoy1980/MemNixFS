// vmmdll_compat.cpp — see header. MemProcFS-compatible C API on top of
// the native lmpfs_* surface.
#define LMPFS_API_BUILDING 1
#include "api/vmmdll_compat.h"
#include "api/lmpfs.h"

#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <mutex>
#include <string>
#include <vector>

namespace {

// The MemProcFS VMM_HANDLE is opaque; we make it carry our lmpfs_handle_t.
// Storing them as parallel pointers via reinterpret_cast lets us avoid an
// extra allocation per handle.
//
// Note: this means VMMDLL_Initialize allocates an lmpfs_handle_t internally
// and VMMDLL_Close frees it. Mixed lmpfs_* / VMMDLL_* on the SAME pointer
// is intentional — they're aliases for the same engine.

inline lmpfs_handle_t to_lmpfs(VMM_HANDLE h) {
    return reinterpret_cast<lmpfs_handle_t>(h);
}
inline VMM_HANDLE to_vmm(lmpfs_handle_t h) {
    return reinterpret_cast<VMM_HANDLE>(h);
}

// Track open handles for VMMDLL_CloseAll() — global lock + vector. This is
// the part of MemProcFS that surprises scripters: they can call CloseAll
// from a signal handler or at shutdown and expect everything to unwind
// cleanly.
std::mutex             g_handles_mu;
std::vector<VMM_HANDLE> g_handles;

void register_handle(VMM_HANDLE h) {
    std::lock_guard<std::mutex> l(g_handles_mu);
    g_handles.push_back(h);
}
void unregister_handle(VMM_HANDLE h) {
    std::lock_guard<std::mutex> l(g_handles_mu);
    auto it = std::find(g_handles.begin(), g_handles.end(), h);
    if (it != g_handles.end()) g_handles.erase(it);
}

// Parse MemProcFS-style argv. Returns (dump_path, symbol_path).
// Unrecognised flags are silently skipped — matches MemProcFS leniency.
std::pair<std::string, std::string>
parse_argv(DWORD argc, LPCSTR argv[]) {
    std::string dump, syms;
    // MemProcFS skips argv[0] by convention.
    for (DWORD i = 1; i + 1 <= argc; ++i) {
        if (!argv[i]) continue;
        std::string a = argv[i];
        // `-device <path>` or `-z <path>` (alias seen in scripts)
        if ((a == "-device" || a == "-z") && i + 1 < argc) {
            dump = argv[++i];
            continue;
        }
        if (a == "-symbol" && i + 1 < argc) {
            syms = argv[++i];
            continue;
        }
        // First non-flag positional → treat as dump path (some scripts
        // pass the path bare).
        if (dump.empty() && !a.empty() && a[0] != '-') {
            dump = a;
            continue;
        }
        // Silently ignore the rest. (-waitinitialize, -symbolserverdisable,
        // -norefresh, -printf, etc. are all accepted-and-ignored.)
    }
    return { dump, syms };
}

} // anonymous

// ---- lifecycle ------------------------------------------------------------

extern "C" VMMDLL_API VMM_HANDLE VMMDLL_Initialize(DWORD argc, LPCSTR argv[]) {
    auto [dump, syms] = parse_argv(argc, argv);
    if (dump.empty()) return nullptr;
    lmpfs_handle_t h = lmpfs_open(dump.c_str(),
                                   syms.empty() ? nullptr : syms.c_str());
    if (!h) return nullptr;
    VMM_HANDLE vh = to_vmm(h);
    register_handle(vh);
    return vh;
}

extern "C" VMMDLL_API VMM_HANDLE VMMDLL_InitializeEx(DWORD argc, LPCSTR argv[],
                                                     void** ppLcErrorInfo) {
    if (ppLcErrorInfo) *ppLcErrorInfo = nullptr;   // we don't surface LeechCore errors
    return VMMDLL_Initialize(argc, argv);
}

extern "C" VMMDLL_API VOID VMMDLL_Close(VMM_HANDLE hVMM) {
    if (!hVMM) return;
    unregister_handle(hVMM);
    lmpfs_close(to_lmpfs(hVMM));
}

extern "C" VMMDLL_API VOID VMMDLL_CloseAll(void) {
    std::vector<VMM_HANDLE> snapshot;
    {
        std::lock_guard<std::mutex> l(g_handles_mu);
        snapshot.swap(g_handles);
    }
    for (auto h : snapshot) lmpfs_close(to_lmpfs(h));
}

// ---- VFS list helpers (used by callbacks) ---------------------------------
//
// In MemProcFS, these are how the *plugin* code adds entries to the file-list
// the consumer passed in. We don't have plugins of our own (yet), so these
// just forward through the user's pFileList callbacks. They're exposed so
// downstream code that already uses them keeps compiling.

namespace {
// Each pFileList is a PVMMDLL_VFS_FILELIST2*. We sanity-check it.
inline PVMMDLL_VFS_FILELIST2 as_filelist(HANDLE p) {
    return reinterpret_cast<PVMMDLL_VFS_FILELIST2>(p);
}
} // anonymous

extern "C" VMMDLL_API VOID VMMDLL_VfsList_AddFile(HANDLE pFileList, LPCSTR uszName,
                                                   ULONG64 cb,
                                                   PVMMDLL_VFS_FILELIST_EXINFO pExInfo) {
    auto* fl = as_filelist(pFileList);
    if (!fl || !fl->pfnAddFile || !uszName) return;
    fl->pfnAddFile(fl->h, uszName, cb, pExInfo);
}

extern "C" VMMDLL_API VOID VMMDLL_VfsList_AddDirectory(HANDLE pFileList, LPCSTR uszName,
                                                        PVMMDLL_VFS_FILELIST_EXINFO pExInfo) {
    auto* fl = as_filelist(pFileList);
    if (!fl || !fl->pfnAddDirectory || !uszName) return;
    fl->pfnAddDirectory(fl->h, uszName, pExInfo);
}

extern "C" VMMDLL_API BOOL VMMDLL_VfsList_IsHandleValid(HANDLE pFileList) {
    auto* fl = as_filelist(pFileList);
    if (!fl) return FALSE;
    return (fl->dwVersion == VMMDLL_VFS_FILELIST_VERSION) ? TRUE : FALSE;
}

// ---- VFS list / read ------------------------------------------------------

extern "C" VMMDLL_API BOOL VMMDLL_VfsListU(VMM_HANDLE hVMM, LPCSTR uszPath,
                                            PVMMDLL_VFS_FILELIST2 pFileList) {
    if (!hVMM || !pFileList || !uszPath) return FALSE;
    if (pFileList->dwVersion != VMMDLL_VFS_FILELIST_VERSION) return FALSE;
    lmpfs_dir_entry_t* entries = nullptr;
    int count = 0;
    if (!lmpfs_vfs_list(to_lmpfs(hVMM), uszPath, &entries, &count)) return FALSE;
    // Dispatch one callback per child.
    for (int i = 0; i < count; ++i) {
        if (entries[i].is_dir) {
            if (pFileList->pfnAddDirectory)
                pFileList->pfnAddDirectory(pFileList->h, entries[i].name, nullptr);
        } else {
            if (pFileList->pfnAddFile)
                pFileList->pfnAddFile(pFileList->h, entries[i].name,
                                       entries[i].size, nullptr);
        }
    }
    lmpfs_vfs_list_free(entries);
    return TRUE;
}

extern "C" VMMDLL_API NTSTATUS VMMDLL_VfsReadU(VMM_HANDLE hVMM, LPCSTR uszFileName,
                                                PBYTE pb, DWORD cb, PDWORD pcbRead,
                                                ULONG64 cbOffset) {
    if (pcbRead) *pcbRead = 0;
    if (!hVMM || !uszFileName || !pb) return (NTSTATUS)0xC0000001L; /* STATUS_UNSUCCESSFUL */
    int64_t got = lmpfs_vfs_read(to_lmpfs(hVMM), uszFileName,
                                  cbOffset, pb, cb);
    if (got < 0) return (NTSTATUS)0xC0000034L; /* STATUS_OBJECT_NAME_NOT_FOUND */
    if (pcbRead) *pcbRead = (DWORD)got;
    return 0; /* STATUS_SUCCESS */
}

// ---- raw memory -----------------------------------------------------------

extern "C" VMMDLL_API BOOL VMMDLL_MemRead(VMM_HANDLE hVMM, DWORD /*dwPID*/,
                                           ULONG64 qwA, PBYTE pb, DWORD cb) {
    if (!hVMM || !pb || cb == 0) return FALSE;
    // dwPID is intentionally ignored: per-process VA reads go through the
    // VFS (/proc/<pid>/proc.dmp). At this entry point we always read
    // physical memory — matches MemProcFS's VMMDLL_PID_PHYSICALMEMORY case
    // and approximates the others reasonably for read-only forensic use.
    int64_t got = lmpfs_mem_read_phys(to_lmpfs(hVMM), qwA, pb, cb);
    return (got == (int64_t)cb) ? TRUE : FALSE;
}

extern "C" VMMDLL_API BOOL VMMDLL_MemReadEx(VMM_HANDLE hVMM, DWORD dwPID,
                                             ULONG64 qwA, PBYTE pb, DWORD cb,
                                             PDWORD pcbReadOpt, ULONG64 /*flags*/) {
    if (pcbReadOpt) *pcbReadOpt = 0;
    if (!hVMM || !pb || cb == 0) return FALSE;
    int64_t got = lmpfs_mem_read_phys(to_lmpfs(hVMM), qwA, pb, cb);
    if (got < 0) return FALSE;
    if (pcbReadOpt) *pcbReadOpt = (DWORD)got;
    (void)dwPID;
    return TRUE;
}

// ---- process enumeration --------------------------------------------------

extern "C" VMMDLL_API BOOL VMMDLL_PidList(VMM_HANDLE hVMM, PDWORD pPIDs,
                                           PSIZE_T pcPIDs) {
    if (!hVMM || !pcPIDs) return FALSE;
    int n = lmpfs_process_count(to_lmpfs(hVMM));
    if (n < 0) return FALSE;
    // MemProcFS pattern: NULL output buffer means "tell me how big".
    if (!pPIDs) { *pcPIDs = (size_t)n; return TRUE; }
    size_t cap = *pcPIDs;
    size_t fill = (size_t)n < cap ? (size_t)n : cap;
    lmpfs_process_t p{};
    for (size_t i = 0; i < fill; ++i) {
        if (!lmpfs_process_get(to_lmpfs(hVMM), (int)i, &p)) return FALSE;
        pPIDs[i] = p.pid;
    }
    *pcPIDs = fill;
    return TRUE;
}

extern "C" VMMDLL_API BOOL VMMDLL_PidGetFromName(VMM_HANDLE hVMM, LPCSTR szProcName,
                                                  PDWORD pdwPID) {
    if (!hVMM || !szProcName || !pdwPID) return FALSE;
    lmpfs_process_t p{};
    if (!lmpfs_process_find_by_name(to_lmpfs(hVMM), szProcName, &p)) return FALSE;
    *pdwPID = p.pid;
    return TRUE;
}

// ---- config (subset) ------------------------------------------------------

extern "C" VMMDLL_API BOOL VMMDLL_ConfigGet(VMM_HANDLE hVMM, ULONG64 fOption,
                                             PULONG64 pqwValue) {
    if (!pqwValue) return FALSE;
    if (!hVMM) return FALSE;
    switch (fOption) {
        case VMMDLL_OPT_CORE_PRINTF_ENABLE:
        case VMMDLL_OPT_CORE_VERBOSE:
        case VMMDLL_OPT_CORE_VERBOSE_EXTRA:
            *pqwValue = 0;       // we don't expose log levels through this API
            return TRUE;
        case VMMDLL_OPT_CORE_MAX_NATIVE_ADDRESS:
            // Best-effort: report the kernel's direct-map limit.
            *pqwValue = 0xffffffff80000000ULL;
            return TRUE;
        default:
            *pqwValue = 0;
            return FALSE;
    }
}

extern "C" VMMDLL_API BOOL VMMDLL_ConfigSet(VMM_HANDLE /*hVMM*/, ULONG64 /*fOption*/,
                                             ULONG64 /*qwValue*/) {
    // The engine is configured at lmpfs_open(); runtime config changes
    // aren't supported. Return FALSE so consumers know.
    return FALSE;
}
