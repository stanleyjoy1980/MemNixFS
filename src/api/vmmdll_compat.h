/* vmmdll_compat.h — MemProcFS-compatible `VMMDLL_*` C API for MemNixFS.
 *
 * A drop-in subset of MemProcFS's `vmmdll.h`. Existing MemProcFS scripts
 * that target `vmm.dll` can swap in our `memnixfs.dll` (rename or symlink
 * to `vmm.dll`) and run unchanged against Linux memory dumps.
 *
 * NOT a complete replica — we ship the surface that mattered in field
 * usage: lifecycle, VFS list/read, process discovery, raw memory reads.
 * Everything that isn't shimmed still returns FALSE / 0 / NULL with
 * GetLastError-style state — never crashes — so callers can gracefully
 * degrade.
 *
 * The shim is implemented in `vmmdll_compat.cpp` on top of the native
 * `lmpfs_*` C ABI (lmpfs.h). Every `VMMDLL_` entry point translates
 * one-or-two-step to an `lmpfs_` call.
 *
 * What's mirrored:
 *
 *   VMMDLL_Initialize           ← lmpfs_open (parses argv for -device / -symbol)
 *   VMMDLL_InitializeEx         ← same
 *   VMMDLL_Close                ← lmpfs_close
 *   VMMDLL_CloseAll
 *   VMMDLL_VfsListU             ← lmpfs_vfs_list + callback dispatch
 *   VMMDLL_VfsReadU             ← lmpfs_vfs_read
 *   VMMDLL_VfsList_AddFile      (helper, used inside our shim)
 *   VMMDLL_VfsList_AddDirectory (helper)
 *   VMMDLL_VfsList_IsHandleValid
 *   VMMDLL_MemRead              ← lmpfs_mem_read_phys (when dwPID == -1)
 *   VMMDLL_MemReadEx            ← same, with flags ignored for now
 *   VMMDLL_PidList              ← lmpfs_process_count + _get
 *   VMMDLL_PidGetFromName       ← lmpfs_process_find_by_name
 *   VMMDLL_ConfigGet            (a few stable LMPFS-specific option ids)
 *
 * What's NOT shimmed (yet):
 *
 *   VfsWriteU                — engine is read-only.
 *   MemReadScatter           — single-page reads cover the common case.
 *   ProcessGetInformation    — needs the full VMMDLL_PROCESS_INFORMATION
 *                              struct; defer until a real consumer asks.
 *   Symbol / debug-info APIs — vol3 + our own ISF path are the right
 *                              substrate for that.
 *
 * References:
 *   MemProcFS:  vmm/vmmdll.h, vmm/vmmdll.c — public API.
 *   This file mirrors the *signatures* exactly. Behaviour is best-effort
 *   (LMPFS isn't bit-identical to MemProcFS; we're aiming for source-
 *   compatibility, not behaviour-isomorphism).
 */
#ifndef LMPFS_VMMDLL_COMPAT_H
#define LMPFS_VMMDLL_COMPAT_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#  include <windows.h>     /* BOOL / DWORD / LPCSTR / HANDLE / FILETIME */
   /* NTSTATUS isn't pulled in by plain windows.h in user-mode builds —
    * <ntstatus.h> needs WIN32_NO_STATUS and <bcrypt.h> drags in extra
    * surface we don't want. Just typedef it ourselves; matches WinNT.h. */
#  ifndef NTSTATUS
   typedef long NTSTATUS;
#  endif
#else
   /* Non-Windows shim — keep the same names so the body compiles. */
   typedef int           BOOL;
   typedef unsigned long DWORD;
   typedef const char*   LPCSTR;
   typedef void*         HANDLE;
   typedef unsigned char BYTE;
   typedef BYTE*         PBYTE;
   typedef DWORD*        PDWORD;
   typedef unsigned long long ULONG64;
   typedef ULONG64*      PULONG64;
   typedef size_t        SIZE_T;
   typedef size_t*       PSIZE_T;
   typedef long          NTSTATUS;
   typedef void          VOID;
#  ifndef TRUE
#    define TRUE  1
#    define FALSE 0
#  endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ---- export decoration -------------------------------------------------- */
#if defined(_WIN32) && defined(LMPFS_API_BUILDING)
#  define VMMDLL_API __declspec(dllexport)
#elif defined(_WIN32)
#  define VMMDLL_API __declspec(dllimport)
#else
#  define VMMDLL_API
#endif

/* ---- opaque handle ----------------------------------------------------- */
typedef struct tdVMM_HANDLE* VMM_HANDLE;

/* ---- VfsList callback dispatch ----------------------------------------- */
#define VMMDLL_VFS_FILELIST_VERSION         2
#define VMMDLL_VFS_FILELIST_EXINFO_VERSION  1

typedef struct tdVMMDLL_VFS_FILELIST_EXINFO {
    DWORD     dwVersion;
    BOOL      fCompressed;
    ULONG64   qwCreationTime;
    ULONG64   qwLastAccessTime;
    ULONG64   qwLastWriteTime;
} VMMDLL_VFS_FILELIST_EXINFO, *PVMMDLL_VFS_FILELIST_EXINFO;

typedef struct tdVMMDLL_VFS_FILELIST2 {
    DWORD   dwVersion;
    VOID  (*pfnAddFile)     (HANDLE h, LPCSTR uszName, ULONG64 cb,
                              PVMMDLL_VFS_FILELIST_EXINFO pExInfo);
    VOID  (*pfnAddDirectory)(HANDLE h, LPCSTR uszName,
                              PVMMDLL_VFS_FILELIST_EXINFO pExInfo);
    HANDLE  h;
} VMMDLL_VFS_FILELIST2, *PVMMDLL_VFS_FILELIST2;

/* ---- lifecycle --------------------------------------------------------- */

/* Parse argv MemProcFS-style:
 *
 *     -device <path>     dump file (required, unless first positional arg)
 *     -symbol <path>     optional ISF / vmlinux path
 *     -waitinitialize    accepted + ignored (we initialise synchronously)
 *     -symbolserverdisable  accepted + ignored
 *
 * Anything we don't recognise is silently skipped — strict-parsing would
 * break tools that pass MemProcFS-specific flags meaninglessly.
 */
VMMDLL_API VMM_HANDLE VMMDLL_Initialize(DWORD argc, LPCSTR argv[]);
VMMDLL_API VMM_HANDLE VMMDLL_InitializeEx(DWORD argc, LPCSTR argv[], void** ppLcErrorInfo);

VMMDLL_API VOID VMMDLL_Close(VMM_HANDLE hVMM);
VMMDLL_API VOID VMMDLL_CloseAll(void);

/* ---- VFS list helper functions used INSIDE a callback ------------------ */
VMMDLL_API VOID VMMDLL_VfsList_AddFile     (HANDLE pFileList, LPCSTR uszName,
                                             ULONG64 cb,
                                             PVMMDLL_VFS_FILELIST_EXINFO pExInfo);
VMMDLL_API VOID VMMDLL_VfsList_AddDirectory(HANDLE pFileList, LPCSTR uszName,
                                             PVMMDLL_VFS_FILELIST_EXINFO pExInfo);
VMMDLL_API BOOL VMMDLL_VfsList_IsHandleValid(HANDLE pFileList);

/* ---- VFS list / read --------------------------------------------------- */
VMMDLL_API BOOL VMMDLL_VfsListU(VMM_HANDLE hVMM, LPCSTR uszPath,
                                 PVMMDLL_VFS_FILELIST2 pFileList);

/* NTSTATUS_SUCCESS == 0, anything non-zero is an error in MemProcFS-land. */
VMMDLL_API NTSTATUS VMMDLL_VfsReadU(VMM_HANDLE hVMM, LPCSTR uszFileName,
                                     PBYTE pb, DWORD cb, PDWORD pcbRead,
                                     ULONG64 cbOffset);

/* ---- raw memory -------------------------------------------------------- */

/* dwPID == -1 (0xFFFFFFFF) → physical addressing.
 * Any other dwPID is currently treated as physical too (our user-PGD
 * machinery isn't exposed at this granularity yet; per-process reads
 * are available via /proc/<pid>/proc.dmp instead). */
#define VMMDLL_PID_PHYSICALMEMORY  ((DWORD)-1)

VMMDLL_API BOOL VMMDLL_MemRead   (VMM_HANDLE hVMM, DWORD dwPID, ULONG64 qwA,
                                   PBYTE pb, DWORD cb);
VMMDLL_API BOOL VMMDLL_MemReadEx (VMM_HANDLE hVMM, DWORD dwPID, ULONG64 qwA,
                                   PBYTE pb, DWORD cb, PDWORD pcbReadOpt,
                                   ULONG64 flags);

/* ---- process enumeration ----------------------------------------------- */

/* Standard MemProcFS pattern: caller passes NULL the first time to learn
 * the count, allocates, calls again to fill. Returns 1 on success. */
VMMDLL_API BOOL VMMDLL_PidList(VMM_HANDLE hVMM, PDWORD pPIDs, PSIZE_T pcPIDs);

VMMDLL_API BOOL VMMDLL_PidGetFromName(VMM_HANDLE hVMM, LPCSTR szProcName,
                                       PDWORD pdwPID);

/* ---- config (subset) --------------------------------------------------- */

/* A few stable option IDs we honour. MemProcFS has many; we ship the
 * ones existing consumer scripts actually read. */
#define VMMDLL_OPT_CORE_PRINTF_ENABLE       0x4000000100000000ULL
#define VMMDLL_OPT_CORE_VERBOSE             0x4000000200000000ULL
#define VMMDLL_OPT_CORE_VERBOSE_EXTRA       0x4000000300000000ULL
#define VMMDLL_OPT_CORE_MAX_NATIVE_ADDRESS  0x4000000800000000ULL

VMMDLL_API BOOL VMMDLL_ConfigGet(VMM_HANDLE hVMM, ULONG64 fOption, PULONG64 pqwValue);
VMMDLL_API BOOL VMMDLL_ConfigSet(VMM_HANDLE hVMM, ULONG64 fOption, ULONG64 qwValue);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* LMPFS_VMMDLL_COMPAT_H */
