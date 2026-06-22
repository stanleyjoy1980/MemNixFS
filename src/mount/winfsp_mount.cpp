// WinFsp read-only filesystem adapter for the lmpfs VFS.
//
// Structure mirrors the WinFsp notifyfs sample (samples/notifyfs/notifyfs.c)
// almost verbatim — that sample is known to work in this environment, so any
// deviation from its surface is suspect when the dispatcher misbehaves.
#ifdef LMPFS_HAS_WINFSP
#include <windows.h>
#include <sddl.h>
typedef LONG *PNTSTATUS;
#include <winfsp/winfsp.h>

#include "app/engine.h"
#include "vfs/vfs.h"
#include "core/log.h"
#include "core/error.h"
#include <fmt/format.h>
#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

namespace lmpfs::mount {

namespace {

using vfs::Node;
using vfs::NodePtr;

struct LmpfsFs {
    FSP_FILE_SYSTEM*     FileSystem = nullptr;
    Engine*              Engine     = nullptr;
    std::vector<uint8_t> DefaultSd;
};

// FileContext: pass the raw Node* directly (MemProcFS pattern — stateless).
// All Nodes live as long as the Engine which lives as long as the mount, so
// the pointer is valid for the file system's lifetime. No new/delete needed,
// which means no double-free risk when WinFsp's dispatch issues spurious
// duplicate Close IRPs (which Explorer's autorun probing definitely does).
inline Node* ctx_node(PVOID FileContext) { return static_cast<Node*>(FileContext); }

// ---- utf-8 / utf-16 helpers ------------------------------------------------
std::wstring W(const std::string& s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
    return w;
}
std::string U(const wchar_t* w) {
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    std::string s(n ? n - 1 : 0, '\0');
    if (n) WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n, nullptr, nullptr);
    return s;
}

NodePtr ResolvePath(LmpfsFs* fs, PWSTR FileName) {
    std::string path = U(FileName);
    if (path.empty() || path == "\\" || path == "/") return fs->Engine->vfs_root();
    std::string norm;
    for (char c : path) norm.push_back(c == '\\' ? '/' : c);
    return vfs::resolve(fs->Engine->vfs_root(), norm);
}

// Converts a C++ time_point to a Windows FILETIME (100ns units since
// 1601-01-01). Used so file timestamps stay STABLE across queries — otherwise
// editors like Notepad++ poll on focus, see a moving mtime, and prompt
// "file was modified, reload?" on every window-focus change.
inline UINT64 chrono_to_filetime(std::chrono::system_clock::time_point tp) {
    using namespace std::chrono;
    auto ns = duration_cast<nanoseconds>(tp.time_since_epoch()).count();
    // 11644473600 s between 1601-01-01 and 1970-01-01, × 10^7 100ns intervals.
    return static_cast<UINT64>(ns / 100) + 116444736000000000ULL;
}

// `cheap`: use the non-producing size_hint() instead of the authoritative
// size(). Set during directory enumeration so listing a folder doesn't run
// every child's lazy producer. The real size is resolved when the file is
// actually opened (GetFileInfo path passes cheap=false).
void FillFileInfo(const NodePtr& node, FSP_FSCTL_FILE_INFO* FileInfo,
                  bool cheap = false) {
    std::memset(FileInfo, 0, sizeof(*FileInfo));
    FileInfo->FileAttributes = node->is_dir()
        ? FILE_ATTRIBUTE_DIRECTORY
        : (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_NORMAL);
    UINT64 sz = 0;
    if (node->is_file()) {
        try {
            sz = cheap ? node->size_hint() : node->size();
        } catch (const std::exception& e) {
            log::warn("[WinFsp] size() threw for '{}': {}", node->name(), e.what());
            sz = 0;
        }
    }
    FileInfo->FileSize       = sz;
    FileInfo->AllocationSize = (sz + 4095) & ~UINT64(4095);
    // STABLE timestamp from the Node's ctime (set at construction). Returning
    // the current wall-clock time here would make every FileInfo query report
    // "modified just now", which triggers reload prompts in any editor that
    // watches files on focus.
    UINT64 t = chrono_to_filetime(node->ctime());
    FileInfo->CreationTime = FileInfo->LastAccessTime =
        FileInfo->LastWriteTime = FileInfo->ChangeTime = t;
    FileInfo->IndexNumber = reinterpret_cast<UINT64>(node.get());
}

// ---- callbacks -------------------------------------------------------------
NTSTATUS GetVolumeInfo(FSP_FILE_SYSTEM*, FSP_FSCTL_VOLUME_INFO* VolumeInfo) {
    std::memset(VolumeInfo, 0, sizeof(*VolumeInfo));
    VolumeInfo->TotalSize = 16ULL * 1024 * 1024 * 1024;
    VolumeInfo->FreeSize  = 0;
    const wchar_t* Label  = L"MemNixFS";
    VolumeInfo->VolumeLabelLength = (UINT16)(wcslen(Label) * sizeof(WCHAR));
    std::memcpy(VolumeInfo->VolumeLabel, Label, VolumeInfo->VolumeLabelLength);
    return STATUS_SUCCESS;
}

NTSTATUS GetSecurityByName(FSP_FILE_SYSTEM* FileSystem,
                           PWSTR FileName, PUINT32 PFileAttributes,
                           PSECURITY_DESCRIPTOR SecurityDescriptor,
                           SIZE_T* PSecurityDescriptorSize)
{
    auto* lf = static_cast<LmpfsFs*>(FileSystem->UserContext);
    auto n = ResolvePath(lf, FileName);
    if (!n) return STATUS_OBJECT_NAME_NOT_FOUND;

    if (PFileAttributes)
        *PFileAttributes = n->is_dir()
            ? FILE_ATTRIBUTE_DIRECTORY
            : (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_NORMAL);

    if (PSecurityDescriptorSize) {
        SIZE_T need = lf->DefaultSd.size();
        if (need > *PSecurityDescriptorSize) {
            *PSecurityDescriptorSize = need;
            return STATUS_BUFFER_OVERFLOW;
        }
        *PSecurityDescriptorSize = need;
        if (SecurityDescriptor)
            std::memcpy(SecurityDescriptor, lf->DefaultSd.data(), need);
    }
    return STATUS_SUCCESS;
}

NTSTATUS Create(FSP_FILE_SYSTEM*, PWSTR, UINT32, UINT32, UINT32,
                PSECURITY_DESCRIPTOR, UINT64, PVOID*, FSP_FSCTL_FILE_INFO*)
{
    return STATUS_INVALID_DEVICE_REQUEST;  // read-only
}

NTSTATUS Open(FSP_FILE_SYSTEM* FileSystem, PWSTR FileName,
              UINT32 /*CreateOptions*/, UINT32 /*GrantedAccess*/,
              PVOID* PFileContext, FSP_FSCTL_FILE_INFO* FileInfo)
{
    auto* lf = static_cast<LmpfsFs*>(FileSystem->UserContext);
    auto n = ResolvePath(lf, FileName);
    if (!n) return STATUS_OBJECT_NAME_NOT_FOUND;
    // Pass the raw Node* — it stays valid for the lifetime of the mount.
    *PFileContext = n.get();
    FillFileInfo(n, FileInfo);
    return STATUS_SUCCESS;
}

NTSTATUS Overwrite(FSP_FILE_SYSTEM*, PVOID, UINT32, BOOLEAN, UINT64,
                   FSP_FSCTL_FILE_INFO*)
{
    return STATUS_INVALID_DEVICE_REQUEST;
}

VOID Cleanup(FSP_FILE_SYSTEM*, PVOID, PWSTR, ULONG) { }

// FileContext is a non-owning Node*: no deletion needed.
VOID Close(FSP_FILE_SYSTEM*, PVOID /*FileContext*/) { }

NTSTATUS Read(FSP_FILE_SYSTEM*, PVOID FileContext, PVOID Buffer,
              UINT64 Offset, ULONG Length, PULONG PBytesTransferred)
{
    Node* node = ctx_node(FileContext);
    if (!node || !node->is_file()) return STATUS_INVALID_DEVICE_REQUEST;
    auto t0 = GetTickCount64();
    try {
        UINT64 size = node->size();
        if (Offset >= size) {
            *PBytesTransferred = 0;
            return STATUS_END_OF_FILE;
        }
        // Cap Length to what's actually inside the file. This is what every
        // sane Windows file driver does; HxD-style readers issue reads that
        // straddle EOF on sector-aligned chunks and expect the FS to return
        // exactly (size - Offset) bytes for the tail.
        ULONG cap = (ULONG)std::min<UINT64>(Length, size - Offset);
        std::size_t got = node->read(Offset, Buffer, cap);

        // If the producer underdelivered (returned fewer bytes than the
        // capped length), zero-fill the gap. Otherwise WinFsp+HxD see a
        // partial read inside the file body and surface a "stream read
        // error" — even though the user-visible file size says the bytes
        // should be there. This matches sparse-file semantics: gaps in
        // the page cache read as zeros, not as I/O failures.
        if (got < cap) {
            std::memset(static_cast<u8*>(Buffer) + got, 0, cap - got);
            got = cap;
        }
        *PBytesTransferred = (ULONG)got;
        auto dt = GetTickCount64() - t0;
        if (dt > 200) {
            log::info("[WinFsp] Read '{}' off={:#x} len={} took {}ms",
                      node->name(), Offset, Length, dt);
        }
        return STATUS_SUCCESS;
    } catch (const std::exception& e) {
        log::warn("[WinFsp] Read threw for '{}': {}", node->name(), e.what());
        *PBytesTransferred = 0;
        return STATUS_IO_DEVICE_ERROR;
    }
}

NTSTATUS GetFileInfo(FSP_FILE_SYSTEM*, PVOID FileContext, FSP_FSCTL_FILE_INFO* FileInfo) {
    Node* node = ctx_node(FileContext);
    if (!node) return STATUS_INVALID_DEVICE_REQUEST;
    // We need a NodePtr for FillFileInfo's interface. Wrap with a no-op
    // deleter so refcount manipulation doesn't free.
    auto guard = std::shared_ptr<Node>(node, [](Node*){});
    FillFileInfo(guard, FileInfo);
    return STATUS_SUCCESS;
}

NTSTATUS GetSecurity(FSP_FILE_SYSTEM* FileSystem, PVOID /*FileContext*/,
                     PSECURITY_DESCRIPTOR SecurityDescriptor,
                     SIZE_T* PSecurityDescriptorSize)
{
    auto* lf = static_cast<LmpfsFs*>(FileSystem->UserContext);
    SIZE_T need = lf->DefaultSd.size();
    if (PSecurityDescriptorSize) {
        if (need > *PSecurityDescriptorSize) {
            *PSecurityDescriptorSize = need;
            return STATUS_BUFFER_OVERFLOW;
        }
        *PSecurityDescriptorSize = need;
        if (SecurityDescriptor)
            std::memcpy(SecurityDescriptor, lf->DefaultSd.data(), need);
    }
    return STATUS_SUCCESS;
}

NTSTATUS ReadDirectory(FSP_FILE_SYSTEM*, PVOID FileContext, PWSTR /*Pattern*/,
                       PWSTR Marker, PVOID Buffer, ULONG BufferLength,
                       PULONG PBytesTransferred)
{
    Node* node = ctx_node(FileContext);
    if (!node || !node->is_dir()) return STATUS_INVALID_DEVICE_REQUEST;
    auto entries = node->list();
    bool past = (Marker == nullptr);
    union {
        UINT8 Buf[sizeof(FSP_FSCTL_DIR_INFO) + 512 * sizeof(WCHAR)];
        FSP_FSCTL_DIR_INFO Di;
    } U;
    for (auto& e : entries) {
        std::wstring wname = W(e.name);
        if (!past) {
            if (wname == Marker) past = true;
            continue;
        }
        std::memset(&U, 0, sizeof(U));
        U.Di.Size = (UINT16)(sizeof(FSP_FSCTL_DIR_INFO) + wname.size() * sizeof(WCHAR));
        FillFileInfo(e.node, &U.Di.FileInfo, /*cheap=*/true);
        std::memcpy(U.Di.FileNameBuf, wname.data(), wname.size() * sizeof(WCHAR));
        if (!FspFileSystemAddDirInfo(&U.Di, Buffer, BufferLength, PBytesTransferred))
            return STATUS_SUCCESS;
    }
    FspFileSystemAddDirInfo(nullptr, Buffer, BufferLength, PBytesTransferred);
    return STATUS_SUCCESS;
}

// Interface — positional initializer, no designated init (works in C++17).
// Order matches FSP_FILE_SYSTEM_INTERFACE in winfsp.h (v2.1).
static FSP_FILE_SYSTEM_INTERFACE LmpfsInterface = {
    GetVolumeInfo,       // 1  GetVolumeInfo
    nullptr,             // 2  SetVolumeLabel
    GetSecurityByName,   // 3  GetSecurityByName
    Create,              // 4  Create
    Open,                // 5  Open
    Overwrite,           // 6  Overwrite
    Cleanup,             // 7  Cleanup
    Close,               // 8  Close
    Read,                // 9  Read
    nullptr,             // 10 Write
    nullptr,             // 11 Flush
    GetFileInfo,         // 12 GetFileInfo
    nullptr,             // 13 SetBasicInfo
    nullptr,             // 14 SetFileSize
    nullptr,             // 15 CanDelete
    nullptr,             // 16 Rename
    GetSecurity,         // 17 GetSecurity
    nullptr,             // 18 SetSecurity
    ReadDirectory,       // 19 ReadDirectory
};

bool preload_winfsp_dll() {
    const wchar_t* paths[] = {
        L"C:/Program Files (x86)/WinFsp/bin/winfsp-x64.dll",
        L"C:/Program Files/WinFsp/bin/winfsp-x64.dll",
    };
    for (auto p : paths) {
        if (LoadLibraryW(p)) return true;
    }
    return false;
}

std::vector<uint8_t> build_default_sd() {
    PSECURITY_DESCRIPTOR psd = nullptr;
    ULONG size = 0;
    LPCWSTR sddl = L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)";
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, &psd, &size)) {
        return {};
    }
    std::vector<uint8_t> v(reinterpret_cast<uint8_t*>(psd),
                            reinterpret_cast<uint8_t*>(psd) + size);
    LocalFree(psd);
    return v;
}

NTSTATUS CreateLmpfs(Engine* engine, PWSTR MountPoint, LmpfsFs** PLmpfs) {
    *PLmpfs = nullptr;

    auto* lf = new LmpfsFs();
    lf->Engine = engine;
    lf->DefaultSd = build_default_sd();
    if (lf->DefaultSd.empty()) { delete lf; return STATUS_UNSUCCESSFUL; }

    FSP_FSCTL_VOLUME_PARAMS p{};
    p.SectorSize                  = 4096;
    p.SectorsPerAllocationUnit    = 1;
    p.VolumeCreationTime          = 0;
    p.VolumeSerialNumber          = 0;
    p.FileInfoTimeout             = 1000;
    p.CaseSensitiveSearch         = 0;
    p.CasePreservedNames          = 1;
    p.UnicodeOnDisk               = 1;
    p.PersistentAcls              = 0;
    p.PostCleanupWhenModifiedOnly = 1;
    wcscpy_s(p.FileSystemName, sizeof p.FileSystemName / sizeof(WCHAR), L"LMPFS");

    NTSTATUS s = FspFileSystemCreate(
        const_cast<PWSTR>(L"" FSP_FSCTL_DISK_DEVICE_NAME),
        &p, &LmpfsInterface, &lf->FileSystem);
    if (!NT_SUCCESS(s)) { delete lf; return s; }
    lf->FileSystem->UserContext = lf;

    // WinFsp's per-IRP debug trace (>>QueryDirectory / <<QueryDirectory …) is
    // a firehose — it floods the console on any directory browse. Only enable
    // it at TRACE verbosity (-vv); otherwise keep it off.
    FspFileSystemSetDebugLog(lf->FileSystem,
                             log::level() <= log::Level::Trace ? -1 : 0);

    s = FspFileSystemSetMountPoint(lf->FileSystem, MountPoint);
    if (!NT_SUCCESS(s)) {
        FspFileSystemDelete(lf->FileSystem);
        delete lf;
        return s;
    }

    *PLmpfs = lf;
    return STATUS_SUCCESS;
}

} // anonymous

int run_winfsp_mount(Engine& engine, const std::string& mount_point) {
    if (!preload_winfsp_dll()) {
        log::error("Cannot load winfsp-x64.dll");
        return 1;
    }
    FspDebugLogSetHandle(GetStdHandle(STD_ERROR_HANDLE));

    std::wstring wmount = W(mount_point);

    LmpfsFs* lf = nullptr;
    NTSTATUS s = CreateLmpfs(&engine, const_cast<PWSTR>(wmount.c_str()), &lf);
    if (!NT_SUCCESS(s)) {
        log::error("CreateLmpfs failed: {:#x}", (unsigned)s);
        return 1;
    }

    s = FspFileSystemStartDispatcher(lf->FileSystem, 0);
    if (!NT_SUCCESS(s)) {
        log::error("FspFileSystemStartDispatcher failed: {:#x}", (unsigned)s);
        FspFileSystemDelete(lf->FileSystem);
        delete lf;
        return 1;
    }

    log::note("Mounted at {}; press Ctrl+C to unmount.", mount_point);
    while (true) Sleep(1000);
}

} // namespace lmpfs::mount

#endif // LMPFS_HAS_WINFSP
