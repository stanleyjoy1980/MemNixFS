// pagecache.h — Linux page-cache enumeration & file-content recovery.
//
// What this does (and why it's a big forensic win):
//
//   `task->files->fdt->fd[]` only shows files that some live process holds
//   open *right now*. Everything else — scripts a defunct cron job ran an
//   hour ago, the bash history of a user who SSH'd out, dropped malware,
//   config snapshots, log lines that were paged in but the writer has long
//   since exited — lives only in the page cache, behind no fd.
//
//   We walk `super_blocks` → `s_inodes` to enumerate every inode the kernel
//   has in memory, regardless of whether anything still has it open. For
//   each inode we read its `i_data.i_pages` xarray and pull every cached
//   folio's physical page, reassembling files in offset order.
//
//   This mirrors Volatility 3's `linux.pagecache.{Files,RecoverFs,InodePages}`
//   and MemProcFS' file-cache exposure under `/files/`.
//
// Caveats:
//   * Anonymous inodes (sockets, pipes, anon_inode files) have no path.
//   * Sparse recovery: pages absent from the page cache come back as zeros
//     in the byte stream for mount/read stability. Those zeros are synthetic
//     unless RecoveredFileStats says the range was complete.
//   * Pages may be partially overwritten by reuse — we trust whatever the
//     page-cache xarray currently points at, the way `cat /proc/.../mem`
//     would.
//   * Modern (≥ 5.18) kernels use folios, which are multi-page; we honour
//     `folio_order` so high-order folios contribute all their pages.
//
#pragma once
#include "core/types.h"
#include "core/stream.h"
#include <string>
#include <vector>

namespace lmpfs {
class Engine;
}

namespace lmpfs::linux {

struct CachedInode {
    VAddr  inode_va     = 0;
    u64    i_ino        = 0;        // inode number
    u64    i_size       = 0;        // file size (bytes) per inode
    u16    i_mode       = 0;        // POSIX type + perms
    u32    i_state      = 0;        // I_DIRTY/I_NEW/I_WILL_FREE/I_FREEING/...
    u64    nr_cached    = 0;        // pages held in page cache
    VAddr  sb_va        = 0;        // owning super_block
    std::string sb_fs   {};         // file_system_type.name (e.g. "ext4")
    std::string path    {};         // resolved absolute path (empty for orphans)
};

struct RecoveredRange {
    u64 offset = 0;
    u64 length = 0;
};

struct RecoveredFileStats {
    u64 logical_size = 0;
    u64 expected_pages = 0;
    u64 xarray_pages_seen = 0;
    u64 pages_within_size = 0;
    u64 pages_copied = 0;
    u64 pages_dropped = 0;
    u64 bytes_copied = 0;
    u64 missing_ranges_total = 0;
    u64 dropped_ranges_total = 0;
    bool physical_reads_checked = false;
    bool missing_ranges_truncated = false;
    bool dropped_ranges_truncated = false;
    std::vector<RecoveredRange> missing_ranges;
    std::vector<RecoveredRange> dropped_ranges;

    bool complete() const {
        return logical_size > 0 &&
               expected_pages > 0 &&
               missing_ranges_total == 0 &&
               dropped_ranges_total == 0 &&
               physical_reads_checked &&
               pages_dropped == 0 &&
               pages_copied == expected_pages &&
               bytes_copied == logical_size;
    }
};

struct RecoveredFile {
    ByteBuf bytes;
    RecoveredFileStats stats;
};

struct SymlinkTarget {
    bool ok = false;
    std::string target;
    std::string source;
    std::string reason;
};

struct PathTrust {
    bool ok = false;
    std::string reason;
};

// I_WILL_FREE (bit 4) | I_FREEING (bit 5) — set during inode teardown.
// Used as a "deleted" heuristic: when a file is unlink()'d while still
// referenced, the inode lingers in cache with these bits set.
inline bool inode_is_dying(const CachedInode& ci) {
    return (ci.i_state & 0x30) != 0;
}

// Heuristic for "no global path resolvable" — covers anonymous inodes
// (sockets/pipes/anon_inode), deleted-but-cached files whose dentry is
// gone, and inodes from filesystems we couldn't resolve a vfsmount for.
inline bool inode_is_orphan(const CachedInode& ci) {
    return ci.path.empty() || ci.path == "/" ||
           ci.path == "(null)" || ci.path[0] != '/';
}

// Snapshot of all inodes the kernel has in memory, across every mounted fs.
// Empty if `super_blocks` symbol or required struct fields aren't in the ISF.
std::vector<CachedInode> enumerate_cached_inodes(const Engine& eng);

// Pretty-printed listing of every cached inode. One row per inode:
//   <ino> <type> <perms> <size> <nrpages>  <fs>  <path>
ByteBuf format_pagecache_index(const Engine& eng);
PathTrust validate_recovered_fs_path(const std::string& path);
ByteBuf format_pagecache_path_quality(const Engine& eng);

// Reconstruct a file's contents from its page cache. Pages not currently
// cached come back as zero-filled for stream compatibility. Use
// recover_file_with_stats when the caller will make forensic claims.
ByteBuf recover_file(const Engine& eng, const CachedInode& ino);
RecoveredFile recover_file_with_stats(const Engine& eng, const CachedInode& ino);
RecoveredFileStats recover_file_stats(const Engine& eng, const CachedInode& ino,
                                      bool check_physical = false);
std::string describe_recovered_file_state(const RecoveredFileStats& st);
ByteBuf format_pagecache_recovery(const Engine& eng);
SymlinkTarget recover_symlink_target(const Engine& eng, const CachedInode& ino);

// Size estimate without materialising the buffer — for VFS `size()` queries.
// Returns the inode's i_size clamped to the highest cached offset.
u64 recover_file_size(const Engine& eng, const CachedInode& ino);

// Filesystem MAC times read straight from a cached `struct inode`. Each value
// is Unix seconds (UTC). Handles both the modern split layout (6.11+:
// `i_atime_sec`/`i_mtime_sec`/`__i_ctime_sec`) and the older `struct timespec64`
// fields (`i_atime`/`i_mtime`/`i_ctime`/`__i_ctime`, tv_sec at offset 0). These
// feed the forensic timeline (filesystem MAC timeline). `ok` is false if no
// time field could be resolved/read.
struct InodeMacTimes {
    bool ok    = false;
    i64  atime = 0;   // last access
    i64  mtime = 0;   // last data modification
    i64  ctime = 0;   // last inode (metadata) change
};
InodeMacTimes read_inode_mac_times(const Engine& eng, VAddr inode_va);

} // namespace lmpfs::linux
