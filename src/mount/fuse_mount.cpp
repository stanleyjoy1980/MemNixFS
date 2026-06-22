// FUSE read-only filesystem adapter for the MemNixFS VFS.
#ifdef LMPFS_HAS_FUSE

#include "app/engine.h"
#include "core/log.h"
#include "vfs/vfs.h"

#include <fuse.h>
#include <fmt/format.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>
#include <vector>

namespace lmpfs::mount {
namespace {

using vfs::Node;
using vfs::NodePtr;

struct FuseState {
    Engine* engine = nullptr;
};

FuseState* state() {
    return static_cast<FuseState*>(fuse_get_context()->private_data);
}

std::string normalize_path(const char* path) {
    if (!path || !*path) return "/";
    std::string out(path);
    std::replace(out.begin(), out.end(), '\\', '/');
    while (out.size() > 1 && out.back() == '/') out.pop_back();
    return out.empty() ? "/" : out;
}

NodePtr resolve_node(const char* path) {
    auto* st = state();
    if (!st || !st->engine) return {};
    const auto norm = normalize_path(path);
    if (norm == "/") return st->engine->vfs_root();
    return vfs::resolve(st->engine->vfs_root(), norm);
}

void fill_stat(const NodePtr& node, struct stat* stbuf, bool cheap) {
    std::memset(stbuf, 0, sizeof(*stbuf));
    stbuf->st_uid = getuid();
    stbuf->st_gid = getgid();
    stbuf->st_nlink = node->is_dir() ? 2 : 1;
    stbuf->st_ino = static_cast<ino_t>(
        reinterpret_cast<std::uintptr_t>(node.get()) >> 4);
    if (node->is_dir()) {
        stbuf->st_mode = S_IFDIR | 0555;
        stbuf->st_size = 0;
    } else {
        stbuf->st_mode = S_IFREG | 0444;
        try {
            stbuf->st_size = static_cast<off_t>(
                cheap ? node->size_hint() : node->size());
        } catch (const std::exception& e) {
            log::warn("[FUSE] size() threw for '{}': {}", node->name(), e.what());
            stbuf->st_size = 0;
        }
    }
    stbuf->st_blksize = 4096;
    stbuf->st_blocks = (stbuf->st_size + 511) / 512;
}

#if FUSE_USE_VERSION >= 30
int lmpfs_getattr(const char* path, struct stat* stbuf,
                  struct fuse_file_info*) {
#else
int lmpfs_getattr(const char* path, struct stat* stbuf) {
#endif
    try {
        auto node = resolve_node(path);
        if (!node) return -ENOENT;
        fill_stat(node, stbuf, false);
        return 0;
    } catch (const std::exception&) {
        return -ENOENT;
    }
}

int lmpfs_open(const char* path, struct fuse_file_info* fi) {
    try {
        auto node = resolve_node(path);
        if (!node) return -ENOENT;
        if (!node->is_file()) return -EISDIR;
        const int access = static_cast<int>(fi->flags) & O_ACCMODE;
        if (access != O_RDONLY) return -EROFS;
        fi->fh = reinterpret_cast<std::uintptr_t>(node.get());
        return 0;
    } catch (const std::exception&) {
        return -ENOENT;
    }
}

int lmpfs_read(const char*, char* buf, size_t size, off_t offset,
               struct fuse_file_info* fi) {
    auto* node = reinterpret_cast<Node*>(fi->fh);
    if (!node || !node->is_file()) return -EINVAL;
    if (offset < 0) return -EINVAL;
    try {
        const u64 file_size = node->size();
        const auto off = static_cast<u64>(offset);
        if (off >= file_size) return 0;
        const auto cap = static_cast<std::size_t>(
            std::min<u64>(static_cast<u64>(size), file_size - off));
        std::size_t got = node->read(off, buf, cap);
        if (got < cap) {
            std::memset(buf + got, 0, cap - got);
            got = cap;
        }
        return static_cast<int>(got);
    } catch (const std::exception& e) {
        log::warn("[FUSE] read threw for '{}': {}", node->name(), e.what());
        return -EIO;
    }
}

#if FUSE_USE_VERSION >= 30
int lmpfs_readdir(const char* path, void* buf, fuse_fill_dir_t filler,
                  off_t, struct fuse_file_info*,
                  enum fuse_readdir_flags) {
#else
int lmpfs_readdir(const char* path, void* buf, fuse_fill_dir_t filler,
                  off_t, struct fuse_file_info*) {
#endif
    try {
        auto node = resolve_node(path);
        if (!node) return -ENOENT;
        if (!node->is_dir()) return -ENOTDIR;
#if FUSE_USE_VERSION >= 30
        filler(buf, ".", nullptr, 0, static_cast<fuse_fill_dir_flags>(0));
        filler(buf, "..", nullptr, 0, static_cast<fuse_fill_dir_flags>(0));
#else
        filler(buf, ".", nullptr, 0);
        filler(buf, "..", nullptr, 0);
#endif
        for (const auto& e : node->list()) {
            struct stat st {};
            fill_stat(e.node, &st, true);
#if FUSE_USE_VERSION >= 30
            if (filler(buf, e.name.c_str(), &st, 0,
                       static_cast<fuse_fill_dir_flags>(0)) != 0)
                break;
#else
            if (filler(buf, e.name.c_str(), &st, 0) != 0)
                break;
#endif
        }
        return 0;
    } catch (const std::exception&) {
        return -ENOENT;
    }
}

int lmpfs_statfs(const char*, struct statvfs* stbuf) {
    std::memset(stbuf, 0, sizeof(*stbuf));
    stbuf->f_bsize = 4096;
    stbuf->f_frsize = 4096;
    stbuf->f_blocks = (16ULL * 1024 * 1024 * 1024) / 4096;
    stbuf->f_bfree = 0;
    stbuf->f_bavail = 0;
    stbuf->f_files = 1024 * 1024;
    stbuf->f_ffree = 0;
    stbuf->f_namemax = 255;
    return 0;
}

fuse_operations make_ops() {
    fuse_operations ops {};
    ops.getattr = lmpfs_getattr;
    ops.open = lmpfs_open;
    ops.read = lmpfs_read;
    ops.readdir = lmpfs_readdir;
    ops.statfs = lmpfs_statfs;
    return ops;
}

std::vector<char*> build_fuse_argv(const std::string& mount_point) {
    static std::string program = "memnixfs";
    static std::string foreground = "-f";
    static std::string single_thread = "-s";
    static std::string read_only = "-o";
    static std::string opts = "ro,default_permissions";
    static std::string mount;
    mount = mount_point;
    return {
        program.data(),
        foreground.data(),
        single_thread.data(),
        read_only.data(),
        opts.data(),
        mount.data(),
    };
}

} // namespace

int run_fuse_mount(Engine& engine, const std::string& mount_point) {
    FuseState st {};
    st.engine = &engine;
    auto ops = make_ops();
    auto args = build_fuse_argv(mount_point);
    log::note("Mounted at {}; press Ctrl+C to unmount.", mount_point);
    return fuse_main(static_cast<int>(args.size()), args.data(), &ops, &st);
}

} // namespace lmpfs::mount

#endif // LMPFS_HAS_FUSE
