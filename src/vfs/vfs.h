#pragma once
#include "core/types.h"
#include "core/stream.h"
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

namespace lmpfs::vfs {

class Node;
using NodePtr = std::shared_ptr<Node>;

// Lazy producer of file contents.
using FileProducer = std::function<ByteBuf()>;

// Static descriptor of a file's cost profile, set at its registration site.
// Tags DESCRIBE the file; the warm policy (in ForensicWarmer) DECIDES what to
// preload — currently `compute == Expensive && mem == Small`. Keeping the two
// separate lets the policy evolve without re-tagging every file.
struct FileCost {
    // Trivial: producing the whole file is so cheap (a few struct reads) that
    // it's fine to run during a directory listing, so the file shows its REAL
    // size in Explorer instead of 0. Cheap: not worth warming, but not safe to
    // run per-listing. Expensive: warm-worthy (and never run during listing).
    enum class Compute { Trivial, Cheap, Expensive };
    enum class Mem     { Small, Large };
    // Forensic categories the user can include/exclude. `None` files are never
    // warmed (no category assigned). SystemInfo is always-on within any mode;
    // ThreatHunt / PerProcess / Yara are individually toggleable.
    enum class Category { None, SystemInfo, ThreatHunt, PerProcess, Yara };

    Compute  compute  = Compute::Cheap;
    Mem      mem      = Mem::Small;
    Category category = Category::None;

    // True when this file is worth warming at all: costly to compute but cheap
    // to keep resident. (The forensic warmer additionally filters by category.)
    bool worth_warming() const {
        return compute == Compute::Expensive && mem == Mem::Small;
    }
    // True when size() is cheap enough to resolve during a directory listing.
    bool cheap_to_size() const {
        return compute == Compute::Trivial && mem == Mem::Small;
    }
};

// Bitmask over FileCost::Category, used by the forensic warmer to decide which
// categories to warm. Bit N == category (int)N enabled.
inline constexpr unsigned warm_bit(FileCost::Category c) {
    return 1u << static_cast<unsigned>(c);
}

struct DirEntry {
    std::string name;
    NodePtr     node;
};

class Node : public std::enable_shared_from_this<Node> {
public:
    enum class Kind { Dir, File };
    Node(std::string name, Kind k) : name_(std::move(name)), kind_(k) {}
    virtual ~Node() = default;

    const std::string& name() const { return name_; }
    Kind kind() const { return kind_; }
    bool is_dir()  const { return kind_ == Kind::Dir; }
    bool is_file() const { return kind_ == Kind::File; }

    // Cost profile (default: cheap+small → never warmed). Lazy file nodes set
    // this from their constructor; the forensic warmer reads it.
    const FileCost& cost() const { return cost_; }
    void set_cost(FileCost c) { cost_ = c; }   // bulk-tagging helper

    // Force the lazy producer to run now and cache the result, if this node
    // has one and hasn't loaded yet. No-op for non-lazy nodes. Used by the
    // forensic warmer to pre-populate caches off the mount thread.
    virtual void warm() {}

    // True if a full `--precompute` pass should warm (produce + cache) this
    // node. Plain derived/analysis files (LazyFileNode) say yes — that's what
    // otherwise shows 0 in a listing and recomputes on open. Two kinds say no:
    //   * streaming nodes (/mem/phys.raw, proc.dmp): unbounded, never resident;
    //   * self-sizing recovered-file nodes (/files, /fs SizedLazyFileNode):
    //     they already report a real size cheaply, and bulk-warming them would
    //     re-extract the entire page cache into RAM — their content streams on
    //     open instead.
    virtual bool warmable() const { return false; }

    // Directory ops
    virtual std::vector<DirEntry> list();
    virtual NodePtr               find(const std::string& name);

    // File ops
    virtual u64 size();
    virtual std::size_t read(u64 offset, void* out, std::size_t len);

    // Cheap, best-effort size for directory listings. MUST NOT run a lazy
    // producer — it's called for every child during a folder enumeration, so
    // making it expensive turns "browse a folder" into "process every file".
    // Default: defer to size() (fine for cheap/stream nodes); lazy nodes
    // override to return their cached size or 0 without producing.
    virtual u64 size_hint() { return size(); }

    std::chrono::system_clock::time_point ctime() const { return ctime_; }

protected:
    std::string                            name_;
    Kind                                   kind_;
    FileCost                               cost_{};
    std::chrono::system_clock::time_point  ctime_ = std::chrono::system_clock::now();
};

// In-memory directory: holds a fixed list of children with UNIQUE names.
//
// Name uniqueness is a hard invariant, not a nicety: WinFsp enumerates a
// directory in pages, resuming each page from a "marker" (the last name it
// emitted). If two children share a name, the resume always re-matches the
// FIRST one and re-emits the span between the duplicates forever — an infinite
// QueryDirectory loop. `add()` therefore drops a child whose name already
// exists (keep-first), enforced in O(1) via a name set.
class DirNode : public Node {
public:
    explicit DirNode(std::string name) : Node(std::move(name), Kind::Dir) {}
    void add(NodePtr child) {
        if (!child) return;
        if (!names_.insert(child->name()).second) return;   // dup name → keep first
        children_.push_back(std::move(child));
    }
    // Return the child directory of this name, creating it if absent. If a
    // NON-directory child of that name already exists, REPLACE it with a
    // directory: a path component must be a directory, and in reconstructed
    // dcache data a file-vs-dir name clash resolves in favour of the dir
    // (which can hold descendants) so we don't drop the whole subtree.
    std::shared_ptr<DirNode> ensure_dir_child(const std::string& name);
    std::vector<DirEntry> list() override;
    NodePtr               find(const std::string& name) override;
protected:
    std::vector<NodePtr>            children_;
    std::unordered_set<std::string> names_;
};

// Lazy file: contents produced on first read, then cached.
// Thread-safe: the forensic warm pool and WinFsp dispatcher threads may hit
// the same node concurrently, so load is guarded by a per-node mutex.
class LazyFileNode : public Node {
public:
    LazyFileNode(std::string name, FileProducer p, FileCost cost = {})
        : Node(std::move(name), Kind::File), producer_(std::move(p)) {
        cost_ = cost;
    }
    u64 size() override;
    // Cheap: never runs the producer. Returns the cached size if already
    // loaded, else 0 — so directory listings don't trigger production.
    u64 size_hint() override;
    std::size_t read(u64 offset, void* out, std::size_t len) override;
    void warm() override { ensure_loaded(); }
    bool warmable() const override { return true; }
private:
    void ensure_loaded();
    std::mutex   mu_;
    FileProducer producer_;
    ByteBuf      data_;
    bool         loaded_ = false;
};

// Same as LazyFileNode but with a separately-supplied cheap size estimator.
// Use this for files whose `size()` would otherwise force a costly producer
// run during a directory listing (e.g. multi-MB ELF cores).
// Thread-safe: WinFsp dispatchers may hit the same node concurrently.
class SizedLazyFileNode : public Node {
public:
    using SizeFn = std::function<u64()>;
    SizedLazyFileNode(std::string name, SizeFn size_fn, FileProducer p,
                      FileCost cost = {})
        : Node(std::move(name), Kind::File)
        , size_fn_(std::move(size_fn))
        , producer_(std::move(p)) {
        cost_ = cost;
    }
    u64 size() override;
    // size() is already cheap here (uses size_fn_), so the default
    // size_hint()==size() is fine — no override needed.
    std::size_t read(u64 offset, void* out, std::size_t len) override;
    void warm() override {
        std::lock_guard<std::mutex> lk(data_mu_);
        ensure_loaded();
    }
    // NOT warmed by --precompute: size() is already cheap (size_fn_), so these
    // never show 0 in a listing, and warming every recovered file would pull
    // the whole page cache into RAM. Content is produced on open instead.
    bool warmable() const override { return false; }
private:
    void ensure_loaded();           // caller must hold data_mu_
    std::mutex   size_mu_;
    std::mutex   data_mu_;
    SizeFn       size_fn_;
    FileProducer producer_;
    ByteBuf      data_;
    bool         size_cached_ = false;
    u64          cached_size_ = 0;
    bool         data_loaded_ = false;
};

// Streaming file: delegates `size()` and `read()` to a StreamReader, never
// materializes the full contents. Use for huge or unboundedly-large files
// (proc.dmp, /mem/phys.raw, etc.). The same StreamReader instance is shared
// across all opens — concurrent dispatcher threads will hit it, so it must
// be thread-safe.
class StreamFileNode : public Node {
public:
    StreamFileNode(std::string name, StreamReaderPtr reader)
        : Node(std::move(name), Kind::File), reader_(std::move(reader)) {}
    u64 size() override { return reader_->size(); }
    std::size_t read(u64 offset, void* out, std::size_t len) override {
        return reader_->read(offset, out, len);
    }
private:
    StreamReaderPtr reader_;
};

// Resolves "/a/b/c" against a root node. Throws Error on missing path.
NodePtr resolve(const NodePtr& root, const std::string& path);

} // namespace lmpfs::vfs

namespace lmpfs {
// Forward declarations used by proc_module.cpp.
class PhysicalLayer;
class IsfSymbols;
class Engine;
namespace x86_64 { class PageTable; }
namespace linux { struct KernelContext; struct Process; }

namespace vfs {
// Builds the /proc/ subtree for the given list of processes.
// `eng` is used by per-pid producers that need the multi-strategy
// kernel-VA reader (fd_table, bash_history). It must outlive the tree.
NodePtr build_proc_tree(const std::vector<lmpfs::linux::Process>& processes,
                        const PhysicalLayer&     phys,
                        const x86_64::PageTable& pt,
                        const IsfSymbols&        isf,
                        const lmpfs::linux::KernelContext& kctx,
                        const Engine&            eng);
}
} // namespace lmpfs
