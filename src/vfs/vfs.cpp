#include "vfs/vfs.h"
#include "core/error.h"
#include <algorithm>
#include <cstring>
#include <sstream>

namespace lmpfs::vfs {

std::vector<DirEntry> Node::list() {
    throw_error("Not a directory: {}", name_);
}
NodePtr Node::find(const std::string&) {
    throw_error("Not a directory: {}", name_);
}
u64 Node::size() {
    throw_error("Not a file: {}", name_);
}
std::size_t Node::read(u64, void*, std::size_t) {
    throw_error("Not a file: {}", name_);
}

std::vector<DirEntry> DirNode::list() {
    std::vector<DirEntry> out;
    out.reserve(children_.size());
    for (auto& c : children_) out.push_back({ c->name(), c });
    return out;
}
NodePtr DirNode::find(const std::string& n) {
    for (auto& c : children_) if (c->name() == n) return c;
    return nullptr;
}

std::shared_ptr<DirNode> DirNode::ensure_dir_child(const std::string& name) {
    for (auto& c : children_) {
        if (c->name() == name) {
            if (auto d = std::dynamic_pointer_cast<DirNode>(c)) return d;
            // A non-directory of this name exists — replace it in place with a
            // directory. names_ already contains `name`, so uniqueness holds.
            auto d = std::make_shared<DirNode>(name);
            c = d;
            return d;
        }
    }
    auto d = std::make_shared<DirNode>(name);
    children_.push_back(d);
    names_.insert(name);
    return d;
}

void LazyFileNode::ensure_loaded() {
    // Caller must hold mu_.
    if (!loaded_) { data_ = producer_(); loaded_ = true; }
}
u64 LazyFileNode::size() {
    std::lock_guard<std::mutex> lk(mu_);
    ensure_loaded();
    return data_.size();
}
u64 LazyFileNode::size_hint() {
    // Directory-listing size. If we've already produced the content, report its
    // real size. Otherwise, for files explicitly tagged cheap-to-size, run the
    // (trivial) producer now so the listing shows a real size instead of 0 —
    // the result is cached, so it's a one-time cost. For everything else
    // (Cheap/Expensive producers — VMA walks, YARA, hash-table walks, …) return
    // 0 to keep browsing instant; the real size resolves when the file is opened.
    std::lock_guard<std::mutex> lk(mu_);
    if (loaded_) return data_.size();
    if (cost_.cheap_to_size()) { ensure_loaded(); return data_.size(); }
    return 0;
}
std::size_t LazyFileNode::read(u64 offset, void* out, std::size_t len) {
    std::lock_guard<std::mutex> lk(mu_);
    ensure_loaded();
    if (offset >= data_.size()) return 0;
    std::size_t n = std::min<std::size_t>(len, data_.size() - offset);
    std::memcpy(out, data_.data() + offset, n);
    return n;
}

void SizedLazyFileNode::ensure_loaded() {
    // caller holds data_mu_
    if (!data_loaded_) { data_ = producer_(); data_loaded_ = true; }
}
u64 SizedLazyFileNode::size() {
    std::lock_guard<std::mutex> lk(size_mu_);
    if (!size_cached_) {
        cached_size_ = size_fn_();
        size_cached_ = true;
    }
    return cached_size_;
}
std::size_t SizedLazyFileNode::read(u64 offset, void* out, std::size_t len) {
    std::lock_guard<std::mutex> lk(data_mu_);
    ensure_loaded();
    if (offset >= data_.size()) return 0;
    std::size_t n = std::min<std::size_t>(len, data_.size() - offset);
    std::memcpy(out, data_.data() + offset, n);
    return n;
}

NodePtr resolve(const NodePtr& root, const std::string& path) {
    if (path.empty() || path == "/") return root;
    NodePtr cur = root;
    std::istringstream ss(path);
    std::string part;
    while (std::getline(ss, part, '/')) {
        if (part.empty()) continue;
        if (!cur || !cur->is_dir()) return nullptr;
        cur = cur->find(part);
    }
    return cur;
}

} // namespace lmpfs::vfs
