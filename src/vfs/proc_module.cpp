#include "vfs/vfs.h"
#include "app/engine.h"
#include "os/linux/process.h"
#include "os/linux/kernel_resolver.h"
#include "os/linux/vma.h"
#include "os/linux/elf_core.h"
#include "os/linux/elf_core_stream.h"
#include "os/linux/task_files.h"
#include "os/linux/fdtable.h"
#include "os/linux/bash_history.h"
#include "os/linux/findevil.h"
#include "os/linux/pscallstack.h"
#include "os/linux/threads.h"
#include "os/linux/entropy.h"
#include "os/linux/strings_search.h"
#include "os/linux/task_extras.h"
#include "os/linux/yara_search.h"
#include "arch/x86_64/paging.h"
#include "symbols/isf_symbols.h"
#include "formats/physical_layer.h"
#include <fmt/format.h>
#include <memory>

namespace lmpfs::vfs {

namespace {

// Cost tags for forensic-mode warming. Expensive+Small files are warmed in the
// background; Large files stay lazy (memory); cheap files don't need warming.
// The Category lets the user include/exclude groups (--forensic-include/exclude).
constexpr FileCost kPerProc{ FileCost::Compute::Expensive, FileCost::Mem::Small,
                             FileCost::Category::PerProcess };
constexpr FileCost kYara{ FileCost::Compute::Expensive, FileCost::Mem::Small,
                          FileCost::Category::Yara };
constexpr FileCost kExpensiveLarge{ FileCost::Compute::Expensive, FileCost::Mem::Large };

const char* vm_flag_str(const linux::Vma& v, char* buf) {
    buf[0] = v.readable()   ? 'r' : '-';
    buf[1] = v.writable()   ? 'w' : '-';
    buf[2] = v.executable() ? 'x' : '-';
    buf[3] = '\0';
    return buf;
}

ByteBuf make_info_txt(const linux::Process& p, std::size_t vma_count, u64 total_user_bytes) {
    auto s = fmt::format(
        "PID:        {}\n"
        "TGID:       {}\n"
        "PPID:       {}\n"
        "COMM:       {}\n"
        "UID:        {}\n"
        "GID:        {}\n"
        "TASK_VA:    {:#x}\n"
        "MM:         {:#x}\n"
        "VMA_COUNT:  {}\n"
        "USERMEM_KB: {}\n",
        p.pid, p.tgid, p.ppid, p.comm, p.uid, p.gid,
        p.task_va, p.mm, vma_count, total_user_bytes / 1024);
    return ByteBuf(s.begin(), s.end());
}

ByteBuf make_memmap_txt(const std::vector<linux::Vma>& vmas) {
    std::string out;
    out.reserve(vmas.size() * 64);
    out += fmt::format("{:>16}  {:>16}  {:>5}  {:>10}  {:>8}\n",
                       "vm_start", "vm_end", "perm", "size_kb", "file?");
    for (auto& v : vmas) {
        char perm[4]; vm_flag_str(v, perm);
        out += fmt::format("{:>16x}  {:>16x}  {:>5}  {:>10}  {:>8}\n",
                           v.vm_start, v.vm_end, perm, v.size() / 1024,
                           v.vm_file ? "yes" : "no");
    }
    return ByteBuf(out.begin(), out.end());
}

std::string sanitize(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '/' || c == '\\' || c == ':' || c == '*' ||
            c == '?' || c == '"' || c == '<' || c == '>' || c == '|' ||
            c < 0x20) out.push_back('_');
        else out.push_back(c);
    }
    if (out.empty()) out = "_";
    return out;
}

// Shared context that the lazy producers can capture cheaply.
struct ProcCtx {
    const PhysicalLayer* phys;
    const IsfSymbols*    isf;
    const linux::KernelContext* kctx;
    const Engine*        eng;        // for fd/ and shell-history recovery
    linux::Process       p;
};

} // anonymous

NodePtr build_proc_tree(const std::vector<linux::Process>&  procs,
                        const PhysicalLayer&                phys,
                        const x86_64::PageTable&            /*kern_pt*/,
                        const IsfSymbols&                   isf,
                        const linux::KernelContext&         kctx,
                        const Engine&                       eng)
{
    auto root = std::make_shared<DirNode>("proc");

    for (const auto& p : procs) {
        auto ctx = std::make_shared<ProcCtx>(ProcCtx{ &phys, &isf, &kctx, &eng, p });
        auto folder_name = fmt::format("{}-{}", p.pid, sanitize(p.comm));
        auto dir = std::make_shared<DirNode>(folder_name);

        // Forensic warming is scoped to real user processes. Kernel threads
        // (mm == 0) have no address space / open files, so warming their
        // per-task files is mostly pointless work — tag those as cheap so the
        // warmer skips them. Files that only exist when mm != 0 (malfind,
        // entropy, yara, …) already can't appear for kernel threads.
        const FileCost procWarm = (p.mm != 0) ? kPerProc : FileCost{};

        // info.txt — populated lazily so VMA enumeration only happens on first read.
        dir->add(std::make_shared<LazyFileNode>("info.txt", [ctx]() {
            std::size_t vma_count = 0;
            u64 user_bytes = 0;
            if (ctx->p.mm) {
                auto vmas = linux::enumerate_vmas(*ctx->phys, *ctx->isf, *ctx->kctx, ctx->p);
                vma_count = vmas.size();
                for (auto& v : vmas) user_bytes += v.size();
            }
            return make_info_txt(ctx->p, vma_count, user_bytes);
        }));

        // memmap.txt — our pretty VMA table (kept for human-readable view).
        dir->add(std::make_shared<LazyFileNode>("memmap.txt", [ctx]() {
            if (!ctx->p.mm) return ByteBuf{};
            auto vmas = linux::enumerate_vmas(*ctx->phys, *ctx->isf, *ctx->kctx, ctx->p);
            return make_memmap_txt(vmas);
        }));

        // ----- Per-process Linux-compatible files. Each one is lazy; they only touch
        // memory on first read.
        dir->add(std::make_shared<LazyFileNode>("cmdline", [ctx]() {
            return linux::gen_cmdline(*ctx->phys, *ctx->isf, *ctx->kctx, ctx->p);
        }));
        auto environ_node = std::make_shared<LazyFileNode>("environ", [ctx]() {
            return linux::gen_environ(*ctx->phys, *ctx->isf, *ctx->kctx, ctx->p);
        });
        dir->add(environ_node);
        dir->add(std::make_shared<LazyFileNode>("comm", [ctx]() {
            return linux::gen_comm(ctx->p);
        }));
        dir->add(std::make_shared<LazyFileNode>("maps", [ctx]() {
            if (!ctx->p.mm) return ByteBuf{};
            auto vmas = linux::enumerate_vmas(*ctx->phys, *ctx->isf, *ctx->kctx, ctx->p);
            return linux::gen_maps(vmas);
        }));
        dir->add(std::make_shared<LazyFileNode>("status", [ctx]() {
            return linux::gen_status(*ctx->phys, *ctx->isf, *ctx->kctx, ctx->p);
        }));
        dir->add(std::make_shared<LazyFileNode>("stat", [ctx]() {
            return linux::gen_stat(*ctx->phys, *ctx->isf, *ctx->kctx, ctx->p);
        }));
        dir->add(std::make_shared<LazyFileNode>("statm", [ctx]() {
            return linux::gen_statm(*ctx->phys, *ctx->isf, *ctx->kctx, ctx->p);
        }));
        dir->add(std::make_shared<LazyFileNode>("limits", [ctx]() {
            return linux::gen_limits(*ctx->phys, *ctx->isf, *ctx->kctx, ctx->p);
        }));
        dir->add(std::make_shared<LazyFileNode>("loginuid", [ctx]() {
            return linux::gen_loginuid(*ctx->phys, *ctx->isf, *ctx->kctx, ctx->p);
        }));
        dir->add(std::make_shared<LazyFileNode>("oom_score_adj", [ctx]() {
            return linux::gen_oom_score_adj(*ctx->phys, *ctx->isf, *ctx->kctx, ctx->p);
        }));
        dir->add(std::make_shared<LazyFileNode>("exe", [ctx]() {
            return linux::gen_exe(*ctx->phys, *ctx->isf, *ctx->kctx, ctx->p);
        }));
        dir->add(std::make_shared<LazyFileNode>("cwd", [ctx]() {
            return linux::gen_cwd(*ctx->phys, *ctx->isf, *ctx->kctx, ctx->p);
        }));
        dir->add(std::make_shared<LazyFileNode>("root", [ctx]() {
            return linux::gen_root(*ctx->phys, *ctx->isf, *ctx->kctx, ctx->p);
        }));
        dir->add(std::make_shared<LazyFileNode>("capabilities", [ctx]() {
            return linux::gen_capabilities(*ctx->phys, *ctx->isf, *ctx->kctx, ctx->p);
        }));

        // fd_table.txt — file-descriptor listing. Walks `task->files->fdt->fd[]`
        // and resolves each open struct file's dentry to a path. For
        // non-file fds (sockets, pipes, anon_inode) we emit a placeholder.
        auto fd_table_node = std::make_shared<LazyFileNode>("fd_table.txt", [ctx]() {
            return linux::format_fd_table(*ctx->eng, ctx->p);
        }, procWarm);
        dir->add(fd_table_node);

        // bash_history — recovered shell-history entries from heap. Empty
        // for non-bash processes. Vol3-style HIST_ENTRY heuristic scan.
        if (ctx->p.mm != 0) {
            dir->add(std::make_shared<LazyFileNode>("shell_history.txt", [ctx]() {
                return linux::format_shell_history(*ctx->eng, ctx->p);
            }, procWarm));
        }

        // malfind.txt — per-process suspicious-VMA list (RWX anonymous
        // mappings, etc.). Only present for processes with an mm.
        if (ctx->p.mm != 0) {
            dir->add(std::make_shared<LazyFileNode>("malfind.txt", [ctx]() {
                return linux::format_proc_malfind(*ctx->eng, ctx->p);
            }, kPerProc));
            // entropy.txt — Shannon entropy of every exec VMA. High entropy
            // (≥ 7.0) suggests packed/encrypted code (UPX, custom packer,
            // injected shellcode).
            dir->add(std::make_shared<LazyFileNode>("entropy.txt", [ctx]() {
                return linux::format_proc_entropy(*ctx->eng, ctx->p);
            }, kPerProc));
            // strings.txt - printable-ASCII strings (>=6 chars) extracted
            // from every scanned readable VMA. No string-count cap; still lazy
            // because output can be large. Analyst can grep it for IOC patterns.
            // NOT warmed: expensive AND large (~250 KB x processes).
            dir->add(std::make_shared<LazyFileNode>("strings.txt", [ctx]() {
                return linux::format_proc_strings(*ctx->eng, ctx->p);
            }, kExpensiveLarge));
            // libs.txt — file-backed VMAs grouped by path. Tier-1 finisher. v0.21
            dir->add(std::make_shared<LazyFileNode>("libs.txt", [ctx]() {
                return linux::gen_libs(*ctx->eng, ctx->p);
            }, kPerProc));
            // yara.txt — per-process YARA scan. Reuses the same default
            // ruleset as /search/yara.txt, scoped to this pid's VMAs. v0.22
            // Its own category so users can --forensic-exclude yara (the
            // single most expensive thing to warm).
            dir->add(std::make_shared<LazyFileNode>("yara.txt", [ctx]() {
                return linux::format_yara_per_pid(*ctx->eng, ctx->p);
            }, kYara));
        }

        // ptrace.txt — ptrace relationships involving this task. Available
        // for every task (kernel threads too — they can be parents).  v0.21
        dir->add(std::make_shared<LazyFileNode>("ptrace.txt", [ctx]() {
            return linux::gen_ptrace(*ctx->eng, ctx->p);
        }, procWarm));

        // kstack.txt — symbolised kernel-stack walk. Shows what kernel
        // functions are on the thread's stack right now ("what was this
        // thread doing at snapshot time?"). Works for both user tasks
        // and kernel threads — anything with a `task->stack` pointer.
        dir->add(std::make_shared<LazyFileNode>("kstack.txt", [ctx]() {
            return linux::format_kstack(*ctx->eng, ctx->p);
        }, procWarm));

        // threads.txt — every thread of this thread group. Walks
        // leader.signal->thread_head; same data as the global
        // /sys/processes/threads.txt but scoped to one leader.
        dir->add(std::make_shared<LazyFileNode>("threads.txt", [ctx]() {
            return linux::format_proc_threads(*ctx->eng, ctx->p);
        }, procWarm));

        // proc.dmp — streaming ELF-core dump. Construction is O(1): we lazily
        // resolve VMAs/PGD only on first access, then keep the ElfCoreStream
        // (which never materializes the whole file) for the life of the mount.
        // Reads pull only the requested byte range, so a 5 GiB process is a
        // 5 GiB file with zero upfront cost.
        //
        // For kernel threads (mm == 0) and PGD-resolution failures we still
        // fall back to a small explanatory text file via LazyFileNode.
        if (p.mm) {
            // Build the stream once (lazy is no longer necessary — the build
            // itself is cheap). We can't construct ElfCoreStream until we have
            // the user PageTable instance because it captures a reference; so
            // we eagerly resolve PGD here, ONCE per process at proc-tree
            // construction.
            PAddr pgd_pa = linux::resolve_user_pgd(phys, isf, kctx, p);
            if (pgd_pa != 0) {
                auto vmas = linux::enumerate_vmas(phys, isf, kctx, p);
                if (!vmas.empty()) {
                    // The PageTable is owned by an aliasing shared_ptr held by
                    // the StreamReader closure so it outlives the proc tree.
                    auto user_pt = std::make_shared<x86_64::PageTable>(phys, pgd_pa);
                    auto stream = std::make_shared<linux::ElfCoreStream>(
                        phys, *user_pt, p, std::move(vmas));
                    // Keep user_pt alive by capturing it alongside.
                    struct Holder : public StreamReader {
                        std::shared_ptr<x86_64::PageTable>      pt;
                        std::shared_ptr<linux::ElfCoreStream>   s;
                        u64 size() const override { return s->size(); }
                        std::size_t read(u64 o, void* b, std::size_t n) override {
                            return s->read(o, b, n);
                        }
                    };
                    auto holder = std::make_shared<Holder>();
                    holder->pt = user_pt;
                    holder->s  = stream;
                    dir->add(std::make_shared<StreamFileNode>("proc.dmp", holder));
                }
            }
        }
        // Kernel threads and PGD-failure cases: dump a tiny explanatory note.
        if (!p.mm || !dir->find("proc.dmp")) {
            dir->add(std::make_shared<LazyFileNode>("proc.dmp", [ctx]() -> ByteBuf {
                std::string s = !ctx->p.mm
                    ? fmt::format("; kernel thread PID {} ({}) has no user memory\n",
                                  ctx->p.pid, ctx->p.comm)
                    : fmt::format("; PID {} ({}): user PGD unavailable\n",
                                  ctx->p.pid, ctx->p.comm);
                return ByteBuf(s.begin(), s.end());
            }));
        }

        root->add(dir);
    }
    return root;
}

} // namespace lmpfs::vfs
