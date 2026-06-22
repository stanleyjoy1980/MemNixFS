#include "os/linux/process.h"
#include "core/error.h"
#include "core/log.h"
#include <cstring>
#include <unordered_set>

namespace lmpfs::linux {

namespace {

struct Offsets {
    u64 pid, tgid, comm, tasks, parent, real_parent, mm, cred;
    u64 cred_uid, cred_gid;
};

Offsets gather_offsets(const IsfSymbols& isf) {
    Offsets o{};
    o.pid          = isf.field_offset("task_struct", "pid");
    o.tgid         = isf.field_offset("task_struct", "tgid");
    o.comm         = isf.field_offset("task_struct", "comm");
    o.tasks        = isf.field_offset("task_struct", "tasks");
    o.parent       = isf.field_offset("task_struct", "parent");
    o.real_parent  = isf.field_offset("task_struct", "real_parent");
    o.mm           = isf.field_offset("task_struct", "mm");
    o.cred         = isf.field_offset("task_struct", "cred");
    o.cred_uid     = isf.field_offset("cred", "uid");
    o.cred_gid     = isf.field_offset("cred", "gid");
    return o;
}

// Translate a kernel-direct-map VA. Returns true if VA falls in [base, base+max).
bool dm_pa(VAddr va, const KernelContext& kctx, PAddr max_pa, PAddr& out) {
    if (va < kctx.direct_map_base) return false;
    u64 off = va - kctx.direct_map_base;
    if (off >= max_pa) return false;
    out = static_cast<PAddr>(off);
    return true;
}

bool read_dm_u32(const PhysicalLayer& phys, const KernelContext& k, VAddr va, u32& v) {
    PAddr pa;
    if (!dm_pa(va, k, phys.max_address(), pa)) return false;
    return phys.read_pod(pa, v);
}
bool read_dm_u64(const PhysicalLayer& phys, const KernelContext& k, VAddr va, u64& v) {
    PAddr pa;
    if (!dm_pa(va, k, phys.max_address(), pa)) return false;
    return phys.read_pod(pa, v);
}
bool read_dm_comm(const PhysicalLayer& phys, const KernelContext& k, VAddr va, std::string& out) {
    PAddr pa;
    if (!dm_pa(va, k, phys.max_address(), pa)) return false;
    char buf[16] = {};
    if (phys.read(pa, buf, sizeof(buf)) != sizeof(buf)) return false;
    std::size_t n = 0;
    while (n < sizeof(buf) && buf[n]) ++n;
    out.assign(buf, n);
    return true;
}

bool fill_process(const PhysicalLayer& phys, const KernelContext& k,
                  VAddr task_va, const Offsets& o, Process& out)
{
    out.task_va = task_va;
    if (!read_dm_u32(phys, k, task_va + o.pid,  out.pid))  return false;
    if (!read_dm_u32(phys, k, task_va + o.tgid, out.tgid)) return false;
    if (!read_dm_comm(phys, k, task_va + o.comm, out.comm)) return false;

    // PPID: on this kernel build, real_parent / parent pointers appear to be
    // offset by 0x40 from the task_struct start (likely due to thread_info-in-
    // task layout reshuffling). We try the documented offset first, then a
    // +0x40 fallback, and validate the resulting task by checking that its
    // comm field is printable.
    auto looks_like_task = [&](u64 candidate) -> bool {
        if (!candidate) return false;
        char comm[16] = {};
        PAddr pa = 0;
        if (!dm_pa(candidate + o.comm, k, phys.max_address(), pa)) return false;
        if (phys.read(pa, comm, sizeof(comm)) != sizeof(comm)) return false;
        return comm[0] >= 0x20 && comm[0] < 0x7f;
    };

    u64 parent_va = 0, parent_va2 = 0;
    read_dm_u64(phys, k, task_va + o.real_parent, parent_va);
    if (parent_va == 0)
        read_dm_u64(phys, k, task_va + o.parent, parent_va2);
    if (parent_va == 0) parent_va = parent_va2;
    if (parent_va) {
        u64 candidate = parent_va;
        if (!looks_like_task(candidate)) candidate = parent_va + 0x40;
        if ( looks_like_task(candidate)) {
            u32 ppid = 0;
            if (read_dm_u32(phys, k, candidate + o.tgid, ppid))
                out.ppid = ppid;
        }
    }
    read_dm_u64(phys, k, task_va + o.mm, out.mm);

    u64 cred_va = 0;
    if (read_dm_u64(phys, k, task_va + o.cred, cred_va) && cred_va) {
        read_dm_u32(phys, k, cred_va + o.cred_uid, out.uid);
        read_dm_u32(phys, k, cred_va + o.cred_gid, out.gid);
    }
    return true;
}

} // anonymous

std::vector<Process> list_processes(const PhysicalLayer&     phys,
                                    const x86_64::PageTable& /*pt*/,
                                    const IsfSymbols&        isf,
                                    const KernelContext&     kctx)
{
    Offsets o = gather_offsets(isf);
    std::vector<Process> out;
    std::unordered_set<VAddr> seen;

    // Read init_task.tasks.next directly via PA (init_task is in kernel text mapping).
    u64 next = 0;
    if (!phys.read_pod(kctx.init_task_pa + o.tasks + 0, next))
        throw_error("processes: cannot read init_task.tasks.next");
    log::info("init_task.tasks.next = {:#x}", next);

    VAddr head_link = kctx.init_task_va + o.tasks; // we may not have the real VA; we
                                                   // detect the loop by direct-map miss.
    (void)head_link;

    VAddr cur = next;
    PAddr maxa = phys.max_address();
    while (cur && !seen.count(cur)) {
        seen.insert(cur);
        VAddr task_va = cur - o.tasks;

        PAddr probe = 0;
        if (!dm_pa(task_va, kctx, maxa, probe)) {
            // Outside the direct map → we looped back to init_task in kernel text.
            log::debug("Stopping list walk: VA {:#x} outside direct map", task_va);
            break;
        }

        Process p{};
        if (fill_process(phys, kctx, task_va, o, p)) {
            if (p.pid != 0 && !p.comm.empty()) out.push_back(p);
        }

        u64 nxt = 0;
        if (!read_dm_u64(phys, kctx, cur + 0, nxt)) break;
        if (nxt == next) break;
        cur = nxt;
    }
    log::info("Listed {} processes", out.size());
    return out;
}

} // namespace lmpfs::linux
