// ebpf.cpp — see header.
#include "os/linux/ebpf.h"
#include "os/linux/kva_reader.h"
#include "app/engine.h"
#include "symbols/isf_symbols.h"
#include "core/log.h"
#include <fmt/format.h>
#include <cstring>

namespace lmpfs::linux {

namespace {

// xarray entry encoding (mirrors pagecache.cpp's walker — kept local
// so we don't entangle modules).
inline bool xa_is_internal(VAddr e) { return (e & 3ULL) == 2; }
inline bool xa_is_value(VAddr e)    { return (e & 1ULL) == 1; }
inline VAddr xa_to_node(VAddr e)    { return e & ~3ULL; }

struct Off {
    u64 idr_idr_rt   = 0x0;
    u64 xa_xa_head   = 0x8;
    u64 xn_shift     = 0x0;
    u64 xn_slots     = 0x28;
    u64 prog_type    = 0x4;
    u64 prog_jited_len = 0x10;
    u64 prog_tag     = 0x14;
    u64 prog_bpf_func= 0x30;
    u64 prog_aux     = 0x38;
    u64 aux_id       = 0x20;
    u64 aux_name     = 0x3d8;
    u64 aux_load_time= 0x3b8;
    bool ok = false;
};
Off resolve_off(const IsfSymbols& isf) {
    Off o{};
    auto tf = [&](u64& dst, const char* t, const char* f) {
        try { dst = isf.field_offset(t, f); } catch (...) {}
    };
    tf(o.idr_idr_rt,    "idr",          "idr_rt");
    tf(o.xa_xa_head,    "xarray",       "xa_head");
    tf(o.xn_shift,      "xa_node",      "shift");
    tf(o.xn_slots,      "xa_node",      "slots");
    tf(o.prog_type,     "bpf_prog",     "type");
    tf(o.prog_jited_len,"bpf_prog",     "jited_len");
    tf(o.prog_tag,      "bpf_prog",     "tag");
    tf(o.prog_bpf_func, "bpf_prog",     "bpf_func");
    tf(o.prog_aux,      "bpf_prog",     "aux");
    tf(o.aux_id,        "bpf_prog_aux", "id");
    tf(o.aux_name,      "bpf_prog_aux", "name");
    tf(o.aux_load_time, "bpf_prog_aux", "load_time");
    o.ok = true;
    return o;
}

void walk_xarray(const Engine& eng, const Off& o, VAddr entry,
                 std::vector<VAddr>& leaves, std::size_t& budget, int depth = 0)
{
    if (entry == 0 || depth > 16) return;
    if (budget == 0) return;   // bound a crafted cyclic/explosive xarray
    --budget;
    if (xa_is_value(entry)) return;
    if (!xa_is_internal(entry)) {
        leaves.push_back(entry);
        return;
    }
    VAddr node = xa_to_node(entry);
    constexpr u64 kSlots = 64;
    std::vector<VAddr> slots(kSlots, 0);
    if (!kva_read(eng, node + o.xn_slots, slots.data(), kSlots * sizeof(VAddr)))
        return;
    for (u64 i = 0; i < kSlots; ++i) {
        if (slots[i] == 0) continue;
        walk_xarray(eng, o, slots[i], leaves, budget, depth + 1);
    }
}

} // anonymous

const char* bpf_prog_type_name(u32 t) {
    // From include/uapi/linux/bpf.h — enum bpf_prog_type
    static const char* names[] = {
        "UNSPEC", "SOCKET_FILTER", "KPROBE", "SCHED_CLS", "SCHED_ACT",
        "TRACEPOINT", "XDP", "PERF_EVENT", "CGROUP_SKB", "CGROUP_SOCK",
        "LWT_IN", "LWT_OUT", "LWT_XMIT", "SOCK_OPS", "SK_SKB",
        "CGROUP_DEVICE", "SK_MSG", "RAW_TRACEPOINT", "CGROUP_SOCK_ADDR",
        "LWT_SEG6LOCAL", "LIRC_MODE2", "SK_REUSEPORT", "FLOW_DISSECTOR",
        "CGROUP_SYSCTL", "RAW_TRACEPOINT_WRITABLE", "CGROUP_SOCKOPT",
        "TRACING", "STRUCT_OPS", "EXT", "LSM", "SK_LOOKUP", "SYSCALL",
        "NETFILTER",
    };
    return t < std::size(names) ? names[t] : "?";
}

std::vector<BpfProgInfo> enumerate_bpf_programs(const Engine& eng) {
    std::vector<BpfProgInfo> out;
    const auto& isf = eng.isf();
    auto* sym = isf.find_symbol("prog_idr");
    if (!sym) {
        log::warn("ebpf: ISF lacks `prog_idr` symbol — eBPF enumeration disabled");
        return out;
    }
    Off o = resolve_off(isf);

    // prog_idr.idr_rt.xa_head → root of the xarray.
    VAddr idr_va = sym->address;
    VAddr xa_root = 0;
    if (!kva_read_pod(eng, idr_va + o.idr_idr_rt + o.xa_xa_head, xa_root))
        return out;
    if (xa_root == 0) {
        log::info("ebpf: prog_idr is empty");
        return out;
    }
    std::vector<VAddr> prog_ptrs;
    if (!xa_is_internal(xa_root)) {
        if (!xa_is_value(xa_root)) prog_ptrs.push_back(xa_root);
    } else {
        std::size_t budget = 1'000'000;
        walk_xarray(eng, o, xa_root, prog_ptrs, budget);
    }
    log::info("ebpf: prog_idr walked, {} program(s) found", prog_ptrs.size());

    for (VAddr prog : prog_ptrs) {
        BpfProgInfo p{};
        p.prog_va = prog;
        kva_read_pod(eng, prog + o.prog_type,      p.type);
        kva_read_pod(eng, prog + o.prog_jited_len, p.jited_len);
        kva_read_pod(eng, prog + o.prog_bpf_func,  p.bpf_func);
        u8 tag[8] = {};
        kva_read(eng, prog + o.prog_tag, tag, sizeof(tag));
        char tbuf[17] = {};
        for (int i = 0; i < 8; ++i) std::snprintf(tbuf + i*2, 3, "%02x", tag[i]);
        p.tag_hex = tbuf;
        VAddr aux = 0;
        kva_read_pod(eng, prog + o.prog_aux, aux);
        if (aux) {
            kva_read_pod(eng, aux + o.aux_id,        p.id);
            kva_read_pod(eng, aux + o.aux_load_time, p.load_time_ns);
            char name[17] = {};
            kva_read(eng, aux + o.aux_name, name, 16);
            std::size_t n = 0;
            while (n < 16 && name[n]) ++n;
            p.name.assign(name, n);
        }
        out.push_back(std::move(p));
    }
    return out;
}

ByteBuf format_ebpf_programs(const Engine& eng) {
    auto progs = enumerate_bpf_programs(eng);
    std::string out;
    out.reserve(8 * 1024);
    out += fmt::format(
        "# /sys/findevil/ebpf.txt — every loaded eBPF program\n"
        "# Walks `prog_idr` (the global xarray of bpf_prog ptrs).\n"
        "# {} program(s) loaded.\n"
        "#\n"
        "# Forensic note: eBPF programs of type TRACING / KPROBE / TRACEPOINT /\n"
        "# RAW_TRACEPOINT / LSM with no associated user process are the modern\n"
        "# rootkit pattern. XDP programs on suspicious interfaces drop traffic.\n"
        "#\n"
        "#   id   type                   jited_len  tag                load_time      name             bpf_func\n"
        "# ----+----------------------+----------+------------------+--------------+----------------+-------------\n",
        progs.size());
    if (progs.empty()) {
        out += "; no eBPF programs loaded (or `prog_idr` symbol missing from ISF)\n";
        return ByteBuf(out.begin(), out.end());
    }
    for (const auto& p : progs) {
        out += fmt::format("{:>5}   {:<20}  {:>8}   {}   {:>12}   {:<16} {:#x}\n",
                           p.id,
                           bpf_prog_type_name(p.type),
                           p.jited_len,
                           p.tag_hex,
                           p.load_time_ns,
                           p.name.empty() ? "(unnamed)" : p.name,
                           p.bpf_func);
    }
    return ByteBuf(out.begin(), out.end());
}

} // namespace lmpfs::linux
