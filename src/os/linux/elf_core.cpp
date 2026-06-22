#include "os/linux/elf_core.h"
#include "core/log.h"
#include <cstring>
#include <algorithm>

namespace lmpfs::linux {

namespace {

#pragma pack(push, 1)
struct Elf64_Ehdr {
    u8  e_ident[16];
    u16 e_type;
    u16 e_machine;
    u32 e_version;
    u64 e_entry;
    u64 e_phoff;
    u64 e_shoff;
    u32 e_flags;
    u16 e_ehsize;
    u16 e_phentsize;
    u16 e_phnum;
    u16 e_shentsize;
    u16 e_shnum;
    u16 e_shstrndx;
};
struct Elf64_Phdr {
    u32 p_type;
    u32 p_flags;
    u64 p_offset;
    u64 p_vaddr;
    u64 p_paddr;
    u64 p_filesz;
    u64 p_memsz;
    u64 p_align;
};
#pragma pack(pop)

constexpr u16 ET_CORE  = 4;
constexpr u16 EM_X86_64 = 62;
constexpr u32 PT_LOAD  = 1;
constexpr u32 PF_X = 1, PF_W = 2, PF_R = 4;

} // anonymous

ByteBuf build_elf_core(const PhysicalLayer&     phys,
                       const x86_64::PageTable& user_pt,
                       const Process&           p,
                       const std::vector<Vma>&  vmas,
                       u64                      max_bytes)
{
    (void)phys; (void)p;

    // Filter to readable, non-empty VMAs and clip total size to max_bytes.
    struct Plan { const Vma* v; u64 filesz; };
    std::vector<Plan> plan;
    plan.reserve(vmas.size());
    u64 total_data = 0;
    for (auto& v : vmas) {
        if (!v.readable()) continue;
        u64 sz = v.size();
        if (sz == 0) continue;
        u64 take = std::min<u64>(sz, max_bytes > total_data ? max_bytes - total_data : 0);
        if (take == 0) break;
        plan.push_back({ &v, take });
        total_data += take;
    }

    // Layout: [Ehdr][N × Phdr][segment data...]
    std::size_t hdr_size = sizeof(Elf64_Ehdr) + plan.size() * sizeof(Elf64_Phdr);
    // Align segment data to page boundary
    std::size_t data_start = (hdr_size + 0xFFF) & ~std::size_t(0xFFF);

    ByteBuf out(data_start + total_data, 0);

    Elf64_Ehdr eh{};
    std::memcpy(eh.e_ident, "\x7f""ELF", 4);
    eh.e_ident[4]  = 2;  // ELFCLASS64
    eh.e_ident[5]  = 1;  // ELFDATA2LSB
    eh.e_ident[6]  = 1;  // EV_CURRENT
    eh.e_type      = ET_CORE;
    eh.e_machine   = EM_X86_64;
    eh.e_version   = 1;
    eh.e_phoff     = sizeof(Elf64_Ehdr);
    eh.e_ehsize    = sizeof(Elf64_Ehdr);
    eh.e_phentsize = sizeof(Elf64_Phdr);
    eh.e_phnum     = static_cast<u16>(plan.size());
    std::memcpy(out.data(), &eh, sizeof(eh));

    u64 file_off = data_start;
    Elf64_Phdr* phdrs = reinterpret_cast<Elf64_Phdr*>(out.data() + sizeof(Elf64_Ehdr));
    for (std::size_t i = 0; i < plan.size(); ++i) {
        const Vma& v = *plan[i].v;
        u64 take = plan[i].filesz;
        Elf64_Phdr& ph = phdrs[i];
        std::memset(&ph, 0, sizeof(ph));
        ph.p_type   = PT_LOAD;
        ph.p_flags  = (v.executable() ? PF_X : 0) |
                      (v.writable()   ? PF_W : 0) |
                      (v.readable()   ? PF_R : 0);
        ph.p_offset = file_off;
        ph.p_vaddr  = v.vm_start;
        ph.p_paddr  = 0;
        ph.p_filesz = take;
        ph.p_memsz  = v.size();
        ph.p_align  = 0x1000;

        // Copy bytes from the user's virtual memory.
        user_pt.read(v.vm_start, out.data() + file_off, static_cast<std::size_t>(take));
        file_off += take;
    }
    log::debug("ELF core: PHnum={} hdr={}B data={}B total={}B",
               plan.size(), hdr_size, total_data, out.size());
    return out;
}

u64 estimate_elf_core_size(const std::vector<Vma>& vmas, u64 max_bytes) {
    // Mirror the layout in build_elf_core(): readable VMAs become PT_LOAD
    // segments, total file size = header_aligned + sum(filesz).
    std::size_t phnum = 0;
    u64 total_data = 0;
    for (auto& v : vmas) {
        if (!v.readable()) continue;
        u64 sz = v.size();
        if (sz == 0) continue;
        u64 take = std::min<u64>(sz, max_bytes > total_data ? max_bytes - total_data : 0);
        if (take == 0) break;
        ++phnum;
        total_data += take;
    }
    std::size_t hdr_size  = sizeof(Elf64_Ehdr) + phnum * sizeof(Elf64_Phdr);
    std::size_t data_start = (hdr_size + 0xFFF) & ~std::size_t(0xFFF);
    return data_start + total_data;
}

} // namespace lmpfs::linux
