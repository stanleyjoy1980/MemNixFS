// elf_core_stream.cpp — see header for design notes.
#include "os/linux/elf_core_stream.h"
#include "core/log.h"
#include <algorithm>
#include <cstring>

namespace lmpfs::linux {

namespace {

#pragma pack(push, 1)
struct Elf64_Ehdr {
    u8  e_ident[16];
    u16 e_type, e_machine;
    u32 e_version;
    u64 e_entry, e_phoff, e_shoff;
    u32 e_flags;
    u16 e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
};
struct Elf64_Phdr {
    u32 p_type, p_flags;
    u64 p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align;
};
#pragma pack(pop)

constexpr u16 ET_CORE   = 4;
constexpr u16 EM_X86_64 = 62;
constexpr u32 PT_LOAD   = 1;
constexpr u32 PF_X = 1, PF_W = 2, PF_R = 4;
constexpr u64 kHdrAlign = 0x1000;

} // anonymous

ElfCoreStream::ElfCoreStream(const PhysicalLayer&     phys,
                             const x86_64::PageTable& user_pt,
                             Process                  process,
                             std::vector<Vma>         vmas)
    : phys_(&phys), user_pt_(&user_pt), p_(std::move(process)), vmas_(std::move(vmas))
{
    plan();
}

void ElfCoreStream::plan() {
    // Filter to readable, non-empty VMAs. No size cap any more — streaming
    // means a 5 GiB process produces a 5 GiB virtual file at zero RAM cost.
    std::vector<const Vma*> use;
    use.reserve(vmas_.size());
    for (auto& v : vmas_) {
        if (!v.readable()) continue;
        if (v.size() == 0) continue;
        use.push_back(&v);
    }

    // Layout: [Ehdr][N × Phdr][padding to kHdrAlign][segment 0 data][seg 1]…
    const std::size_t hdr_struct_size =
        sizeof(Elf64_Ehdr) + use.size() * sizeof(Elf64_Phdr);
    const std::size_t hdr_padded =
        (hdr_struct_size + (kHdrAlign - 1)) & ~(kHdrAlign - 1);

    header_blob_.assign(hdr_padded, 0);

    Elf64_Ehdr eh{};
    std::memcpy(eh.e_ident, "\x7f""ELF", 4);
    eh.e_ident[4]  = 2;   // ELFCLASS64
    eh.e_ident[5]  = 1;   // ELFDATA2LSB
    eh.e_ident[6]  = 1;   // EV_CURRENT
    eh.e_type      = ET_CORE;
    eh.e_machine   = EM_X86_64;
    eh.e_version   = 1;
    eh.e_phoff     = sizeof(Elf64_Ehdr);
    eh.e_ehsize    = sizeof(Elf64_Ehdr);
    eh.e_phentsize = sizeof(Elf64_Phdr);
    eh.e_phnum     = static_cast<u16>(use.size());
    std::memcpy(header_blob_.data(), &eh, sizeof(eh));

    Elf64_Phdr* phdrs = reinterpret_cast<Elf64_Phdr*>(
        header_blob_.data() + sizeof(Elf64_Ehdr));

    u64 file_off = hdr_padded;
    segs_.reserve(use.size());
    for (std::size_t i = 0; i < use.size(); ++i) {
        const Vma& v = *use[i];
        const u64 sz = v.size();

        Elf64_Phdr& ph = phdrs[i];
        std::memset(&ph, 0, sizeof(ph));
        ph.p_type   = PT_LOAD;
        ph.p_flags  = (v.executable() ? PF_X : 0) |
                      (v.writable()   ? PF_W : 0) |
                      (v.readable()   ? PF_R : 0);
        ph.p_offset = file_off;
        ph.p_vaddr  = v.vm_start;
        ph.p_paddr  = 0;
        ph.p_filesz = sz;
        ph.p_memsz  = sz;
        ph.p_align  = 0x1000;

        segs_.push_back({ file_off, sz, v.vm_start });
        file_off += sz;
    }
    total_size_ = file_off;
    log::debug("ElfCoreStream pid={} segs={} hdr={}B total={}B (no upfront read)",
               p_.pid, segs_.size(), hdr_padded, total_size_);
}

std::size_t ElfCoreStream::read(u64 offset, void* out_v, std::size_t len) {
    u8* out = static_cast<u8*>(out_v);
    std::memset(out, 0, len);
    if (offset >= total_size_) return len; // past EOF → zero-filled (POSIX)
    if (offset + len > total_size_) len = static_cast<std::size_t>(total_size_ - offset);

    std::size_t written = 0;
    u64 cur = offset;
    u64 remaining = len;

    // 1) Serve any bytes that fall inside the precomputed header blob.
    if (cur < header_blob_.size()) {
        std::size_t take = static_cast<std::size_t>(
            std::min<u64>(header_blob_.size() - cur, remaining));
        std::memcpy(out, header_blob_.data() + cur, take);
        out += take; cur += take; remaining -= take; written += take;
    }
    if (remaining == 0) return written;

    // 2) Walk segments; for each that overlaps, pull only the touched bytes
    // through the per-process page cache. Repeated reads of the same page
    // (typical for editors / hex viewers) become pure memcpy.
    for (const auto& s : segs_) {
        u64 s_end_file = s.file_off + s.file_len;
        if (s_end_file <= cur) continue;
        if (s.file_off >= cur + remaining) break;

        u64 hit_start = std::max(cur, s.file_off);
        u64 hit_end   = std::min(cur + remaining, s_end_file);
        std::size_t hit_len = static_cast<std::size_t>(hit_end - hit_start);
        u64 vm_addr = s.vm_start + (hit_start - s.file_off);

        page_cache_.read(*user_pt_, vm_addr, out + (hit_start - cur), hit_len);
        written += hit_len;
    }
    return len; // total advertised, including zero-fill for any sparse gap
}

} // namespace lmpfs::linux
