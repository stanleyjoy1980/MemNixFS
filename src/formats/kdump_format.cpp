// kdump_format.cpp — read kdump-format memory dumps (ELF64 core files).
//
// Kdump format: an ELF64 ET_CORE file with
//   * one PT_NOTE segment carrying CORE notes + VMCOREINFO
//   * N PT_LOAD segments, each mapping a contiguous physical range
//     (p_paddr = start PA, p_filesz = bytes in file, p_offset = file off).
//
// We parse the ELF header + program headers once, build a sorted
// (PA-range → file-offset) lookup table, and answer read(pa) requests
// by binary-searching the table.
//
// VMCOREINFO is parsed best-effort and stashed for the kernel resolver
// to consult (currently informational — not yet used to short-circuit
// the DTB/KASLR scan, pending validation against a real kdump sample).
//
// IMPORTANT: this reader is STRUCTURALLY correct against the ELF/kdump
// specs but **untested against a real kdump file** at the time of this
// commit. The author's test corpus is AVML + LiME only. First-pass
// validation: a kdump dump should be opened, read at random offsets,
// and the output cross-checked with `crash` or `makedumpfile --dry-run`.
//
// References:
//   * Linux Documentation/admin-guide/kdump/vmcoreinfo.rst
//   * kernel source: kernel/crash_core.c
//   * makedumpfile: https://github.com/makedumpfile/makedumpfile
//
#include "formats/format_factory.h"
#include "core/error.h"
#include "core/log.h"
#include <algorithm>
#include <cstring>
#include <vector>
#include <string>

namespace lmpfs {

namespace {

// Minimal ELF64 + Note structs. Layouts are stable across versions.
#pragma pack(push, 1)
struct Elf64_Ehdr {
    u8   e_ident[16];
    u16  e_type;
    u16  e_machine;
    u32  e_version;
    u64  e_entry;
    u64  e_phoff;
    u64  e_shoff;
    u32  e_flags;
    u16  e_ehsize;
    u16  e_phentsize;
    u16  e_phnum;
    u16  e_shentsize;
    u16  e_shnum;
    u16  e_shstrndx;
};
struct Elf64_Phdr {
    u32  p_type;
    u32  p_flags;
    u64  p_offset;
    u64  p_vaddr;
    u64  p_paddr;
    u64  p_filesz;
    u64  p_memsz;
    u64  p_align;
};
struct Elf64_Nhdr {
    u32  n_namesz;
    u32  n_descsz;
    u32  n_type;
};
#pragma pack(pop)

static_assert(sizeof(Elf64_Ehdr) == 64,  "ELF64 ehdr size");
static_assert(sizeof(Elf64_Phdr) == 56,  "ELF64 phdr size");
static_assert(sizeof(Elf64_Nhdr) == 12,  "ELF64 note hdr size");

constexpr u16 kEtCore       = 4;
constexpr u16 kEmX86_64     = 62;
constexpr u32 kPtLoad       = 1;
constexpr u32 kPtNote       = 4;
constexpr u32 kNoteRoundUp  = 4;

// Round up to multiple of 4 (ELF Note convention).
inline u64 align4(u64 x) { return (x + 3) & ~u64(3); }

struct LoadRange {
    PAddr pa_start;   // p_paddr
    u64   pa_size;    // p_filesz (bytes actually in the dump)
    u64   file_off;   // p_offset
};

class KdumpPhysical : public PhysicalLayer {
public:
    KdumpPhysical(std::unique_ptr<MemorySource> src,
                   std::vector<LoadRange> ranges,
                   std::string vmcoreinfo)
        : src_(std::move(src)),
          ranges_(std::move(ranges)),
          vmcoreinfo_(std::move(vmcoreinfo)),
          fmt_("kdump (ELF64 core)"),
          name_(src_->name())
    {
        // Sort by pa_start for binary search.
        std::sort(ranges_.begin(), ranges_.end(),
            [](const LoadRange& a, const LoadRange& b) {
                return a.pa_start < b.pa_start;
            });
        max_pa_ = 0;
        for (const auto& r : ranges_) max_pa_ = std::max(max_pa_, r.pa_start + r.pa_size);
        log::info("kdump: {} PT_LOAD ranges, max PA = {:#x}{}",
                  ranges_.size(), max_pa_,
                  vmcoreinfo_.empty() ? ""
                                       : ", VMCOREINFO captured");
    }

    PAddr max_address() const override { return max_pa_; }
    const std::string& format_name() const override { return fmt_; }
    const std::string& source_name() const override { return name_; }
    std::vector<Range> ranges() const override {
        std::vector<Range> out;
        out.reserve(ranges_.size());
        for (const auto& r : ranges_)
            out.push_back({r.pa_start, r.pa_size});
        return out;
    }

    std::size_t read(PAddr pa, void* out, std::size_t len) const override {
        std::memset(out, 0, len);
        std::size_t got_total = 0;
        u8* dst = static_cast<u8*>(out);
        PAddr cur = pa;
        std::size_t remaining = len;
        while (remaining > 0) {
            // Binary search for the range containing `cur`.
            auto it = std::upper_bound(ranges_.begin(), ranges_.end(), cur,
                [](PAddr a, const LoadRange& r) { return a < r.pa_start; });
            if (it == ranges_.begin()) {
                // `cur` is below the first range → hole, but advance to it.
                PAddr first_pa = ranges_.front().pa_start;
                std::size_t hole = std::min<u64>(remaining, first_pa - cur);
                cur += hole; dst += hole; remaining -= hole;
                continue;
            }
            --it;
            if (cur >= it->pa_start + it->pa_size) {
                // Past this range → hole. Advance to next range's start
                // (or end of request).
                auto nx = it + 1;
                PAddr next_pa = (nx == ranges_.end()) ? PAddr(~0ULL)
                                                       : nx->pa_start;
                if (cur >= next_pa) { ++cur; continue; }   // shouldn't happen
                std::size_t hole = std::min<u64>(remaining, next_pa - cur);
                cur += hole; dst += hole; remaining -= hole;
                continue;
            }
            // We're inside `*it`. Read up to the range's end.
            std::size_t off_in_range = cur - it->pa_start;
            std::size_t can_read     = it->pa_size - off_in_range;
            std::size_t want         = std::min<u64>(remaining, can_read);
            std::size_t got = src_->read(it->file_off + off_in_range, dst, want);
            got_total += got;
            cur += want; dst += want; remaining -= want;
        }
        return got_total;
    }

    const std::string& vmcoreinfo() const { return vmcoreinfo_; }

private:
    std::unique_ptr<MemorySource> src_;
    std::vector<LoadRange>        ranges_;
    std::string                   vmcoreinfo_;
    std::string                   fmt_, name_;
    PAddr                         max_pa_ = 0;
};

// Walk a PT_NOTE segment and return the desc of the "VMCOREINFO" note,
// or empty if not present. Each note: Elf64_Nhdr + name (rounded to 4)
// + desc (rounded to 4).
std::string extract_vmcoreinfo(MemorySource& src, u64 note_off, u64 note_size) {
    std::vector<u8> buf(note_size);
    std::size_t got = src.read(note_off, buf.data(), note_size);
    if (got < sizeof(Elf64_Nhdr)) return {};

    std::size_t p = 0;
    while (p + sizeof(Elf64_Nhdr) <= got) {
        Elf64_Nhdr nh;
        std::memcpy(&nh, buf.data() + p, sizeof(nh));
        std::size_t name_pad = align4(nh.n_namesz);
        std::size_t desc_pad = align4(nh.n_descsz);
        if (p + sizeof(nh) + name_pad + desc_pad > got) break;

        std::string name(reinterpret_cast<const char*>(buf.data()) +
                          p + sizeof(nh),
                          nh.n_namesz > 0 ? nh.n_namesz - 1 : 0);  // strip NUL
        if (name == "VMCOREINFO") {
            std::string desc(reinterpret_cast<const char*>(buf.data()) +
                              p + sizeof(nh) + name_pad,
                              nh.n_descsz);
            log::info("kdump: VMCOREINFO captured ({} bytes)", desc.size());
            return desc;
        }
        p += sizeof(nh) + name_pad + desc_pad;
    }
    return {};
}

} // anonymous

std::unique_ptr<PhysicalLayer>
open_kdump_physical(std::unique_ptr<MemorySource> src) {
    Elf64_Ehdr eh;
    std::size_t got = src->read(0, &eh, sizeof(eh));
    if (got < sizeof(eh)) throw_error("kdump: file too small for ELF header");

    if (std::memcmp(eh.e_ident, "\x7f""ELF", 4) != 0)
        throw_error("kdump: not an ELF file");
    if (eh.e_ident[4] != 2)   // EI_CLASS — must be ELFCLASS64
        throw_error("kdump: not ELF64");
    if (eh.e_ident[5] != 1)   // EI_DATA  — must be ELFDATA2LSB (little-endian)
        throw_error("kdump: not little-endian");
    if (eh.e_type != kEtCore)
        throw_error("kdump: ELF type is not ET_CORE (got {})", eh.e_type);
    if (eh.e_machine != kEmX86_64)
        log::warn("kdump: e_machine = {} (expected x86_64 = 62) — proceeding anyway",
                  eh.e_machine);
    if (eh.e_phoff == 0 || eh.e_phnum == 0)
        throw_error("kdump: ELF has no program headers");
    if (eh.e_phentsize != sizeof(Elf64_Phdr))
        throw_error("kdump: unexpected phentsize {} (expected {})",
                    eh.e_phentsize, sizeof(Elf64_Phdr));

    std::vector<Elf64_Phdr> phs(eh.e_phnum);
    std::size_t want = eh.e_phnum * sizeof(Elf64_Phdr);
    if (src->read(eh.e_phoff, phs.data(), want) != want)
        throw_error("kdump: short read on program headers");

    std::vector<LoadRange> ranges;
    std::string vmcoreinfo;
    for (const auto& ph : phs) {
        if (ph.p_type == kPtLoad) {
            if (ph.p_filesz == 0) continue;
            ranges.push_back({ ph.p_paddr, ph.p_filesz, ph.p_offset });
        } else if (ph.p_type == kPtNote && vmcoreinfo.empty()) {
            // Multiple PT_NOTE segments are possible; only one carries
            // VMCOREINFO. Take the first match.
            vmcoreinfo = extract_vmcoreinfo(*src, ph.p_offset, ph.p_filesz);
        }
    }
    if (ranges.empty())
        throw_error("kdump: no PT_LOAD segments found");

    log::note("Format: kdump (ELF64 core) — {} PT_LOAD ranges, {} PT_NOTE",
              ranges.size(), vmcoreinfo.empty() ? "no VMCOREINFO" : "VMCOREINFO present");
    return std::make_unique<KdumpPhysical>(std::move(src),
                                            std::move(ranges),
                                            std::move(vmcoreinfo));
}

} // namespace lmpfs
