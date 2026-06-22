// dmesg.cpp — see header.
//
// Wire layout of `struct printk_ringbuffer` (x86_64, kernel 6.x):
//
//   printk_ringbuffer {                                  size = 88
//     prb_desc_ring desc_ring;                           @0x00, size 48
//       unsigned int count_bits;                         @+0x00
//       prb_desc *descs;                                 @+0x08
//       printk_info *infos;                              @+0x10
//       atomic_long_t head_id;                           @+0x18
//       atomic_long_t tail_id;                           @+0x20
//       atomic_long_t last_finalized_seq;                @+0x28
//     prb_data_ring text_data_ring;                      @0x30, size 32
//       unsigned int size_bits;                          @+0x00
//       char *data;                                      @+0x08
//       atomic_long_t head_lpos;                         @+0x10
//       atomic_long_t tail_lpos;                         @+0x18
//     atomic_long_t fail;                                @0x50
//   }
//
//   prb_desc { atomic_long_t state_var; prb_data_blk_lpos text_blk_lpos; }
//   prb_data_blk_lpos { unsigned long begin; unsigned long next; }
//
//   printk_info {                                        size 88
//     u64 seq;                                           @+0x00
//     u64 ts_nsec;                                       @+0x08
//     u16 text_len;                                      @+0x10
//     u8  facility;                                      @+0x12
//     u8  flags:5; u8 level:3;                           @+0x13 (packed byte)
//     u32 caller_id;                                     @+0x14
//     dev_printk_info dev_info;                          @+0x18
//   }
//
// State encoding in `state_var` (top 2 bits, x86_64 = bits 62-63):
//   0 = reserved (being written)
//   1 = committed (text complete, info still being filled)
//   2 = finalized (text + info complete — what we want)
//   3 = reusable  (skip)
//
#include "os/linux/dmesg.h"
#include "app/engine.h"
#include "symbols/isf_symbols.h"
#include "arch/x86_64/paging.h"
#include "formats/physical_layer.h"
#include "os/linux/kernel_resolver.h"
#include "os/linux/kva_reader.h"
#include "core/log.h"
#include <fmt/format.h>
#include <cstring>
#include <vector>

namespace lmpfs::linux {

namespace {

// Mirror of kernel/printk/printk_ringbuffer.h state encoding.
constexpr u64 DESC_SV_BITS      = 64;
constexpr u64 DESC_FLAGS_SHIFT  = DESC_SV_BITS - 2;
constexpr u64 DESC_FLAGS_MASK   = u64(3) << DESC_FLAGS_SHIFT;
constexpr u64 DESC_STATE_RESERVED  = 0;
constexpr u64 DESC_STATE_COMMITTED = 1;
constexpr u64 DESC_STATE_FINALIZED = 2;
constexpr u64 DESC_STATE_REUSABLE  = 3;
constexpr u64 DESC_ID_MASK         = ~DESC_FLAGS_MASK;

// `unsigned long` for the kernel build target — 8 on x86_64.
constexpr u64 kULong = 8;

// Each prb_data block in the data ring is prefixed by an `unsigned long id`
// header. The text starts immediately after.
constexpr u64 kDataBlkHdrSize = kULong;

// Kernel canonical-VA region boundaries on x86_64.
constexpr u64 kStartKernelMap = 0xffffffff80000000ULL;  // kernel image base
constexpr u64 kPhysmapStart   = 0xffff800000000000ULL;  // direct-map starts here

// Translate a kernel-image VA to PA via the engine's kaslr_phys_shift.
// Works for any symbol in the static kernel image (.text/.rodata/.data/.bss).
inline PAddr kva_to_pa_image(VAddr va, i64 phys_shift) {
    return static_cast<PAddr>(static_cast<i64>(va - kStartKernelMap)
                              + phys_shift);
}

// Delegated to the shared multi-strategy kernel-VA reader.
// Critical for the dmesg ringbuffer: the printk_ringbuffer struct itself
// is in the kernel image (.bss), but its descs/infos/data pointers may
// point into kmalloc'd memory (direct-map range) when the kernel resized
// log_buf at boot via setup_log_buf().
inline bool kread(const Engine& eng, VAddr va, void* dst, std::size_t n) {
    return kva_read(eng, va, dst, n);
}
template <typename T>
inline bool kread_pod(const Engine& eng, VAddr va, T& out) {
    return kva_read_pod(eng, va, out);
}

// Sanitise a printk text payload for the output file. Linux text
// may contain raw control bytes (e.g. embedded CR) — strip them.
std::string clean_text(const u8* src, std::size_t len) {
    std::string out;
    out.reserve(len);
    for (std::size_t i = 0; i < len; ++i) {
        u8 c = src[i];
        if (c == '\n') break;            // log entries are single-line
        if (c == '\r')  continue;
        if (c < 0x20 || c >= 0x7F) {
            if (c == '\t') { out.push_back('\t'); continue; }
            out += fmt::format("\\x{:02x}", c);
            continue;
        }
        out.push_back(static_cast<char>(c));
    }
    return out;
}

ByteBuf err(const std::string& s) {
    return ByteBuf(s.begin(), s.end());
}

} // anon

ByteBuf format_dmesg(const Engine& eng) {
    const auto& isf = eng.isf();
    const auto& kctx = eng.kernel();

    // ── 1. Find the `prb` global pointer ──
    auto* prb_sym = isf.find_symbol("prb");
    if (!prb_sym) {
        return err(
            "; no `prb` symbol in ISF — old (pre-5.10) printk format or\n"
            "; this build was compiled with CONFIG_PRINTK=n.\n");
    }
    log::debug("dmesg: prb symbol VA = {:#x}", prb_sym->address);

    // The `prb` global is a `struct printk_ringbuffer *`. Read 8 bytes
    // there to get the pointer value (which points to either
    // `printk_rb_static` or a dynamically-allocated one).
    VAddr rb_va = 0;
    if (!kread_pod(eng, prb_sym->address, rb_va) || rb_va == 0) {
        return err("; could not read prb pointer\n");
    }
    log::debug("dmesg: printk_ringbuffer * = {:#x}", rb_va);

    // ── 2. Read printk_ringbuffer field offsets from ISF ──
    u64 dr_off, td_off;
    u64 cb_off, descs_off, infos_off, head_off, tail_off, lastfin_off;
    u64 sb_off, data_off;
    u64 ds_state_off, ds_text_lpos_off;
    u64 lpos_begin_off, lpos_next_off;
    u64 info_seq_off, info_ts_off, info_text_len_off, info_flags_off;
    u64 desc_size, info_size;
    try {
        dr_off          = isf.field_offset("printk_ringbuffer", "desc_ring");
        td_off          = isf.field_offset("printk_ringbuffer", "text_data_ring");
        cb_off          = isf.field_offset("prb_desc_ring",     "count_bits");
        descs_off       = isf.field_offset("prb_desc_ring",     "descs");
        infos_off       = isf.field_offset("prb_desc_ring",     "infos");
        head_off        = isf.field_offset("prb_desc_ring",     "head_id");
        tail_off        = isf.field_offset("prb_desc_ring",     "tail_id");
        lastfin_off     = isf.field_offset("prb_desc_ring",     "last_finalized_seq");
        sb_off          = isf.field_offset("prb_data_ring",     "size_bits");
        data_off        = isf.field_offset("prb_data_ring",     "data");
        ds_state_off    = isf.field_offset("prb_desc",          "state_var");
        ds_text_lpos_off= isf.field_offset("prb_desc",          "text_blk_lpos");
        lpos_begin_off  = isf.field_offset("prb_data_blk_lpos", "begin");
        lpos_next_off   = isf.field_offset("prb_data_blk_lpos", "next");
        info_seq_off    = isf.field_offset("printk_info",       "seq");
        info_ts_off     = isf.field_offset("printk_info",       "ts_nsec");
        info_text_len_off = isf.field_offset("printk_info",     "text_len");
        info_flags_off  = isf.field_offset("printk_info",       "flags");
        desc_size       = isf.type_size("prb_desc");
        info_size       = isf.type_size("printk_info");
    } catch (const std::exception& e) {
        return err(fmt::format(
            "; ISF lacks a printk-ringbuffer struct field: {}\n", e.what()));
    }

    // ── 3. Read the ringbuffer struct ──
    u32 count_bits = 0, text_size_bits = 0;
    VAddr descs_va = 0, infos_va = 0, data_va = 0;
    u64   head_id_sv = 0, tail_id_sv = 0, last_fin_seq = 0;

    if (!kread_pod(eng, rb_va + dr_off + cb_off,      count_bits)     ||
        !kread_pod(eng, rb_va + dr_off + descs_off,   descs_va)       ||
        !kread_pod(eng, rb_va + dr_off + infos_off,   infos_va)       ||
        !kread_pod(eng, rb_va + dr_off + head_off,    head_id_sv)     ||
        !kread_pod(eng, rb_va + dr_off + tail_off,    tail_id_sv)     ||
        !kread_pod(eng, rb_va + dr_off + lastfin_off, last_fin_seq)   ||
        !kread_pod(eng, rb_va + td_off + sb_off,      text_size_bits) ||
        !kread_pod(eng, rb_va + td_off + data_off,    data_va))
    {
        return err("; failed to read printk_ringbuffer fields\n");
    }

    if (count_bits == 0 || count_bits > 24 ||
        text_size_bits == 0 || text_size_bits > 28)
    {
        return err(fmt::format(
            "; suspicious ringbuffer sizes: count_bits={} text_size_bits={}\n"
            "; (likely the pointer in `prb` didn't translate correctly)\n",
            count_bits, text_size_bits));
    }

    const u64 desc_count = 1ULL << count_bits;
    const u64 text_size  = 1ULL << text_size_bits;
    log::info("dmesg: rb @ {:#x}; {} descriptors, {} KB text ring; head_id={:#x} tail_id={:#x}",
              rb_va, desc_count, text_size / 1024,
              head_id_sv & DESC_ID_MASK, tail_id_sv & DESC_ID_MASK);

    // ── 4. Walk descriptors from tail_id to head_id ──
    const u64 head_id = head_id_sv & DESC_ID_MASK;
    const u64 tail_id = tail_id_sv & DESC_ID_MASK;

    // Sanity: tail_id should be ≤ head_id in modular arithmetic.
    // The valid range is the descriptor IDs from tail to head (both inclusive).
    // We cap at `desc_count` iterations to avoid pathological loops.
    std::string out;
    out.reserve(64 * 1024);

    std::size_t emitted = 0, skipped = 0;
    u64 id = tail_id;
    for (u64 i = 0; i < desc_count + 1; ++i) {
        const u64 desc_idx = id & (desc_count - 1);

        // Read this descriptor's state_var and text_blk_lpos
        VAddr desc_va = descs_va + desc_idx * desc_size;
        u64 state_var = 0;
        u64 lpos_begin = 0, lpos_next = 0;
        if (!kread_pod(eng, desc_va + ds_state_off, state_var)) {
            ++skipped;
        } else {
            const u64 state = (state_var & DESC_FLAGS_MASK) >> DESC_FLAGS_SHIFT;
            const bool valid = (state == DESC_STATE_COMMITTED ||
                                state == DESC_STATE_FINALIZED);
            if (valid &&
                kread_pod(eng, desc_va + ds_text_lpos_off + lpos_begin_off, lpos_begin) &&
                kread_pod(eng, desc_va + ds_text_lpos_off + lpos_next_off,  lpos_next))
            {
                // Read printk_info
                VAddr info_va = infos_va + desc_idx * info_size;
                u64 seq = 0, ts_nsec = 0;
                u16 text_len = 0;
                u8  flags_level = 0;
                if (kread_pod(eng, info_va + info_seq_off,      seq) &&
                    kread_pod(eng, info_va + info_ts_off,       ts_nsec) &&
                    kread_pod(eng, info_va + info_text_len_off, text_len) &&
                    kread_pod(eng, info_va + info_flags_off,    flags_level))
                {
                    if (text_len > 0 && text_len < 4096) {
                        // Text block layout: [unsigned long id][text bytes]
                        const u64 begin_off = lpos_begin & (text_size - 1);
                        const VAddr text_va = data_va + begin_off + kDataBlkHdrSize;

                        std::vector<u8> tbuf(text_len);
                        if (kread(eng, text_va, tbuf.data(), text_len)) {
                            const u64 sec  = ts_nsec / 1'000'000'000ULL;
                            const u64 usec = (ts_nsec % 1'000'000'000ULL) / 1000ULL;
                            const u8 level = flags_level & 0x07;  // 3 LSB

                            out += fmt::format("[{:>5}.{:06}] ", sec, usec);
                            // Add the kernel-printk level prefix (<N>) if we can.
                            if (level <= 7) out += fmt::format("<{}>", level);
                            out += clean_text(tbuf.data(), text_len);
                            out.push_back('\n');
                            ++emitted;
                        } else {
                            ++skipped;
                        }
                    }
                } else {
                    ++skipped;
                }
            }
        }

        if (id == head_id) break;
        // The ID space is monotonically increasing across the ringbuffer's
        // lifetime. Each iteration moves to the next ID.
        ++id;
        // ID 0 is reserved as invalid; skip it if we wrap.
        if (id == 0) id = 1;
    }

    log::info("dmesg: emitted {} records, skipped {}", emitted, skipped);

    if (emitted == 0) {
        return err(fmt::format(
            "; walked {} descriptors but emitted 0 records.\n"
            "; head_id={:#x} tail_id={:#x} desc_count={} text_size={} KB\n"
            "; (descriptors may all be reserved/reusable, or text reads failed)\n",
            desc_count, head_id, tail_id, desc_count, text_size / 1024));
    }
    return ByteBuf(out.begin(), out.end());
}

} // namespace lmpfs::linux
