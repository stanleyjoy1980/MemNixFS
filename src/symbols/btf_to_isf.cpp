// btf_to_isf.cpp — see header.
//
// Reads a BTF blob in memory and emits a Volatility-3-compatible ISF JSON.
//
// BTF wire format (include/uapi/linux/btf.h):
//   - 24-byte header: magic, version, flags, hdr_len,
//                     type_off, type_len, str_off, str_len
//   - Type section:   sequence of btf_type {name_off, info, size_or_type}
//                     followed by kind-specific variable-length data
//   - String section: NUL-terminated UTF-8 strings; offset 0 = empty
//
// Type info encoding:
//   BTF_INFO_KIND(info)  = (info >> 24) & 0x1F
//   BTF_INFO_VLEN(info)  = info & 0xFFFF
//   BTF_INFO_KFLAG(info) = (info >> 31) & 1
//
// Kinds we emit to ISF:
//   INT, FLOAT    -> base_types
//   STRUCT, UNION -> user_types (with fields)
//   ENUM, ENUM64  -> enums
//   TYPEDEF       -> user_types alias (size + 'type' redirect)
//   PTR/ARRAY/CONST/VOLATILE/RESTRICT  inlined into field type refs
//
#include "symbols/btf_to_isf.h"
#include "symbols/xz_decompress.h"        // for the inverse: we want compress; reuse liblzma
#include "core/error.h"
#include "core/log.h"
#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <lzma.h>
#include <algorithm>
#include <cstring>
#include <fstream>
#include <vector>

namespace lmpfs {

namespace {

using json = nlohmann::json;

#pragma pack(push, 1)
struct BtfHeader {
    u16 magic;
    u8  version;
    u8  flags;
    u32 hdr_len;
    u32 type_off;
    u32 type_len;
    u32 str_off;
    u32 str_len;
};
struct BtfType {
    u32 name_off;
    u32 info;          // kind (bits 24-28) | vlen (bits 0-15) | kflag (bit 31)
    u32 size_or_type;  // size for INT/STRUCT/UNION/ENUM/DATASEC/FLOAT; type id otherwise
};
struct BtfArray { u32 type, index_type, nelems; };
struct BtfMember { u32 name_off, type, offset; };
struct BtfEnum  { u32 name_off; i32 val; };
struct BtfEnum64 { u32 name_off; u32 val_lo, val_hi; };
struct BtfParam { u32 name_off, type; };
#pragma pack(pop)

constexpr u16 kMagic = 0xEB9F;

enum Kind {
    K_VOID = 0, K_INT, K_PTR, K_ARRAY, K_STRUCT, K_UNION, K_ENUM,
    K_FWD, K_TYPEDEF, K_VOLATILE, K_CONST, K_RESTRICT,
    K_FUNC, K_FUNC_PROTO, K_VAR, K_DATASEC, K_FLOAT,
    K_DECL_TAG, K_TYPE_TAG, K_ENUM64
};

u32 kind_of(u32 info)   { return (info >> 24) & 0x1F; }
u32 vlen_of(u32 info)   { return info & 0xFFFF; }
bool kflag_of(u32 info) { return (info >> 31) & 1; }

// One decoded BTF entry. Variable-length data is captured as needed.
struct Decoded {
    BtfType        hdr{};
    std::string    name;
    // Per-kind extras (only the relevant fields populated):
    struct Member { std::string name; u32 type; u32 bit_offset; u32 bit_size; };
    struct EnumV  { std::string name; i64 value; };
    std::vector<Member> members;     // STRUCT/UNION
    std::vector<EnumV>  enum_vals;   // ENUM/ENUM64
    u32 array_type     = 0;          // ARRAY
    u32 array_nelems   = 0;          // ARRAY
    u32 int_encoding   = 0;          // INT (signed/char/bool flags + bit-size)
    u32 int_offset     = 0;
    u32 int_bits       = 0;
};

const char* str_at(const std::vector<char>& strs, u32 off) {
    if (off >= strs.size()) return "";
    return strs.data() + off;
}

// Walk the type section and produce one Decoded per type. Type ids are 1-based
// (id 0 is reserved for VOID).
std::vector<Decoded>
parse_types(const u8* type_buf, u32 type_len, const std::vector<char>& strs)
{
    std::vector<Decoded> out;
    // id 0 = VOID placeholder.
    out.push_back({});

    // Histogram: kind code -> count (BTF kinds top out at 19 = ENUM64; pad to 32
    // for the 5-bit kind field).
    std::size_t kind_hist[32] = {};
    int         dumped        = 0;     // for first-N-entries diagnostic dump

    u32 off = 0;
    while (off + sizeof(BtfType) <= type_len) {
        const u32 entry_off = off;
        Decoded d;
        std::memcpy(&d.hdr, type_buf + off, sizeof(BtfType));
        off += sizeof(BtfType);
        d.name = str_at(strs, d.hdr.name_off);

        const u32 k = kind_of(d.hdr.info);
        const u32 vlen = vlen_of(d.hdr.info);
        if (k < 32) kind_hist[k]++;

        // Print the first handful of entries so we can see if anything looks
        // wrong (kind 0/info 0, weird names, …).
        if (dumped < 8) {
            log::debug("BTF[{}] @+{:#x}: name_off={} info={:#010x} (kind={} vlen={}) sz/t={}"
                      " name='{}'",
                      out.size(), entry_off, d.hdr.name_off, d.hdr.info, k, vlen,
                      d.hdr.size_or_type, d.name);
            ++dumped;
        }

        switch (k) {
        case K_INT: {
            if (off + 4 > type_len) goto done;
            u32 enc = 0; std::memcpy(&enc, type_buf + off, 4); off += 4;
            d.int_encoding = (enc >> 24) & 0x0F;   // flags
            d.int_offset   = (enc >> 16) & 0xFF;   // bit offset
            d.int_bits     = enc & 0xFF;           // bit size
            break;
        }
        case K_FLOAT:
            // No variable data; size is in hdr.size_or_type.
            break;
        case K_PTR: case K_TYPEDEF: case K_VOLATILE: case K_CONST:
        case K_RESTRICT: case K_FUNC: case K_FWD: case K_TYPE_TAG:
            // No variable data.
            break;
        case K_ARRAY: {
            if (off + sizeof(BtfArray) > type_len) goto done;
            BtfArray a; std::memcpy(&a, type_buf + off, sizeof(a)); off += sizeof(a);
            d.array_type   = a.type;
            d.array_nelems = a.nelems;
            break;
        }
        case K_STRUCT: case K_UNION: {
            for (u32 i = 0; i < vlen; ++i) {
                if (off + sizeof(BtfMember) > type_len) goto done;
                BtfMember m; std::memcpy(&m, type_buf + off, sizeof(m));
                off += sizeof(m);
                Decoded::Member dm;
                dm.name = str_at(strs, m.name_off);
                dm.type = m.type;
                if (kflag_of(d.hdr.info)) {
                    // bitfield: high 24 bits = offset in bits, low 8 = bit size
                    dm.bit_offset = m.offset & 0x00FFFFFF;
                    dm.bit_size   = (m.offset >> 24) & 0xFF;
                } else {
                    dm.bit_offset = m.offset;
                    dm.bit_size   = 0;
                }
                d.members.push_back(std::move(dm));
            }
            break;
        }
        case K_ENUM: {
            for (u32 i = 0; i < vlen; ++i) {
                if (off + sizeof(BtfEnum) > type_len) goto done;
                BtfEnum e; std::memcpy(&e, type_buf + off, sizeof(e));
                off += sizeof(e);
                d.enum_vals.push_back({ str_at(strs, e.name_off), e.val });
            }
            break;
        }
        case K_ENUM64: {
            for (u32 i = 0; i < vlen; ++i) {
                if (off + sizeof(BtfEnum64) > type_len) goto done;
                BtfEnum64 e; std::memcpy(&e, type_buf + off, sizeof(e));
                off += sizeof(e);
                i64 v = (i64(e.val_hi) << 32) | e.val_lo;
                d.enum_vals.push_back({ str_at(strs, e.name_off), v });
            }
            break;
        }
        case K_FUNC_PROTO:
            off += vlen * sizeof(BtfParam);
            break;
        case K_VAR:
            off += 4;          // linkage
            break;
        case K_DATASEC:
            off += vlen * 12;  // btf_var_secinfo: type + offset + size
            break;
        case K_DECL_TAG:
            off += 4;          // component_idx
            break;
        default:
            // Unknown kind — be liberal, hope vlen entries are 0-size.
            break;
        }
        out.push_back(std::move(d));
    }
done:
    // Names for kinds 0..19 (anything past 19 is reserved/future).
    static const char* knm[32] = {
        "VOID","INT","PTR","ARRAY","STRUCT","UNION","ENUM","FWD",
        "TYPEDEF","VOLATILE","CONST","RESTRICT","FUNC","FUNC_PROTO",
        "VAR","DATASEC","FLOAT","DECL_TAG","TYPE_TAG","ENUM64",
        "20?","21?","22?","23?","24?","25?","26?","27?","28?","29?","30?","31?",
    };
    std::string hist;
    for (int i = 0; i < 32; ++i) {
        if (kind_hist[i] == 0) continue;
        if (!hist.empty()) hist += ' ';
        hist += knm[i];
        hist += '=';
        hist += std::to_string(kind_hist[i]);
    }
    log::debug("BTF: kind histogram: {}", hist);
    return out;
}

// Strip qualifiers (CONST/VOLATILE/RESTRICT/TYPE_TAG) and return the underlying
// type id we should render in JSON. Bounded recursion depth. Always returns
// an in-bounds id (0 = VOID) so the caller can safely index `types[]`.
u32 strip_quals(const std::vector<Decoded>& types, u32 id, int depth = 0) {
    if (depth > 32 || id == 0 || id >= types.size()) return 0;
    const auto& t = types[id];
    u32 k = kind_of(t.hdr.info);
    if (k == K_CONST || k == K_VOLATILE || k == K_RESTRICT || k == K_TYPE_TAG) {
        u32 nxt = t.hdr.size_or_type;
        if (nxt >= types.size()) return 0;
        return strip_quals(types, nxt, depth + 1);
    }
    return id;
}

// Build a JSON "type" object referring to type `id`. Recurses into PTR/ARRAY.
// Recursion is bounded by `depth` because typedef chains and pointer cycles
// can in principle be very deep / circular in malformed BTF.
json type_ref(const std::vector<Decoded>& types, u32 id, int depth = 0) {
    if (depth > 32)                  return json{ {"kind","base"}, {"name","void"} };
    if (id == 0)                     return json{ {"kind","base"}, {"name","void"} };
    if (id >= types.size())          return json{ {"kind","unknown"} };
    id = strip_quals(types, id);
    if (id == 0)                     return json{ {"kind","base"}, {"name","void"} };
    if (id >= types.size())          return json{ {"kind","unknown"} };
    const auto& t = types[id];
    u32 k = kind_of(t.hdr.info);
    switch (k) {
    case K_VOID:
        return json{ {"kind","base"}, {"name","void"} };
    case K_INT: case K_FLOAT:
        return json{ {"kind","base"}, {"name", t.name.empty() ? "?" : t.name} };
    case K_PTR:
        return json{ {"kind","pointer"},
                     {"subtype", type_ref(types, t.hdr.size_or_type, depth + 1)} };
    case K_ARRAY:
        return json{ {"kind","array"},
                     {"count",  t.array_nelems},
                     {"subtype", type_ref(types, t.array_type, depth + 1)} };
    case K_STRUCT:
        return json{ {"kind","struct"}, {"name", t.name.empty() ? "?" : t.name} };
    case K_UNION:
        return json{ {"kind","union"},  {"name", t.name.empty() ? "?" : t.name} };
    case K_ENUM: case K_ENUM64:
        return json{ {"kind","enum"},   {"name", t.name.empty() ? "?" : t.name} };
    case K_TYPEDEF:
        // Re-resolve through the typedef's target.
        return type_ref(types, t.hdr.size_or_type, depth + 1);
    case K_FUNC: case K_FUNC_PROTO:
        return json{ {"kind","function"} };
    case K_FWD:
        return json{ {"kind", kflag_of(t.hdr.info) ? "union" : "struct"},
                     {"name", t.name.empty() ? "?" : t.name} };
    default:
        return json{ {"kind","unknown"} };
    }
}

// Emit base_types (INT, FLOAT) keyed by name.
json build_base_types(const std::vector<Decoded>& types) {
    json b = json::object();
    std::size_t int_seen = 0, int_unnamed = 0, float_seen = 0, float_unnamed = 0;
    for (const auto& t : types) {
        u32 k = kind_of(t.hdr.info);
        if (k == K_INT) {
            ++int_seen;
            if (t.name.empty()) { ++int_unnamed; continue; }
            json e;
            e["size"]    = t.hdr.size_or_type;
            e["signed"]  = (t.int_encoding & 0x01) != 0;
            e["kind"]    = (t.int_encoding & 0x02) ? "char"
                         : (t.int_encoding & 0x04) ? "bool" : "int";
            e["endian"]  = "little";
            b[t.name] = std::move(e);
        } else if (k == K_FLOAT) {
            ++float_seen;
            if (t.name.empty()) { ++float_unnamed; continue; }
            json e;
            e["size"]   = t.hdr.size_or_type;
            e["signed"] = true;
            e["kind"]   = "float";
            e["endian"] = "little";
            b[t.name] = std::move(e);
        }
    }
    log::debug("BTF: base_types: {} INTs ({} unnamed skipped), {} FLOATs ({} unnamed skipped)",
              int_seen, int_unnamed, float_seen, float_unnamed);
    // Always include `void` for ISF consumers.
    if (!b.contains("void")) {
        b["void"] = { {"size",0}, {"signed",false}, {"kind","void"}, {"endian","little"} };
    }
    return b;
}

// Recursively flatten members of `t` into `fields`. When a field is an
// **anonymous** struct/union (name empty) we inline that nested type's members
// at the parent's offset + the member's offset, matching Volatility-3's flat
// ISF layout. Named nested structs are referenced as kind=struct/union.
//
// This is critical for modern kernels where `mm_struct`, `task_struct`, etc.
// nest large anonymous structs for organizational reasons — without flattening,
// well-known fields like `mm_struct.mm_mt` get hidden inside `unnamed_*`.
void flatten_members_into(const std::vector<Decoded>& types,
                          const Decoded& t,
                          u64 base_bit_off,
                          json& fields,
                          int depth = 0)
{
    if (depth > 8) return;   // pathological: refuse to recurse forever
    for (const auto& m : t.members) {
        const u64 mem_bit_off = base_bit_off + m.bit_offset;

        // Inline anonymous nested struct/union types (name_off==0 in BTF).
        if (m.name.empty() && m.type != 0 && m.type < types.size()) {
            u32 tid = strip_quals(types, m.type);
            if (tid != 0 && tid < types.size()) {
                const auto& nested = types[tid];
                u32 nk = kind_of(nested.hdr.info);
                if ((nk == K_STRUCT || nk == K_UNION) && nested.name.empty()) {
                    // Anonymous nested: lift its fields up to us.
                    flatten_members_into(types, nested, mem_bit_off, fields, depth + 1);
                    continue;
                }
            }
        }

        json f;
        f["offset"] = mem_bit_off / 8;
        if (m.bit_size != 0) {
            f["type"] = json{
                {"kind","bitfield"},
                {"bit_position", mem_bit_off % 8},
                {"bit_length",   m.bit_size},
                {"type", type_ref(types, m.type)}
            };
        } else {
            f["type"] = type_ref(types, m.type);
        }
        std::string fname = m.name.empty()
            ? "__unnamed_" + std::to_string(fields.size())
            : m.name;
        if (fields.contains(fname)) {
            // Field collision after flattening (e.g. two anonymous unions with
            // same-named members) — suffix to keep both.
            fname += "_" + std::to_string(fields.size());
        }
        fields[fname] = std::move(f);
    }
}

// Build user_types: STRUCT, UNION (with fields). Same name dedup is best-effort —
// in the wild, BTF can include multiple anonymous structs; we suffix-disambiguate.
json build_user_types(const std::vector<Decoded>& types) {
    json out = json::object();
    int anon_counter = 0;
    std::size_t skipped_anon = 0;
    for (const auto& t : types) {
        u32 k = kind_of(t.hdr.info);
        if (k != K_STRUCT && k != K_UNION) continue;
        // Skip top-level anonymous structs/unions — they'll be inlined into
        // whichever named parent embeds them. Keeping them as top-level
        // entries bloats the ISF (we had ~9000 unnamed_* entries) and lets
        // duplicate-named ones shadow each other.
        if (t.name.empty()) {
            ++skipped_anon;
            continue;
        }
        std::string nm = t.name;
        if (out.contains(nm)) {
            // Same name reused (rare; e.g. two static structs in different TUs).
            nm += "__" + std::to_string(++anon_counter);
        }
        json e;
        e["kind"]   = (k == K_STRUCT) ? "struct" : "union";
        e["size"]   = t.hdr.size_or_type;
        json fields = json::object();
        flatten_members_into(types, t, /*base_bit_off=*/0, fields);
        e["fields"] = std::move(fields);
        out[nm] = std::move(e);
    }
    log::debug("BTF: user_types: {} named, {} top-level anonymous skipped (inlined)",
              out.size(), skipped_anon);
    return out;
}

json build_enums(const std::vector<Decoded>& types) {
    json out = json::object();
    int anon = 0;
    for (const auto& t : types) {
        u32 k = kind_of(t.hdr.info);
        if (k != K_ENUM && k != K_ENUM64) continue;
        std::string nm = t.name;
        if (nm.empty()) nm = "anon_enum_" + std::to_string(++anon);
        if (out.contains(nm)) nm += "__" + std::to_string(++anon);
        json e;
        e["size"]  = t.hdr.size_or_type ? t.hdr.size_or_type
                                        : (k == K_ENUM64 ? 8 : 4);
        e["base"]  = "int";
        json consts = json::object();
        for (const auto& v : t.enum_vals) consts[v.name] = v.value;
        e["constants"] = std::move(consts);
        out[nm] = std::move(e);
    }
    return out;
}

// xz-compress in memory. Returns the compressed buffer.
std::vector<u8> xz_compress(const std::string& src) {
    lzma_stream s = LZMA_STREAM_INIT;
    if (lzma_easy_encoder(&s, 6 /*preset*/, LZMA_CHECK_CRC64) != LZMA_OK)
        throw_error("xz: easy_encoder init failed");
    s.next_in  = reinterpret_cast<const u8*>(src.data());
    s.avail_in = src.size();
    std::vector<u8> out;
    out.reserve(src.size() / 4 + 1024);
    std::vector<u8> chunk(256 * 1024);
    s.next_out = chunk.data();
    s.avail_out = chunk.size();
    while (true) {
        lzma_ret r = lzma_code(&s, LZMA_FINISH);
        std::size_t produced = chunk.size() - s.avail_out;
        if (produced) out.insert(out.end(), chunk.begin(), chunk.begin() + produced);
        s.next_out  = chunk.data();
        s.avail_out = chunk.size();
        if (r == LZMA_STREAM_END) break;
        if (r != LZMA_OK) { lzma_end(&s); throw_error("xz encode error {}", int(r)); }
    }
    lzma_end(&s);
    return out;
}

} // anonymous

BtfIsfResult btf_to_isf(const ByteBuf&               btf_blob,
                        const std::string&           kernel_release,
                        const std::filesystem::path& out_path,
                        const linux::KallsymsResult* kallsyms)
{
    BtfIsfResult r;
    if (btf_blob.size() < sizeof(BtfHeader)) {
        r.error = "BTF blob too small for header";
        return r;
    }
    BtfHeader hdr;
    std::memcpy(&hdr, btf_blob.data(), sizeof(hdr));
    if (hdr.magic != kMagic) { r.error = "bad BTF magic"; return r; }
    if (hdr.version != 1)    { r.error = "unsupported BTF version"; return r; }
    if (hdr.hdr_len < sizeof(BtfHeader)) { r.error = "short BTF hdr"; return r; }
    if (hdr.hdr_len > btf_blob.size())   { r.error = "BTF hdr_len past blob"; return r; }

    const u8* base = btf_blob.data() + hdr.hdr_len;
    // Overflow-safe section bounds. All fields are u32; widen to u64 and check
    // as `off > avail || len > avail - off` so a crafted header can't wrap the
    // sum (the old `off + len` was u32+u32) or underflow `size - hdr_len`
    // (guarded above) — either of which let an out-of-bounds section through to
    // memcpy/parse_types and faulted on a malicious dump.
    const u64 avail    = btf_blob.size() - hdr.hdr_len;
    const u64 type_off = hdr.type_off, type_len = hdr.type_len;
    const u64 str_off  = hdr.str_off,  str_len  = hdr.str_len;
    if (type_off > avail || type_len > avail - type_off ||
        str_off  > avail || str_len  > avail - str_off) {
        r.error = "BTF sections out of bounds";
        return r;
    }

    std::vector<char> strs(hdr.str_len);
    std::memcpy(strs.data(), base + hdr.str_off, hdr.str_len);
    log::debug("BTF: parsing {} bytes of types + {} bytes of strings",
              hdr.type_len, hdr.str_len);

    auto types = parse_types(base + hdr.type_off, hdr.type_len, strs);
    log::debug("BTF: {} types parsed (incl. VOID at id 0)", types.size());

    log::debug("BTF: building base_types...");
    auto bt = build_base_types(types);
    log::debug("BTF: {} base_types", bt.size());

    log::debug("BTF: building user_types...");
    auto ut = build_user_types(types);
    log::debug("BTF: {} user_types", ut.size());

    log::debug("BTF: building enums...");
    auto en = build_enums(types);
    log::debug("BTF: {} enums", en.size());

    // Sanity: a real kernel BTF has 20+ INT types and thousands of structs.
    // If we see less, treat this blob as bogus (parser desync or false-positive
    // probe hit) and let the caller try the next candidate. The "void" entry
    // is always auto-added so the bar is `bt.size() > 1`.
    if (bt.size() <= 4 || ut.size() < 100) {
        r.error = fmt::format("BTF parse looks degenerate: {} base_types, {} user_types"
                              " (expected 20+/10000+ for a real kernel BTF)",
                              bt.size(), ut.size());
        log::warn("{}", r.error);
        return r;
    }

    json isf;
    isf["metadata"] = json::object();
    isf["metadata"]["linux"] = json::object();
    isf["metadata"]["linux"]["symbols"] = json::array({
        json{ {"kind","btf"}, {"name", "vmlinux-" + kernel_release},
              {"hash_type","none"}, {"hash_value",""} }
    });
    isf["metadata"]["linux"]["types"] = json::array({
        json{ {"kind","btf"}, {"name", "vmlinux-" + kernel_release},
              {"hash_type","none"}, {"hash_value",""} }
    });
    isf["metadata"]["producer"] = json{ {"name","lmpfs-btf-to-isf"}, {"version","0.1"} };
    isf["metadata"]["format"]   = "6.2.0";

    isf["base_types"] = std::move(bt);
    isf["user_types"] = std::move(ut);
    isf["enums"]      = std::move(en);

    // Symbols: empty by default (BTF has no addresses). If a successful
    // kallsyms extraction is provided, populate from there. We only include
    // entries with sensible C-identifier names — kallsyms ships ~210k entries
    // of which roughly 1/3 are GCC-internal build artefacts (`__pfx_*`,
    // `__cfi_*`, `.cold.*`, `.constprop.*`, anonymous lambdas, etc.) that
    // bloat the ISF without helping the engine. We keep the originals
    // (no fancy renaming); ISF consumers look up by exact name.
    json sym_obj = json::object();
    std::size_t sym_kept = 0, sym_skipped = 0;
    auto looks_like_c_identifier = [](const std::string& n) {
        if (n.empty() || n.size() > 256) return false;
        // Reject names starting with non-identifier chars or containing
        // characters outside [A-Za-z0-9_$.] (the last two are common in
        // mangled kernel symbol names like `init.rodata`).
        for (char c : n) {
            bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                      (c >= '0' && c <= '9') || c == '_' || c == '$' || c == '.';
            if (!ok) return false;
        }
        return true;
    };
    if (kallsyms && kallsyms->ok && kallsyms->relative_base != 0) {
        log::debug("BTF→ISF: merging {} kallsyms entries into symbols section",
                  kallsyms->symbols.size());
        for (const auto& e : kallsyms->symbols) {
            if (!looks_like_c_identifier(e.name)) { ++sym_skipped; continue; }
            // First-occurrence wins (kallsyms can have static-inline duplicates
            // across translation units — the first is canonical).
            if (sym_obj.contains(e.name))      { ++sym_skipped; continue; }
            sym_obj[e.name] = { {"address", e.address} };
            ++sym_kept;
        }
        log::debug("BTF→ISF: {} symbols emitted ({} filtered out as build-artefact / duplicate)",
                  sym_kept, sym_skipped);
    } else if (kallsyms && kallsyms->ok) {
        log::warn("BTF→ISF: kallsyms extracted in names-only mode (no relative_base) — "
                  "symbols section will be EMPTY; the engine will fall back to "
                  "swapper-anchored discovery");
    }
    isf["symbols"]    = std::move(sym_obj);

    log::debug("BTF: serializing JSON ({}/{}/{} entries)...",
              isf["base_types"].size(), isf["user_types"].size(), isf["enums"].size());
    std::string raw = isf.dump();
    log::debug("BTF: serialized {} MB", raw.size() / (1024 * 1024));

    std::filesystem::create_directories(out_path.parent_path());
    if (out_path.extension() == ".xz") {
        auto comp = xz_compress(raw);
        std::ofstream f(out_path, std::ios::binary);
        f.write(reinterpret_cast<const char*>(comp.data()), comp.size());
    } else {
        std::ofstream f(out_path);
        f << raw;
    }

    r.ok                    = true;
    r.path                  = out_path;
    r.type_count            = types.size();
    r.symbol_count          = sym_kept;
    r.string_table_bytes    = hdr.str_len;
    log::debug("BTF→ISF: wrote {} ({} types, {} symbols, {}B strings)",
              out_path.string(), types.size(), sym_kept, hdr.str_len);
    return r;
}

} // namespace lmpfs
