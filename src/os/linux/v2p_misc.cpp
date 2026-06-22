// v2p_misc.cpp — see header.
#include "os/linux/v2p_misc.h"
#include "os/linux/kva_reader.h"
#include "os/linux/kernel_resolver.h"
#include "app/engine.h"
#include "core/types.h"
#include "core/log.h"
#include <fmt/format.h>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>

namespace lmpfs::linux {

namespace {

// Parse a directory-component name as a hex address. Accepts:
//   * 0x-prefixed:  "0xffffffffa7fb3580"
//   * Bare hex:     "ffffffffa7fb3580"
//   * With trailing ".txt" (so it shows up as a "file" in Explorer)
// Returns nullopt on any other format.
std::optional<u64> parse_hex_name(std::string n) {
    // Strip ".txt" so users can append it for a nicer Explorer experience.
    if (n.size() > 4) {
        std::string suf = n.substr(n.size() - 4);
        for (auto& c : suf) c = static_cast<char>(std::tolower((unsigned char)c));
        if (suf == ".txt") n.resize(n.size() - 4);
    }
    if (n.size() > 2 && (n[0] == '0') && (n[1] == 'x' || n[1] == 'X')) {
        n = n.substr(2);
    }
    if (n.empty() || n.size() > 16) return std::nullopt;
    u64 v = 0;
    for (char c : n) {
        v <<= 4;
        if      (c >= '0' && c <= '9') v |= (c - '0');
        else if (c >= 'a' && c <= 'f') v |= (c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= (c - 'A' + 10);
        else return std::nullopt;
    }
    return v;
}

// Builds the per-query result text for /misc/virt2phys/<name>.
ByteBuf render_virt2phys(const Engine& eng, VAddr va) {
    auto r = kva_translate(eng, va);
    std::string out;
    if (!r.ok) {
        out = fmt::format(
            "VA       : {:#x}\n"
            "PA       : (unmapped — no strategy resolved this VA)\n"
            "Strategy : unmapped\n"
            "\n"
            "Hints:\n"
            "  * Canonical kernel half starts at 0xffff800000000000.\n"
            "  * direct-map runs from direct_map_base ({:#x}) to\n"
            "    0xffffffff80000000.\n"
            "  * kernel image is 0xffffffff80000000 – 0xffffffffc0000000\n"
            "    (linear via kaslr_phys_shift = {:#x}).\n"
            "  * vmalloc / modules > 0xffffffffc0000000 (PGD walk).\n",
            va, eng.kernel().direct_map_base, eng.kernel().kaslr_phys_shift);
    } else {
        const char* notes = "";
        if (std::string_view(r.strategy) == "direct-map")
            notes = "linear: PA = VA - direct_map_base";
        else if (std::string_view(r.strategy) == "kernel-image")
            notes = "linear: PA = VA - 0xffffffff80000000 + kaslr_phys_shift";
        else if (std::string_view(r.strategy) == "vmalloc-dtb" ||
                 std::string_view(r.strategy) == "fallback-dtb")
            notes = "page-table walk via the brute-force-resolved kernel DTB";
        else
            notes = "page-table walk via init_mm.pgd (kernel master PGD)";

        out = fmt::format(
            "VA       : {:#x}\n"
            "PA       : {:#x}\n"
            "Strategy : {}\n"
            "Notes    : {}\n",
            va, r.pa, r.strategy, notes);
    }
    return ByteBuf(out.begin(), out.end());
}

// Builds the per-query result text for /misc/phys2virt/<name>.
ByteBuf render_phys2virt(const Engine& eng, PAddr pa) {
    const auto& k = eng.kernel();
    std::string out = fmt::format("PA       : {:#x}\n", pa);

    // 1) Direct-map alias (always exists for any PA the kernel has access to,
    //    which is essentially every PA in a typical x86_64 dump).
    if (k.direct_map_base != 0) {
        u8 probe;
        VAddr va = static_cast<VAddr>(k.direct_map_base + pa);
        bool present = eng.phys().read(pa, &probe, 1) == 1;
        out += fmt::format(
            "direct-map  : {:#x}  ({})\n",
            va, present ? "present in dump" : "not in dump's physical span");
    } else {
        out += "direct-map  : (direct_map_base unresolved — older / minimal dump)\n";
    }

    // 2) Kernel-image alias: only valid if PA lies in the image's physical
    //    range. Image VA span is 0xffffffff80000000 .. 0xffffffffc0000000,
    //    so the image PA range is [kaslr_phys_shift, kaslr_phys_shift +
    //    1 GiB). Anything outside that span has NO image alias.
    {
        i64 image_size = 0x40000000;       // 1 GiB image window
        i64 img_pa_lo  = static_cast<i64>(k.kaslr_phys_shift);
        i64 img_pa_hi  = img_pa_lo + image_size;
        i64 ipa        = static_cast<i64>(pa);
        if (ipa >= img_pa_lo && ipa < img_pa_hi) {
            VAddr va = 0xffffffff80000000ULL + static_cast<u64>(ipa - img_pa_lo);
            out += fmt::format("kernel-image: {:#x}\n", va);
        } else {
            out += "kernel-image: (PA outside image span)\n";
        }
    }

    out +=
        "\n"
        "Note: a full reverse map (vmalloc / per-process VAs) would require\n"
        "walking every PGD on the system. That's deferred; the two aliases\n"
        "above cover kernel data (direct-map) and kernel code (image).\n";
    return ByteBuf(out.begin(), out.end());
}

// Helper: build the README that lives at /misc/virt2phys/README.txt and
// /misc/phys2virt/README.txt.
ByteBuf v2p_readme() {
    static const char* txt =
        "Path-encoded address translation.\n"
        "\n"
        "/misc/virt2phys/<hex-va>[.txt]    kernel-VA → PA\n"
        "/misc/phys2virt/<hex-pa>[.txt]    PA       → kernel-VA(s)\n"
        "\n"
        "Examples:\n"
        "  cat /misc/virt2phys/0xffffffffa7fb3580\n"
        "  cat /misc/virt2phys/ffff8a0da4210f00.txt\n"
        "  cat /misc/phys2virt/0x48bb3580\n"
        "\n"
        "Hex is parsed case-insensitively with or without `0x` prefix.\n"
        "Append `.txt` if your editor prefers a recognised extension.\n"
        "\n"
        "These directories appear empty in Explorer because every query\n"
        "is a synthesised file — type or paste the path directly.\n";
    return ByteBuf(txt, txt + std::strlen(txt));
}

ByteBuf p2v_readme() { return v2p_readme(); }   // Same body for both.

// ---- dynamic-directory node types ----------------------------------------

class Virt2PhysDir : public vfs::DirNode {
public:
    explicit Virt2PhysDir(const Engine& eng) : DirNode("virt2phys"), eng_(eng) {
        // README is materially the only fixed child — everything else is
        // path-synthesised. Storing it as a child means it shows up under
        // `dir` listings and is browsable in Explorer.
        add(std::make_shared<vfs::LazyFileNode>("README.txt",
            [](){ return v2p_readme(); }));
    }

    // find() handles synthesised "<hex>" / "<hex>.txt" children; everything
    // else (including README.txt) falls through to DirNode::find().
    vfs::NodePtr find(const std::string& name) override {
        if (auto p = DirNode::find(name)) return p;
        auto va = parse_hex_name(name);
        if (!va) return nullptr;
        VAddr v = *va;
        // Capture by value so the closure has no dangling reference.
        const Engine& eng = eng_;
        return std::make_shared<vfs::LazyFileNode>(name,
            [&eng, v]() -> ByteBuf { return render_virt2phys(eng, v); });
    }
private:
    const Engine& eng_;
};

class Phys2VirtDir : public vfs::DirNode {
public:
    explicit Phys2VirtDir(const Engine& eng) : DirNode("phys2virt"), eng_(eng) {
        add(std::make_shared<vfs::LazyFileNode>("README.txt",
            [](){ return p2v_readme(); }));
    }
    vfs::NodePtr find(const std::string& name) override {
        if (auto p = DirNode::find(name)) return p;
        auto pa = parse_hex_name(name);
        if (!pa) return nullptr;
        PAddr p = *pa;
        const Engine& eng = eng_;
        return std::make_shared<vfs::LazyFileNode>(name,
            [&eng, p]() -> ByteBuf { return render_phys2virt(eng, p); });
    }
private:
    const Engine& eng_;
};

} // anonymous

vfs::NodePtr build_virt2phys_dir(const Engine& eng) {
    return std::make_shared<Virt2PhysDir>(eng);
}

vfs::NodePtr build_phys2virt_dir(const Engine& eng) {
    return std::make_shared<Phys2VirtDir>(eng);
}

} // namespace lmpfs::linux
