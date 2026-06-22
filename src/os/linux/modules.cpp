// modules.cpp — see header.
//
// `struct module` layout (kernel 6.x, x86_64; offsets from the dump's ISF):
//   .state           @ 0x000   (enum module_state: 0=LIVE 1=COMING 2=GOING)
//   .list            @ 0x008   (list_head: linked into the global `modules`)
//   .name[56]        @ 0x018   (inline char array, NUL-terminated)
//   .version         @ 0x0B8   (char* — pointer, not inline)
//   .srcversion      @ 0x0C0   (char* — pointer, not inline)
//   .mem[7]          @ 0x140   (module_memory mem[MOD_MEM_NUM_TYPES])
//                              each module_memory is 72 bytes:
//                                .base @0x00  (void*)
//                                .size @0x08  (u32)
//                                .mtn  @0x10  (struct module_memory_section_name)
//   .args            @ 0x3E0   (char*)
//
// IMPORTANT — vmalloc translation:
//   The `modules` list head sits in the kernel image (.bss). Its .next points
//   to the first loaded module's list_head, in the modules/vmalloc region
//   (0xffffffffc0000000+). That region has no linear PA mapping — only a PGD
//   walk works. Worse, the brute-force-resolved DTB may walk the kernel
//   image fine but lack vmalloc PUD entries. The shared kva_reader handles
//   this by falling back to init_mm.pgd (the kernel's master PGD).
//
#include "os/linux/modules.h"
#include "app/engine.h"
#include "symbols/isf_symbols.h"
#include "os/linux/kva_reader.h"
#include "core/log.h"
#include <fmt/format.h>
#include <cstring>

namespace lmpfs::linux {

namespace {

// Wrappers so existing code keeps reading nicely.
inline bool kread(const Engine& eng, VAddr va, void* dst, std::size_t n) {
    return kva_read(eng, va, dst, n);
}
template <typename T>
inline bool kread_pod(const Engine& eng, VAddr va, T& out) {
    return kva_read_pod(eng, va, out);
}
inline std::string kread_inline_str(const Engine& eng, VAddr va, std::size_t maxlen) {
    return kva_read_cstr(eng, va, maxlen);
}
inline std::string kread_cstr(const Engine& eng, VAddr va, std::size_t maxlen) {
    return kva_read_cstr(eng, va, maxlen);
}

const char* state_name(u32 state) {
    switch (state) {
    case 0:  return "LIVE";
    case 1:  return "COMING";
    case 2:  return "GOING";
    default: return "UNFORMED";
    }
}

} // anon

std::vector<LoadedModule> enumerate_modules(const Engine& eng) {
    std::vector<LoadedModule> out;
    const auto& isf  = eng.isf();
    const auto& kctx = eng.kernel();

    auto* modules_sym = isf.find_symbol("modules");
    if (!modules_sym) {
        log::warn("modules: ISF lacks `modules` symbol");
        return out;
    }

    u64 mod_state_off, mod_list_off, mod_name_off,
        mod_version_off, mod_srcversion_off, mod_args_off, mod_mem_off;
    u64 mm_base_off, mm_size_off, mm_stride;
    try {
        mod_state_off      = isf.field_offset("module", "state");
        mod_list_off       = isf.field_offset("module", "list");
        mod_name_off       = isf.field_offset("module", "name");
        mod_version_off    = isf.field_offset("module", "version");
        mod_srcversion_off = isf.field_offset("module", "srcversion");
        mod_args_off       = isf.field_offset("module", "args");
        mod_mem_off        = isf.field_offset("module", "mem");
        mm_base_off        = isf.field_offset("module_memory", "base");
        mm_size_off        = isf.field_offset("module_memory", "size");
        mm_stride          = isf.type_size("module_memory");
    } catch (const std::exception& e) {
        log::warn("modules: ISF missing struct field — {}", e.what());
        return out;
    }

    // The `modules` global IS a list_head (not a pointer). The head's
    // .next is the first module.list, which sits at offset mod_list_off
    // within the struct module. Symbol addresses from a kallsyms-
    // populated ISF are already runtime VAs (post-KASLR), so we don't
    // add kaslr_virt_shift here.
    (void)kctx;
    VAddr head_va = modules_sym->address;
    VAddr cur = 0;
    log::debug("modules: head_va = {:#x}", head_va);
    if (!kread_pod(eng, head_va, cur)) {
        log::warn("modules: cannot read modules list head @ {:#x}", head_va);
        return out;
    }
    log::debug("modules: first list_head.next = {:#x}", cur);

    std::size_t loop_guard = 0;
    while (cur != 0 && cur != head_va && loop_guard++ < 4096) {
        VAddr mod_va = cur - mod_list_off;

        LoadedModule m{};
        m.module_va = mod_va;

        if (!kread_pod(eng, mod_va + mod_state_off, m.state)) {
            log::debug("modules: read state @ {:#x} FAILED — stopping walk",
                       mod_va + mod_state_off);
            break;
        }

        // Name is inline char[56]
        m.name = kread_inline_str(eng, mod_va + mod_name_off, 56);

        // version + srcversion + args are all char* in 6.x kernels.
        VAddr ver_va = 0, srv_va = 0, args_va = 0;
        kread_pod(eng, mod_va + mod_version_off,    ver_va);
        kread_pod(eng, mod_va + mod_srcversion_off, srv_va);
        kread_pod(eng, mod_va + mod_args_off,       args_va);
        if (ver_va  != 0) m.version    = kread_cstr(eng, ver_va,  64);
        if (srv_va  != 0) m.srcversion = kread_cstr(eng, srv_va,  64);
        if (args_va != 0) m.args       = kread_cstr(eng, args_va, 256);

        // mem[7] — read each base/size
        for (u32 i = 0; i < MOD_MEM_NUM_TYPES; ++i) {
            VAddr mm_va = mod_va + mod_mem_off + i * mm_stride;
            kread_pod(eng, mm_va + mm_base_off, m.mem[i].base);
            kread_pod(eng, mm_va + mm_size_off, m.mem[i].size);
        }

        // Sanity: skip entries whose name doesn't look like a module name
        // (alphanumeric + underscore + dash, 1-56 chars).
        bool name_ok = !m.name.empty();
        for (char c : m.name) {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '_' || c == '-')) {
                name_ok = false; break;
            }
        }
        if (name_ok) out.push_back(std::move(m));

        // Walk to next
        VAddr next = 0;
        if (!kread_pod(eng, mod_va + mod_list_off, next)) break;
        if (next == cur) break;          // sanity: self-loop
        cur = next;
    }

    log::info("modules: enumerated {} loaded module(s)", out.size());
    return out;
}

ByteBuf format_modules_summary(const Engine& eng) {
    auto mods = enumerate_modules(eng);
    if (mods.empty()) {
        const char msg[] =
            "; no loaded modules found.\n"
            "; either the kernel has no out-of-tree modules, or `modules`\n"
            "; symbol is missing / list walk failed.\n";
        return ByteBuf(msg, msg + sizeof(msg) - 1);
    }
    std::string out;
    out.reserve(64 * 1024);
    out += fmt::format("# {} loaded modules. Format:\n", mods.size());
    out += "# <name>  <total_size_kb>  <state>  <text_base_va>  <version>\n";
    out += "#\n";
    for (const auto& m : mods) {
        u64 total = 0;
        for (const auto& mem : m.mem) total += mem.size;
        out += fmt::format("{:<24} {:>6}  {:<8}  {:#018x}  {}\n",
                           m.name, total / 1024, state_name(m.state),
                           m.mem[MOD_TEXT].base, m.version);
    }
    return ByteBuf(out.begin(), out.end());
}

ByteBuf format_module_info(const LoadedModule& m) {
    std::string out;
    out.reserve(2048);
    out += fmt::format("Name:        {}\n", m.name);
    out += fmt::format("Version:     {}\n", m.version);
    out += fmt::format("Srcversion:  {}\n", m.srcversion);
    out += fmt::format("State:       {} ({})\n", state_name(m.state), m.state);
    out += fmt::format("Module VA:   {:#018x}\n", m.module_va);
    out += fmt::format("Args:        {}\n", m.args);
    out += "\nMemory layout:\n";

    static const char* mem_names[MOD_MEM_NUM_TYPES] = {
        "TEXT",  "DATA",      "RODATA",        "RO_AFTER_INIT",
        "INIT_TEXT", "INIT_DATA", "INIT_RODATA"
    };
    u64 total = 0;
    for (u32 i = 0; i < MOD_MEM_NUM_TYPES; ++i) {
        out += fmt::format("  {:<14} {:#018x}  {:>10} bytes\n",
                           mem_names[i], m.mem[i].base, m.mem[i].size);
        total += m.mem[i].size;
    }
    out += fmt::format("  {:<14} {:>30} bytes\n", "TOTAL", total);
    return ByteBuf(out.begin(), out.end());
}

} // namespace lmpfs::linux
