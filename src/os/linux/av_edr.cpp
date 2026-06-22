// av_edr.cpp — see header.
#include "os/linux/av_edr.h"
#include "os/linux/task_files.h"
#include "os/linux/modules.h"
#include "app/engine.h"
#include "symbols/isf_symbols.h"
#include "core/log.h"
#include <fmt/format.h>
#include <algorithm>
#include <cstring>
#include <string_view>

namespace lmpfs::linux {

namespace {

// Signature table. Each row is (substring, kind, vendor, product).
//
// `kind` is a tiny bit-mask: 1 = match process comm/cmdline; 2 = match
// kernel-module name; 3 = both. Most vendors ship a userland daemon AND
// at least one LKM, so the dual-flag rows are common.
//
// Matching is plain case-insensitive substring (no regex) — fast, no
// dependencies, and the false-positive rate is essentially zero given
// how vendor-specific these strings are. If we ever need regex, that's
// a one-line swap to <regex>.
//
// New signatures: keep alphabetical-by-product within a vendor block.
struct Sig {
    const char* needle;
    u8          kind;    // 1=proc, 2=mod, 3=both
    const char* vendor;
    const char* product;
};

constexpr Sig kSigs[] = {
    // -- CrowdStrike Falcon ---------------------------------------------
    { "falcon-sensor",          3, "CrowdStrike",       "Falcon Sensor"   },
    { "falconctl",              1, "CrowdStrike",       "Falcon Sensor"   },
    { "falcond",                1, "CrowdStrike",       "Falcon Sensor"   },
    { "falcon_kal",             2, "CrowdStrike",       "Falcon Sensor"   },
    { "falcon_lsm",             2, "CrowdStrike",       "Falcon Sensor"   },

    // -- SentinelOne ----------------------------------------------------
    { "sentinelagent",          1, "SentinelOne",       "Singularity"     },
    { "s1agent",                1, "SentinelOne",       "Singularity"     },
    { "sentinelone",            3, "SentinelOne",       "Singularity"     },

    // -- Microsoft Defender for Endpoint --------------------------------
    { "mdatp",                  3, "Microsoft",         "Defender for Endpoint" },
    { "wdavdaemon",             1, "Microsoft",         "Defender for Endpoint" },
    { "mdatp_audisp",           1, "Microsoft",         "Defender for Endpoint" },

    // -- Carbon Black / VMware ------------------------------------------
    { "cbagentd",               1, "VMware",            "Carbon Black"    },
    { "cbsensor",               1, "VMware",            "Carbon Black"    },
    { "cbdefense",              1, "VMware",            "Carbon Black Defense" },
    { "cbeventfwd",             1, "VMware",            "Carbon Black"    },

    // -- Trend Micro ----------------------------------------------------
    { "ds_agent",               1, "Trend Micro",       "Deep Security"   },
    { "dsa_filter",             2, "Trend Micro",       "Deep Security"   },
    { "dsa_mod",                2, "Trend Micro",       "Deep Security"   },

    // -- Cisco AMP / Secure Endpoint ------------------------------------
    { "ampdaemon",              1, "Cisco",             "AMP for Endpoints" },
    { "ampscansvc",             1, "Cisco",             "AMP for Endpoints" },

    // -- ESET ------------------------------------------------------------
    { "eset_rtm",               1, "ESET",              "Endpoint Security" },
    { "esetsm",                 1, "ESET",              "Endpoint Security" },
    { "esrpcsvc",               1, "ESET",              "Endpoint Security" },

    // -- Sophos ----------------------------------------------------------
    { "sav-protect",            1, "Sophos",            "Anti-Virus"      },
    { "savdid",                 1, "Sophos",            "Anti-Virus"      },
    { "savd",                   1, "Sophos",            "Anti-Virus"      },

    // -- Bitdefender -----------------------------------------------------
    { "bdsec",                  1, "Bitdefender",       "GravityZone"     },
    { "bdsecnotify",            1, "Bitdefender",       "GravityZone"     },
    { "bdcfgd",                 1, "Bitdefender",       "GravityZone"     },

    // -- Kaspersky -------------------------------------------------------
    { "kavd",                   1, "Kaspersky",         "Endpoint Security" },
    { "kesl",                   1, "Kaspersky",         "Endpoint Security" },

    // -- McAfee / Trellix ------------------------------------------------
    { "mfeesp",                 1, "Trellix",           "ENS for Linux"   },
    { "mfetpd",                 1, "Trellix",           "ENS for Linux"   },
    { "mvehost",                1, "Trellix",           "MOVE"            },
    { "cmasvc",                 1, "Trellix",           "MOVE"            },

    // -- Tanium ----------------------------------------------------------
    { "taniumclient",           1, "Tanium",            "Endpoint"        },

    // -- Lacework --------------------------------------------------------
    { "laceworkctl",            1, "Lacework",          "FortiCNAPP"      },
    { "datacollector",          1, "Lacework",          "FortiCNAPP"      },

    // -- Sysdig / Falco (open-source EDR-like) ---------------------------
    { "sysdig-agent",           1, "Sysdig",            "Secure"          },
    { "falco",                  3, "Sysdig",            "Falco"           },

    // -- Aqua Velociraptor (open-source DFIR endpoint) -------------------
    { "velociraptor",           1, "Velocidex",         "Velociraptor"    },

    // -- Wazuh / OSSEC ---------------------------------------------------
    { "wazuh-agentd",           1, "Wazuh",             "Agent"           },
    { "ossec-agentd",           1, "OSSEC",             "Agent"           },

    // -- Osquery (Tableau / monitoring) ----------------------------------
    { "osqueryd",               1, "Linux Foundation",  "osquery"         },

    // -- Sumo Logic ------------------------------------------------------
    { "sumologic-otelcol",      1, "Sumo Logic",        "Collector"       },

    // -- Elastic / Beats -------------------------------------------------
    { "auditbeat",              1, "Elastic",           "Auditbeat"       },
    { "filebeat",               1, "Elastic",           "Filebeat"        },
    { "elastic-agent",          1, "Elastic",           "Elastic Agent"   },

    // -- Cybereason ------------------------------------------------------
    { "cybereason",             3, "Cybereason",        "EDR"             },
    { "cb-active-respo",        1, "Cybereason",        "Active Response" },

    // -- Open-source Linux audit ----------------------------------------
    { "auditd",                 1, "Linux",             "audit subsystem" },
};

// Case-insensitive substring search. Returns true if `needle` appears
// anywhere in `hay`.
bool icontains(std::string_view hay, std::string_view needle) {
    if (needle.empty() || hay.size() < needle.size()) return false;
    auto lc = [](unsigned char c) { return static_cast<unsigned char>(std::tolower(c)); };
    for (size_t i = 0; i + needle.size() <= hay.size(); ++i) {
        size_t j = 0;
        for (; j < needle.size(); ++j) {
            if (lc(hay[i + j]) != lc(needle[j])) break;
        }
        if (j == needle.size()) return true;
    }
    return false;
}

// Read the first argv element of a process (the exe path) as a single
// UTF-8 string. Empty on failure or kernel thread.
std::string read_argv0(const Engine& eng, const Process& p) {
    if (p.mm == 0) return {};
    ByteBuf raw;
    try { raw = gen_cmdline(eng.phys(), eng.isf(), eng.kernel(), p); }
    catch (...) { return {}; }
    if (raw.empty()) return {};
    // gen_cmdline is NUL-separated argv. argv[0] = up to the first NUL.
    std::string s;
    s.reserve(raw.size());
    for (u8 c : raw) {
        if (c == 0) break;
        if (c < 0x20 || c == 0x7F) s.push_back('?');
        else s.push_back(static_cast<char>(c));
    }
    return s;
}

} // anonymous

std::vector<AvEdrHit> scan_av_edr(const Engine& eng) {
    std::vector<AvEdrHit> hits;

    // ---- pass 1: processes ------------------------------------------------
    for (const auto& p : eng.processes()) {
        // Read argv0 once per process. comm is always available.
        std::string argv0 = read_argv0(eng, p);
        for (const auto& sig : kSigs) {
            if (!(sig.kind & 1)) continue;
            std::string_view needle{ sig.needle };
            bool hit = icontains(p.comm, needle) ||
                       (!argv0.empty() && icontains(argv0, needle));
            if (!hit) continue;
            AvEdrHit h;
            h.source   = AvEdrHit::Source::Process;
            h.vendor   = sig.vendor;
            h.product  = sig.product;
            h.pid      = p.pid;
            h.uid      = p.uid;
            h.comm     = p.comm;
            h.evidence = argv0.empty() ? p.comm : argv0;
            hits.push_back(std::move(h));
            break;  // one hit per process (don't double-report SentinelOne)
        }
    }

    // ---- pass 2: kernel modules ------------------------------------------
    try {
        auto mods = enumerate_modules(eng);
        for (const auto& m : mods) {
            for (const auto& sig : kSigs) {
                if (!(sig.kind & 2)) continue;
                if (!icontains(m.name, sig.needle)) continue;
                AvEdrHit h;
                h.source   = AvEdrHit::Source::Module;
                h.vendor   = sig.vendor;
                h.product  = sig.product;
                h.evidence = m.name;
                h.mod_va   = m.module_va;
                hits.push_back(std::move(h));
                break;
            }
        }
    } catch (const std::exception& e) {
        log::debug("av_edr: module scan failed: {}", e.what());
    }
    return hits;
}

ByteBuf format_av_edr(const Engine& eng) {
    auto hits = scan_av_edr(eng);

    std::string out;
    out += "AV / EDR fingerprinting — pattern match against known endpoint-security agents\n";
    out += "================================================================================\n";
    out += fmt::format("Signatures: {} patterns covering ~30 products.\n\n", std::size(kSigs));

    if (hits.empty()) {
        out += "(no matches — this box is NOT running any AV/EDR product in the\n"
               "signature table. Either truly unmonitored, OR running something\n"
               "this list doesn't yet cover — see kSigs[] in src/os/linux/av_edr.cpp\n"
               "and submit a patch.)\n";
        return ByteBuf(out.begin(), out.end());
    }

    // Split into two sections so analysts can read the "agent process running"
    // vs "agent kernel module loaded" surfaces independently.
    out += "PROCESS HITS (running userspace agents)\n";
    out += "----------------------------------------\n";
    out += fmt::format("{:>5}  {:>5}  {:<16}  {:<22}  {:<30}  {}\n",
                       "PID", "UID", "COMM", "VENDOR", "PRODUCT", "EVIDENCE");
    int proc_n = 0;
    for (const auto& h : hits) {
        if (h.source != AvEdrHit::Source::Process) continue;
        out += fmt::format("{:>5}  {:>5}  {:<16}  {:<22}  {:<30}  {}\n",
                           h.pid, h.uid,
                           h.comm.substr(0, 16),
                           h.vendor, h.product, h.evidence);
        ++proc_n;
    }
    if (proc_n == 0) out += "(none)\n";

    out += "\nKERNEL-MODULE HITS (loaded LKM agents)\n";
    out += "----------------------------------------\n";
    out += fmt::format("{:<28}  {:<22}  {:<30}  {}\n",
                       "MODULE", "VENDOR", "PRODUCT", "MODULE_VA");
    int mod_n = 0;
    for (const auto& h : hits) {
        if (h.source != AvEdrHit::Source::Module) continue;
        out += fmt::format("{:<28}  {:<22}  {:<30}  {:#x}\n",
                           h.evidence, h.vendor, h.product, h.mod_va);
        ++mod_n;
    }
    if (mod_n == 0) out += "(none)\n";

    out += fmt::format("\nTotals: {} process hits, {} module hits.\n", proc_n, mod_n);
    return ByteBuf(out.begin(), out.end());
}

} // namespace lmpfs::linux
