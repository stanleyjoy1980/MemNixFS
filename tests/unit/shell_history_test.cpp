// shell_history_test.cpp — regression test for the stateful, format-aware
// on-disk shell-history parser (lmpfs::linux::parse_history_bytes).
//
// Feeds synthetic history-file content for every shell we claim to support and
// asserts the recovered command, the paired timestamp, and the detected
// `source` shell. This guards the fragile bits: bash "#<epoch>" markers that
// PRECEDE the command, fish "when:" lines that FOLLOW it, tcsh "#+<epoch>",
// zsh extended-history, binary ksh files, and CRLF PowerShell logs.
//
// No memory dump required — pure string parsing.

#include "os/linux/bash_history.h"

#include <cstdio>
#include <string>
#include <vector>

using lmpfs::linux::ShellCmd;
using lmpfs::linux::parse_history_bytes;

static int g_failures = 0;

#define CHECK(cond, msg)                                       \
    do {                                                       \
        if (cond) {                                            \
            std::printf("  ok: %s\n", (msg));                  \
        } else {                                               \
            std::printf("FAIL: %s\n", (msg));                  \
            ++g_failures;                                      \
        }                                                      \
    } while (0)

static const ShellCmd* find_cmd(const std::vector<ShellCmd>& v,
                                const std::string& cmd) {
    for (const auto& e : v)
        if (e.command == cmd) return &e;
    return nullptr;
}

static bool has_prefix(const std::string& s, const std::string& p) {
    return s.rfind(p, 0) == 0;
}

static bool contains(const std::string& s, const std::string& n) {
    return s.find(n) != std::string::npos;
}

int main() {
    // epoch 1700000000 == 2023-11-14 22:13:20 UTC (gmtime → deterministic).
    const std::string kDay = "2023-11-14";

    // ---- bash: "#<epoch>" precedes the command; last line has no timestamp.
    {
        std::string content =
            "#1700000000\n"
            "ls -la\n"
            "#1700000005\n"
            "sudo reboot\n"
            "echo no-timestamp\n"
            "#!/bin/bash\n";          // a '#' line that is NOT a timestamp
        auto r = parse_history_bytes(".bash_history", content);
        const ShellCmd* ls = find_cmd(r, "ls -la");
        const ShellCmd* rb = find_cmd(r, "sudo reboot");
        const ShellCmd* ne = find_cmd(r, "echo no-timestamp");
        const ShellCmd* sh = find_cmd(r, "#!/bin/bash");
        CHECK(ls && contains(ls->timestamp, kDay), "bash: '#<epoch>' pairs with NEXT command (ls -la)");
        CHECK(ls && ls->source == "bash/.bash_history", "bash: source names shell + file");
        CHECK(ls && has_prefix(ls->note, "high:"), "bash: on-disk line is high-confidence");
        CHECK(rb && contains(rb->timestamp, kDay), "bash: second '#<epoch>' pairs correctly");
        CHECK(ne && ne->timestamp.empty(), "bash: trailing line without marker has no timestamp");
        CHECK(sh != nullptr, "bash: '#!/bin/bash' kept as a command, not a timestamp");
    }

    // ---- zsh: extended-history ": <ts>:<dur>;cmd" + a plain line.
    {
        std::string content =
            ": 1700000000:0;git status\n"
            ": 1700000010:5;make -j8\n"
            "plain-zsh-command\n";
        auto r = parse_history_bytes(".zsh_history", content);
        const ShellCmd* gs = find_cmd(r, "git status");
        const ShellCmd* mk = find_cmd(r, "make -j8");
        const ShellCmd* pl = find_cmd(r, "plain-zsh-command");
        CHECK(gs && contains(gs->timestamp, kDay), "zsh: extended-history timestamp parsed (git status)");
        CHECK(gs && gs->source == "zsh/.zsh_history", "zsh: source names shell + file");
        CHECK(mk && contains(mk->timestamp, kDay), "zsh: second extended entry (make -j8)");
        CHECK(pl && pl->timestamp.empty(), "zsh: plain line kept without timestamp");
    }

    // ---- fish: YAML "- cmd:" then "when:" (timestamp FOLLOWS the command).
    {
        std::string content =
            "- cmd: echo hello\n"
            "  when: 1700000000\n"
            "- cmd: ls /tmp\n"
            "  when: 1700000020\n"
            "  paths:\n"
            "    - /tmp\n";
        auto r = parse_history_bytes("fish_history", content);
        const ShellCmd* eh = find_cmd(r, "echo hello");
        const ShellCmd* lt = find_cmd(r, "ls /tmp");
        CHECK(eh && contains(eh->timestamp, kDay), "fish: 'when:' timestamp pairs with preceding cmd (echo hello)");
        CHECK(eh && eh->source == "fish/fish_history", "fish: source names shell + file");
        CHECK(lt && contains(lt->timestamp, kDay), "fish: second record's 'when:' parsed (ls /tmp)");
        CHECK(lt != nullptr, "fish: 'paths:' block does not swallow the next record");
    }

    // ---- tcsh: "#+<epoch>" precedes the command.
    {
        std::string content =
            "#+1700000000\n"
            "vim ~/.cshrc\n";
        auto r = parse_history_bytes(".tcsh_history", content);
        const ShellCmd* vc = find_cmd(r, "vim ~/.cshrc");
        CHECK(vc && contains(vc->timestamp, kDay), "tcsh: '#+<epoch>' marker parsed");
        CHECK(vc && vc->source == "tcsh/.tcsh_history", "tcsh: source names shell + file");
    }

    // ---- PowerShell: PSReadLine ConsoleHost_history.txt, CRLF, UTF-8 BOM.
    {
        std::string content =
            "\xEF\xBB\xBF"               // UTF-8 BOM
            "Get-Process\r\n"
            "Set-Location C:\\Windows\r\n";
        auto r = parse_history_bytes("ConsoleHost_history.txt", content);
        const ShellCmd* gp = find_cmd(r, "Get-Process");
        const ShellCmd* sl = find_cmd(r, "Set-Location C:\\Windows");
        CHECK(gp != nullptr, "powershell: first command parsed (BOM + CRLF stripped)");
        CHECK(gp && gp->source == "powershell/ConsoleHost_history.txt", "powershell: source names shell + file");
        CHECK(sl != nullptr, "powershell: second CRLF line parsed");
    }

    // ---- ksh/mksh: binary .sh_history (commands between control/NUL bytes).
    {
        std::string content;
        content += '\x01'; content += "ls -la";          content += '\0';
        content += '\x02'; content += "cat /etc/passwd"; content += '\0';
        auto r = parse_history_bytes(".sh_history", content);
        const ShellCmd* a = find_cmd(r, "ls -la");
        const ShellCmd* b = find_cmd(r, "cat /etc/passwd");
        CHECK(a != nullptr, "ksh: binary history command extracted (ls -la)");
        CHECK(a && a->source == "ksh/.sh_history", "ksh: source names shell + file");
        CHECK(b != nullptr, "ksh: second binary command extracted (cat /etc/passwd)");
    }

    // ---- dash/ash (POSIX): plain lines, no timestamps.
    {
        std::string content =
            "apt update\n"
            "./configure\n";
        auto r = parse_history_bytes(".dash_history", content);
        const ShellCmd* au = find_cmd(r, "apt update");
        CHECK(au != nullptr, "dash: plain command parsed");
        CHECK(au && au->source == "sh/.dash_history", "dash: POSIX source names sh + file");
        CHECK(au && has_prefix(au->note, "high:"), "dash: on-disk line is high-confidence");
    }

    std::printf("== %d failure(s) ==\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
