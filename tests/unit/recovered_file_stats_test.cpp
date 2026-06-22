#include "os/linux/pagecache.h"

#include <cstdio>
#include <string>

using lmpfs::linux::RecoveredFileStats;
using lmpfs::linux::RecoveredRange;
using lmpfs::linux::describe_recovered_file_state;
using lmpfs::linux::validate_recovered_fs_path;

static int g_failures = 0;

#define CHECK(cond, msg)                                      \
    do {                                                      \
        if (cond) {                                           \
            std::printf("  ok: %s\n", (msg));                 \
        } else {                                              \
            std::printf("FAIL: %s\n", (msg));                 \
            ++g_failures;                                     \
        }                                                     \
    } while (0)

static bool contains(const std::string& s, const std::string& n) {
    return s.find(n) != std::string::npos;
}

int main() {
    {
        RecoveredFileStats st{};
        st.logical_size = 8192;
        st.expected_pages = 2;
        st.xarray_pages_seen = 2;
        st.pages_within_size = 2;
        st.pages_copied = 2;
        st.bytes_copied = 8192;
        st.physical_reads_checked = true;
        CHECK(st.complete(), "complete: all expected pages copied");
        CHECK(contains(describe_recovered_file_state(st), "checked"),
              "complete: state is checked");
    }

    {
        RecoveredFileStats st{};
        st.logical_size = 8192;
        st.expected_pages = 2;
        st.xarray_pages_seen = 1;
        st.pages_within_size = 1;
        st.pages_copied = 1;
        st.bytes_copied = 4096;
        st.missing_ranges_total = 1;
        st.missing_ranges.push_back({4096, 4096});
        CHECK(!st.complete(), "missing page: not complete");
        CHECK(contains(describe_recovered_file_state(st), "missing cached pages"),
              "missing page: state names missing cached pages");
    }

    {
        RecoveredFileStats st{};
        st.logical_size = 4096;
        st.expected_pages = 1;
        st.xarray_pages_seen = 1;
        st.pages_within_size = 1;
        st.pages_dropped = 1;
        st.dropped_ranges_total = 1;
        st.physical_reads_checked = true;
        st.dropped_ranges.push_back({0, 4096});
        CHECK(!st.complete(), "dropped page: not complete");
        CHECK(contains(describe_recovered_file_state(st), "physical bytes were unreadable"),
              "dropped page: state names unreadable physical bytes");
    }

    {
        RecoveredFileStats st{};
        st.logical_size = 8192;
        st.expected_pages = 2;
        st.xarray_pages_seen = 1;
        st.pages_within_size = 1;
        st.pages_dropped = 1;
        st.missing_ranges_total = 1;
        st.dropped_ranges_total = 1;
        CHECK(!st.complete(), "mixed sparse/dropped: not complete");
        CHECK(contains(describe_recovered_file_state(st), "missing cached pages and unreadable"),
              "mixed sparse/dropped: state names both causes");
    }

    {
        RecoveredFileStats st{};
        CHECK(!st.complete(), "zero-length: not complete");
        CHECK(contains(describe_recovered_file_state(st), "zero-length"),
              "zero-length: state is unavailable");
    }

    {
        CHECK(validate_recovered_fs_path("/etc/os-release").ok,
              "path trust: valid ASCII path accepted");

        // Well-formed UTF-8 filenames are legitimate and must be ACCEPTED.
        std::string utf8_latin = "/home/user/caf";        // café (U+00E9, 0xC3 0xA9)
        utf8_latin.push_back(static_cast<char>(0xc3));
        utf8_latin.push_back(static_cast<char>(0xa9));
        std::string utf8_cyrillic = "/home/";             // Документ (Cyrillic)
        for (auto b : {0xd0,0x94,0xd0,0xbe,0xd0,0xba,0xd1,0x83,0xd0,0xbc,0xd0,0xb5,0xd0,0xbd,0xd1,0x82})
            utf8_cyrillic.push_back(static_cast<char>(b));
        std::string utf8_emoji = "/tmp/";                 // U+1F600 (0xF0 0x9F 0x98 0x80)
        for (auto b : {0xf0,0x9f,0x98,0x80})
            utf8_emoji.push_back(static_cast<char>(b));
        CHECK(validate_recovered_fs_path(utf8_latin).ok,
              "path trust: valid UTF-8 (Latin-1 supplement) accepted");
        CHECK(validate_recovered_fs_path(utf8_cyrillic).ok,
              "path trust: valid UTF-8 (Cyrillic) accepted");
        CHECK(validate_recovered_fs_path(utf8_emoji).ok,
              "path trust: valid UTF-8 (4-byte emoji) accepted");

        // Malformed/garbage byte sequences must still be REJECTED.
        std::string lone_cont = "/etc/";                  // lone continuation byte
        lone_cont.push_back(static_cast<char>(0x80));
        lone_cont += "x";
        std::string overlong = "/etc/";                   // 0xC0 0xAF = overlong '/'
        overlong.push_back(static_cast<char>(0xc0));
        overlong.push_back(static_cast<char>(0xaf));
        std::string truncated = "/etc/";                  // 3-byte lead, only 1 follows
        truncated.push_back(static_cast<char>(0xe2));
        truncated.push_back(static_cast<char>(0x82));
        std::string surrogate = "/etc/";                  // 0xED 0xA0 0x80 = U+D800
        surrogate.push_back(static_cast<char>(0xed));
        surrogate.push_back(static_cast<char>(0xa0));
        surrogate.push_back(static_cast<char>(0x80));
        std::string c1_ctrl = "/etc/";                    // 0xC2 0x85 = U+0085 (C1 control)
        c1_ctrl.push_back(static_cast<char>(0xc2));
        c1_ctrl.push_back(static_cast<char>(0x85));

        std::string with_del = "/etc/ba";
        with_del.push_back(static_cast<char>(0x7f));
        with_del += "d";
        std::string with_ctl = "/etc/";
        with_ctl.push_back(static_cast<char>(0x01));
        with_ctl += "name";
        CHECK(!validate_recovered_fs_path(lone_cont).ok,
              "path trust: lone UTF-8 continuation byte rejected");
        CHECK(!validate_recovered_fs_path(overlong).ok,
              "path trust: overlong UTF-8 encoding rejected");
        CHECK(!validate_recovered_fs_path(truncated).ok,
              "path trust: truncated UTF-8 sequence rejected");
        CHECK(!validate_recovered_fs_path(surrogate).ok,
              "path trust: UTF-16 surrogate in UTF-8 rejected");
        CHECK(!validate_recovered_fs_path(c1_ctrl).ok,
              "path trust: C1 control codepoint rejected");
        CHECK(!validate_recovered_fs_path(with_del).ok,
              "path trust: DEL byte rejected");
        CHECK(!validate_recovered_fs_path(with_ctl).ok,
              "path trust: control byte rejected");
        CHECK(!validate_recovered_fs_path("/etc/bad:name").ok,
              "path trust: host-forbidden character rejected");
        CHECK(!validate_recovered_fs_path("/etc/..").ok,
              "path trust: traversal component rejected");
        CHECK(!validate_recovered_fs_path("etc/passwd").ok,
              "path trust: relative path rejected");
    }

    std::printf("== %d failure(s) ==\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
