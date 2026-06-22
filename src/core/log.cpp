#include "core/log.h"
#include <atomic>
#include <cstdio>

namespace lmpfs::log {

namespace {
// Default: Note. Info/Debug/Trace diagnostics are hidden until the user
// raises verbosity with -v (Debug) or -vv (Trace); -q drops to Warn.
std::atomic<Level> g_level{ Level::Note };

const char* tag(Level lv) {
    switch (lv) {
        case Level::Trace: return "TRC";
        case Level::Debug: return "DBG";
        case Level::Info:  return "INF";
        case Level::Note:  return "==>";
        case Level::Warn:  return "WRN";
        case Level::Error: return "ERR";
    }
    return "?";
}
fmt::color color_of(Level lv) {
    switch (lv) {
        case Level::Trace: return fmt::color::dark_gray;
        case Level::Debug: return fmt::color::gray;
        case Level::Info:  return fmt::color::cyan;
        case Level::Note:  return fmt::color::white;
        case Level::Warn:  return fmt::color::yellow;
        case Level::Error: return fmt::color::red;
    }
    return fmt::color::white;
}
} // anonymous

void set_level(Level lv) { g_level.store(lv); }
Level level()            { return g_level.load(); }

void emit(Level lv, std::string_view msg) {
    // Note lines are the clean, default-visible status output: print them
    // without the bracketed level tag so a normal run reads as plain prose.
    if (lv == Level::Note) {
        fmt::print(stderr, "{}\n", msg);
        return;
    }
    fmt::print(stderr, fmt::fg(color_of(lv)), "[{}] ", tag(lv));
    fmt::print(stderr, "{}\n", msg);
}

} // namespace lmpfs::log
