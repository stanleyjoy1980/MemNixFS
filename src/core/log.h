#pragma once
#include <fmt/format.h>
#include <fmt/color.h>
#include <string_view>

namespace lmpfs::log {

// A message is emitted when level() <= its level. Note sits ABOVE Warn on
// purpose: a normal run prints the small set of user-facing status lines
// (Note) plus Errors, but NOT warnings — warnings are diagnostics that only
// surface with -v. So the default threshold is Note; -v lowers it to Debug
// (revealing Info, Warn and Debug), -vv to Trace, and -q raises it to Error
// (critical errors only).
enum class Level { Trace, Debug, Info, Warn, Note, Error };

void set_level(Level lv);
Level level();

void emit(Level lv, std::string_view msg);

template <typename... Args>
inline void trace(fmt::format_string<Args...> f, Args&&... a) {
    if (level() <= Level::Trace) emit(Level::Trace, fmt::format(f, std::forward<Args>(a)...));
}
template <typename... Args>
inline void debug(fmt::format_string<Args...> f, Args&&... a) {
    if (level() <= Level::Debug) emit(Level::Debug, fmt::format(f, std::forward<Args>(a)...));
}
template <typename... Args>
inline void info(fmt::format_string<Args...> f, Args&&... a) {
    if (level() <= Level::Info) emit(Level::Info, fmt::format(f, std::forward<Args>(a)...));
}
template <typename... Args>
inline void note(fmt::format_string<Args...> f, Args&&... a) {
    if (level() <= Level::Note) emit(Level::Note, fmt::format(f, std::forward<Args>(a)...));
}
template <typename... Args>
inline void warn(fmt::format_string<Args...> f, Args&&... a) {
    if (level() <= Level::Warn) emit(Level::Warn, fmt::format(f, std::forward<Args>(a)...));
}
template <typename... Args>
inline void error(fmt::format_string<Args...> f, Args&&... a) {
    if (level() <= Level::Error) emit(Level::Error, fmt::format(f, std::forward<Args>(a)...));
}

} // namespace lmpfs::log
