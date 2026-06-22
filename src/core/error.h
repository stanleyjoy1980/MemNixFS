#pragma once
#include <stdexcept>
#include <string>
#include <fmt/format.h>

namespace lmpfs {

class Error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

template <typename... Args>
[[noreturn]] inline void throw_error(fmt::format_string<Args...> fmt_str, Args&&... args) {
    throw Error(fmt::format(fmt_str, std::forward<Args>(args)...));
}

} // namespace lmpfs
