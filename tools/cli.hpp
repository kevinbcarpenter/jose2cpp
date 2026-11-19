#pragma once

// jose-cli's commands, as a function, so the tests can run them in-process.
// tools/jose_cli.cpp is the program around it.

#include <iosfwd>
#include <string>
#include <vector>

namespace jose::cli {

struct streams {
    std::istream& in;
    std::ostream& out;
    std::ostream& err;
};

// Exit statuses.
inline constexpr int exit_ok = 0;
inline constexpr int exit_failed = 1; // the operation failed (bad key, bad signature, ...)
inline constexpr int exit_usage = 2;  // the command line is wrong

// Runs one command. `args` doesn't include the program name.
auto run(const std::vector<std::string>& args, streams io) -> int;

} // namespace jose::cli
