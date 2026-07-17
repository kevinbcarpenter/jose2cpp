#pragma once

#include "jose/error.hpp"
#include "jose/secure_bytes.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace jose::base64url {

auto encode(std::span<const uint8_t> input) -> std::string;
auto decode(std::string_view input) -> expected<secure_bytes>;

// Convenience overloads
auto encode(std::string_view input) -> std::string;
auto encode(const secure_bytes& input) -> std::string;

} // namespace jose::base64url
