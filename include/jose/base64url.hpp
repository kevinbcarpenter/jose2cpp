#pragma once

/// @file
/// Base64url without padding (RFC 4648 §5), as JOSE uses it. Decoding is
/// strict: no padding, no whitespace, no characters outside the alphabet, and
/// no non-zero trailing bits.

#include "jose/error.hpp"
#include "jose/secure_bytes.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>

/// Base64url encoding and strict decoding.
namespace jose::base64url {

/// Encodes without padding.
///@{
auto encode(std::span<const uint8_t> input) -> std::string;
auto encode(std::string_view input) -> std::string;
auto encode(const secure_bytes& input) -> std::string;
///@}
/// Decodes strictly; anything else is errc::invalid_base64.
auto decode(std::string_view input) -> expected<secure_bytes>;

} // namespace jose::base64url
