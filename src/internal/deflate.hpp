#pragma once

// Raw DEFLATE (RFC 1951, no zlib/gzip wrapper) for JWE "zip":"DEF"
// (RFC 7516 §4.1.3). Internal; not installed.

#include "jose/error.hpp"
#include "jose/secure_bytes.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace jose::internal {

auto deflate_raw(std::span<const uint8_t> input) -> expected<secure_bytes>;

// Fails with errc::compression_error on malformed or truncated input, or if
// the output would exceed `max_output` octets (decompression-bomb guard).
auto inflate_raw(std::span<const uint8_t> input, size_t max_output) -> expected<secure_bytes>;

} // namespace jose::internal
