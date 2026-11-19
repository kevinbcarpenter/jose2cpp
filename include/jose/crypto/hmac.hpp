#pragma once

/// @file
/// HMAC-SHA2 signatures (HS256, HS384, HS512; RFC 7518 §3.2).

#include "jose/algorithm.hpp"
#include "jose/crypto/openssl_util.hpp"

#include <cstdint>
#include <span>

namespace jose {

/// The HMAC of `data` for HS256, HS384 or HS512. A key shorter than the
/// hash output is errc::key_too_short. Prefer jose::sign.
auto hmac_sign(signing_algorithm alg, std::span<const uint8_t> key,
               std::span<const uint8_t> data) -> expected<secure_bytes>;

/// Compares in constant time. A mismatch is errc::invalid_signature.
auto hmac_verify(signing_algorithm alg, std::span<const uint8_t> key,
                 std::span<const uint8_t> data,
                 std::span<const uint8_t> signature) -> expected<void>;

} // namespace jose
