#pragma once

/// @file
/// AES Key Wrap (A128KW, A192KW, A256KW; RFC 3394, RFC 7518 §4.4).

#include "jose/algorithm.hpp"
#include "jose/crypto/openssl_util.hpp"

#include <cstdint>
#include <span>

namespace jose {

/// Wraps `cek` with a 16, 24 or 32 octet key-encryption key (A128KW,
/// A192KW, A256KW).
auto aes_key_wrap(key_algorithm alg, std::span<const uint8_t> kek,
                  std::span<const uint8_t> cek) -> expected<secure_bytes>;

/// Unwraps; a failed integrity check is errc::decryption_failed.
auto aes_key_unwrap(key_algorithm alg, std::span<const uint8_t> kek,
                    std::span<const uint8_t> encrypted_key)
    -> expected<secure_bytes>;

} // namespace jose
