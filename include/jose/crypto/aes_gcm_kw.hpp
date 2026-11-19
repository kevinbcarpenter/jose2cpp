#pragma once

/// @file
/// AES-GCM key wrapping (A128GCMKW, A192GCMKW, A256GCMKW; RFC 7518 §4.7).

#include "jose/algorithm.hpp"
#include "jose/crypto/openssl_util.hpp"

#include <cstdint>
#include <span>

namespace jose {

/// What AES-GCM key wrapping returns: the JWE Encrypted Key and the
/// "iv" and "tag" header values.
struct gcm_kw_result {
    secure_bytes encrypted_key; ///< the wrapped CEK
    secure_bytes iv;   ///< 12 bytes, randomly generated
    secure_bytes tag;  ///< 16 bytes
};

/// Wraps `cek` under `kek` with a fresh random IV.
auto aes_gcm_key_wrap(key_algorithm alg, std::span<const uint8_t> kek,
                      std::span<const uint8_t> cek)
    -> expected<gcm_kw_result>;

/// Unwraps with the "iv" and "tag" from the header; a mismatch is
/// errc::decryption_failed.
auto aes_gcm_key_unwrap(key_algorithm alg, std::span<const uint8_t> kek,
                        std::span<const uint8_t> encrypted_key,
                        std::span<const uint8_t> iv,
                        std::span<const uint8_t> tag)
    -> expected<secure_bytes>;

} // namespace jose
