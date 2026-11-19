#pragma once

/// @file
/// Content encryption for every JWE "enc" value behind one pair of functions.

#include "jose/algorithm.hpp"
#include "jose/secure_bytes.hpp"

#include <cstdint>
#include <span>

namespace jose {

/// What content encryption returns.
struct encryption_result {
    secure_bytes ciphertext; ///< same length as the plaintext (GCM) or padded (CBC)
    secure_bytes tag;        ///< the authentication tag
};

// --- Unified content encryption (RFC 7518 §5) ---

/// Encrypts with AES-CBC-HMAC or AES-GCM, chosen by `enc`. Prefer this and
/// decrypt() over the per-family functions in aes_gcm.hpp and
/// aes_cbc_hmac.hpp. `cek` and `iv` must be the sizes `enc` needs, and a
/// CEK and IV pair must never be used twice.
///
/// @code{.cpp}
/// auto cek = jose::generate_cek(enc).value();
/// auto iv  = jose::generate_iv(enc).value();
/// auto sealed = jose::encrypt(enc, cek, iv, plaintext, aad);
/// auto opened = jose::decrypt(enc, cek, iv, sealed->ciphertext, aad, sealed->tag);
/// @endcode
auto encrypt(content_encryption enc, std::span<const uint8_t> cek,
             std::span<const uint8_t> iv,
             std::span<const uint8_t> plaintext,
             std::span<const uint8_t> aad) -> expected<encryption_result>;

/// Checks the tag and decrypts.
auto decrypt(content_encryption enc, std::span<const uint8_t> cek,
             std::span<const uint8_t> iv,
             std::span<const uint8_t> ciphertext,
             std::span<const uint8_t> aad,
             std::span<const uint8_t> tag) -> expected<secure_bytes>;

/// Fresh random CEK / IV correctly sized for `enc`.
///@{
auto generate_cek(content_encryption enc) -> expected<secure_bytes>;
auto generate_iv(content_encryption enc) -> expected<secure_bytes>;
///@}

} // namespace jose
