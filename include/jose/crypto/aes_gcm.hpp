#pragma once

/// @file
/// AES-GCM content encryption (A128GCM, A192GCM, A256GCM; RFC 7518 §5.3).

#include "jose/algorithm.hpp"
#include "jose/crypto/encryption.hpp"

#include <cstdint>
#include <span>

namespace jose {

/// AES-GCM with a 16, 24 or 32 octet CEK and a 12 octet IV. Prefer
/// jose::encrypt.
auto aes_gcm_encrypt(content_encryption enc, std::span<const uint8_t> cek,
                     std::span<const uint8_t> iv,
                     std::span<const uint8_t> plaintext,
                     std::span<const uint8_t> aad)
    -> expected<encryption_result>;

/// A tag mismatch is errc::decryption_failed. Prefer jose::decrypt.
auto aes_gcm_decrypt(content_encryption enc, std::span<const uint8_t> cek,
                     std::span<const uint8_t> iv,
                     std::span<const uint8_t> ciphertext,
                     std::span<const uint8_t> aad,
                     std::span<const uint8_t> tag)
    -> expected<secure_bytes>;

} // namespace jose
