#pragma once

/// @file
/// AES-CBC with HMAC-SHA2 content encryption (A128CBC-HS256, A192CBC-HS384,
/// A256CBC-HS512; RFC 7518 §5.2).

#include "jose/algorithm.hpp"
#include "jose/crypto/encryption.hpp"

#include <cstdint>
#include <span>

namespace jose {

/// AES-CBC with PKCS#7 padding, then HMAC over the AAD, IV, ciphertext and
/// AAD length (RFC 7518 §5.2.2). The CEK is the MAC key followed by the
/// encryption key. Prefer jose::encrypt.
auto aes_cbc_hmac_encrypt(content_encryption enc, std::span<const uint8_t> cek,
                          std::span<const uint8_t> iv,
                          std::span<const uint8_t> plaintext,
                          std::span<const uint8_t> aad)
    -> expected<encryption_result>;

/// Checks the tag in constant time before decrypting. A mismatch is
/// errc::invalid_tag. Prefer jose::decrypt.
auto aes_cbc_hmac_decrypt(content_encryption enc, std::span<const uint8_t> cek,
                          std::span<const uint8_t> iv,
                          std::span<const uint8_t> ciphertext,
                          std::span<const uint8_t> aad,
                          std::span<const uint8_t> tag)
    -> expected<secure_bytes>;

} // namespace jose
