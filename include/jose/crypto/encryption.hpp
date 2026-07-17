#pragma once

#include "jose/algorithm.hpp"
#include "jose/secure_bytes.hpp"

#include <cstdint>
#include <span>

namespace jose {

struct encryption_result {
    secure_bytes ciphertext;
    secure_bytes tag;
};

// --- Unified content encryption (RFC 7518 §5) ---
//
// Dispatches to AES-CBC-HMAC or AES-GCM based on `enc`. Prefer these over
// the per-family functions in jose/crypto/aes_gcm.hpp / aes_cbc_hmac.hpp.
//
//   auto cek = jose::generate_cek(enc).value();
//   auto iv  = jose::generate_iv(enc).value();
//   auto sealed = jose::encrypt(enc, cek, iv, plaintext, aad);
//   auto opened = jose::decrypt(enc, cek, iv, sealed->ciphertext, aad, sealed->tag);

auto encrypt(content_encryption enc, std::span<const uint8_t> cek,
             std::span<const uint8_t> iv,
             std::span<const uint8_t> plaintext,
             std::span<const uint8_t> aad) -> expected<encryption_result>;

auto decrypt(content_encryption enc, std::span<const uint8_t> cek,
             std::span<const uint8_t> iv,
             std::span<const uint8_t> ciphertext,
             std::span<const uint8_t> aad,
             std::span<const uint8_t> tag) -> expected<secure_bytes>;

// Fresh random CEK / IV correctly sized for `enc`.
auto generate_cek(content_encryption enc) -> expected<secure_bytes>;
auto generate_iv(content_encryption enc) -> expected<secure_bytes>;

} // namespace jose
