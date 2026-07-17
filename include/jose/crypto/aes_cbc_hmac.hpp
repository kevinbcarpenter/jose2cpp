#pragma once

#include "jose/algorithm.hpp"
#include "jose/crypto/openssl_util.hpp"

#include <cstdint>
#include <span>
#include <utility>

namespace jose {

auto aes_cbc_hmac_encrypt(content_encryption enc, std::span<const uint8_t> cek,
                          std::span<const uint8_t> iv,
                          std::span<const uint8_t> plaintext,
                          std::span<const uint8_t> aad)
    -> expected<std::pair<secure_bytes, secure_bytes>>;

auto aes_cbc_hmac_decrypt(content_encryption enc, std::span<const uint8_t> cek,
                          std::span<const uint8_t> iv,
                          std::span<const uint8_t> ciphertext,
                          std::span<const uint8_t> aad,
                          std::span<const uint8_t> tag)
    -> expected<secure_bytes>;

} // namespace jose
