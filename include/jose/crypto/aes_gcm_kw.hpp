#pragma once

#include "jose/algorithm.hpp"
#include "jose/crypto/openssl_util.hpp"

#include <cstdint>
#include <span>

namespace jose {

struct gcm_kw_result {
    secure_bytes encrypted_key;
    secure_bytes iv;   // 12 bytes, randomly generated
    secure_bytes tag;  // 16 bytes
};

auto aes_gcm_key_wrap(key_algorithm alg, std::span<const uint8_t> kek,
                      std::span<const uint8_t> cek)
    -> expected<gcm_kw_result>;

auto aes_gcm_key_unwrap(key_algorithm alg, std::span<const uint8_t> kek,
                        std::span<const uint8_t> encrypted_key,
                        std::span<const uint8_t> iv,
                        std::span<const uint8_t> tag)
    -> expected<secure_bytes>;

} // namespace jose
