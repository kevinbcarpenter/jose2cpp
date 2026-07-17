#pragma once

#include "jose/algorithm.hpp"
#include "jose/crypto/openssl_util.hpp"

#include <cstdint>
#include <span>

namespace jose {

auto aes_key_wrap(key_algorithm alg, std::span<const uint8_t> kek,
                  std::span<const uint8_t> cek) -> expected<secure_bytes>;

auto aes_key_unwrap(key_algorithm alg, std::span<const uint8_t> kek,
                    std::span<const uint8_t> encrypted_key)
    -> expected<secure_bytes>;

} // namespace jose
