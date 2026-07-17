#pragma once

#include "jose/algorithm.hpp"
#include "jose/crypto/openssl_util.hpp"

#include <cstdint>
#include <span>

namespace jose {

auto hmac_sign(signing_algorithm alg, std::span<const uint8_t> key,
               std::span<const uint8_t> data) -> expected<secure_bytes>;

auto hmac_verify(signing_algorithm alg, std::span<const uint8_t> key,
                 std::span<const uint8_t> data,
                 std::span<const uint8_t> signature) -> expected<void>;

} // namespace jose
