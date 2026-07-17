#pragma once

#include "jose/algorithm.hpp"
#include "jose/crypto/openssl_util.hpp"

#include <cstdint>
#include <span>

namespace jose {

auto ec_sign(signing_algorithm alg, EVP_PKEY* key,
             std::span<const uint8_t> data) -> expected<secure_bytes>;

auto ec_verify(signing_algorithm alg, EVP_PKEY* key,
               std::span<const uint8_t> data,
               std::span<const uint8_t> signature) -> expected<void>;

} // namespace jose
