#pragma once

#include "jose/crypto/openssl_util.hpp"

#include <cstdint>
#include <span>

namespace jose {

auto eddsa_sign(EVP_PKEY* key,
                std::span<const uint8_t> data) -> expected<secure_bytes>;

auto eddsa_verify(EVP_PKEY* key,
                  std::span<const uint8_t> data,
                  std::span<const uint8_t> signature) -> expected<void>;

} // namespace jose
