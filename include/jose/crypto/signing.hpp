#pragma once

#include "jose/algorithm.hpp"
#include "jose/crypto/openssl_util.hpp"

#include <cstdint>
#include <span>

namespace jose {

// --- Unified signing (RFC 7518 §3) ---
//
// Dispatches to HMAC, RSA (PKCS#1 / PSS), ECDSA, or EdDSA based on `alg`.
// Prefer these over the per-family functions.
//
//   auto key = jose::generate_ec_key(jose::ec_curve::P256).value();
//   auto sig = jose::sign(jose::signing_algorithm::ES256, key.get(), payload);
//   auto ok  = jose::verify(jose::signing_algorithm::ES256, key.get(), payload, *sig);

// HS256/HS384/HS512 with a symmetric (oct) key.
auto sign(signing_algorithm alg, std::span<const uint8_t> key,
          std::span<const uint8_t> data) -> expected<secure_bytes>;

auto verify(signing_algorithm alg, std::span<const uint8_t> key,
            std::span<const uint8_t> data,
            std::span<const uint8_t> signature) -> expected<void>;

// RS*/PS*/ES*/EdDSA with an asymmetric key.
auto sign(signing_algorithm alg, EVP_PKEY* key,
          std::span<const uint8_t> data) -> expected<secure_bytes>;

auto verify(signing_algorithm alg, EVP_PKEY* key,
            std::span<const uint8_t> data,
            std::span<const uint8_t> signature) -> expected<void>;

} // namespace jose
