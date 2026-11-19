#pragma once

/// @file
/// ECDSA signatures (ES256, ES384, ES512; RFC 7518 §3.4) in JWS form, R || S.

#include "jose/algorithm.hpp"
#include "jose/crypto/openssl_util.hpp"

#include <cstdint>
#include <span>

namespace jose {

/// Signs `data` with ES256, ES384 or ES512. The key's curve must match
/// the algorithm. The signature is R || S. Prefer jose::sign.
auto ec_sign(signing_algorithm alg, EVP_PKEY* key,
             std::span<const uint8_t> data) -> expected<secure_bytes>;

/// Succeeds if the R || S `signature` is valid; otherwise
/// errc::invalid_signature.
auto ec_verify(signing_algorithm alg, EVP_PKEY* key,
               std::span<const uint8_t> data,
               std::span<const uint8_t> signature) -> expected<void>;

} // namespace jose
