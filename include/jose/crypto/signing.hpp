#pragma once

/// @file
/// Signing and verification for every JWS "alg" value behind one pair of
/// functions. They dispatch on `alg` to HMAC, RSA (PKCS#1 / PSS), ECDSA or
/// EdDSA; prefer them over the per-family functions. They don't check JWK
/// metadata ("alg", "use"): jws does that before calling them.
///
/// @code{.cpp}
/// auto key = jose::generate_ec_key(jose::ec_curve::P256).value();
/// auto sig = jose::sign(jose::signing_algorithm::ES256, key.get(), payload);
/// auto ok  = jose::verify(jose::signing_algorithm::ES256, key.get(), payload, *sig);
/// @endcode

#include "jose/algorithm.hpp"
#include "jose/crypto/openssl_util.hpp"

#include <cstdint>
#include <span>

namespace jose {

// --- Unified signing (RFC 7518 §3) ---

/// HS256/HS384/HS512 with a symmetric (oct) key. Any other `alg` is
/// errc::algorithm_mismatch.
auto sign(signing_algorithm alg, std::span<const uint8_t> key,
          std::span<const uint8_t> data) -> expected<secure_bytes>;

/// Checks an HS* signature in constant time. A mismatch is
/// errc::invalid_signature.
auto verify(signing_algorithm alg, std::span<const uint8_t> key,
            std::span<const uint8_t> data,
            std::span<const uint8_t> signature) -> expected<void>;

/// RS*/PS*/ES*/EdDSA with an asymmetric key.
auto sign(signing_algorithm alg, EVP_PKEY* key,
          std::span<const uint8_t> data) -> expected<secure_bytes>;

/// Checks an RS*/PS*/ES*/EdDSA signature (R || S for ES*). A bad
/// signature is errc::invalid_signature.
auto verify(signing_algorithm alg, EVP_PKEY* key,
            std::span<const uint8_t> data,
            std::span<const uint8_t> signature) -> expected<void>;

} // namespace jose
