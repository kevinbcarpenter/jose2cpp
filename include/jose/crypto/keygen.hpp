#pragma once

/// @file
/// Key generation and random bytes from OpenSSL's CSPRNG.

#include "jose/algorithm.hpp"
#include "jose/crypto/openssl_util.hpp"

#include <cstddef>

namespace jose {

/// Generate an RSA key pair. Keys below 2048 bits are rejected
/// (errc::key_size_too_small).
auto generate_rsa_key(int bits = 2048) -> expected<evp_pkey_ptr>;

/// Generate an EC key pair on the given curve (P-256, P-384, P-521).
auto generate_ec_key(ec_curve crv) -> expected<evp_pkey_ptr>;

/// Generate an OKP key pair (Ed25519/Ed448 for signing,
/// X25519/X448 for key agreement).
auto generate_okp_key(okp_curve crv) -> expected<evp_pkey_ptr>;

/// Cryptographically secure random bytes (for oct keys, CEKs, IVs, salts).
auto random_bytes(size_t len) -> expected<secure_bytes>;

} // namespace jose
