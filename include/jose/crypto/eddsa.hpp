#pragma once

/// @file
/// EdDSA signatures with Ed25519 or Ed448 (RFC 8037).

#include "jose/crypto/openssl_util.hpp"

#include <cstdint>
#include <span>

namespace jose {

/// Signs `data` with an Ed25519 or Ed448 private key. Prefer jose::sign.
auto eddsa_sign(EVP_PKEY* key,
                std::span<const uint8_t> data) -> expected<secure_bytes>;

/// Succeeds if `signature` is valid; otherwise errc::invalid_signature.
auto eddsa_verify(EVP_PKEY* key,
                  std::span<const uint8_t> data,
                  std::span<const uint8_t> signature) -> expected<void>;

} // namespace jose
