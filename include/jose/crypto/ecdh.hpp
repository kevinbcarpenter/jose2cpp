#pragma once

/// @file
/// ECDH-ES key agreement with the Concat KDF (RFC 7518 §4.6).

#include "jose/algorithm.hpp"
#include "jose/crypto/openssl_util.hpp"

#include <cstdint>
#include <string_view>

namespace jose {

/// What ecdh_derive_key returns.
struct ecdh_result {
    secure_bytes derived_key;   ///< the Concat KDF output: the CEK or the key-wrapping key
    evp_pkey_ptr ephemeral_key; ///< the ephemeral key pair, whose public half goes in "epk"
};

/// Derive key for ECDH-ES (direct) or ECDH-ES+A*KW (key wrapping).
/// Generates an ephemeral key pair matching the recipient's curve.
auto ecdh_derive_key(
    EVP_PKEY* recipient_public_key,
    std::string_view algorithm,
    std::string_view apu,
    std::string_view apv,
    size_t key_length_bits
) -> expected<ecdh_result>;

/// Derive key from a known ephemeral key (decryption side).
auto ecdh_derive_key_from_epk(
    EVP_PKEY* recipient_private_key,
    EVP_PKEY* ephemeral_public_key,
    std::string_view algorithm,
    std::string_view apu,
    std::string_view apv,
    size_t key_length_bits
) -> expected<secure_bytes>;

} // namespace jose
