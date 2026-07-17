#pragma once

#include "jose/algorithm.hpp"
#include "jose/crypto/openssl_util.hpp"

#include <cstdint>
#include <string_view>

namespace jose {

struct ecdh_result {
    secure_bytes derived_key;
    evp_pkey_ptr ephemeral_key;
};

// Derive key for ECDH-ES (direct) or ECDH-ES+A*KW (key wrapping).
// Generates an ephemeral key pair matching the recipient's curve.
auto ecdh_derive_key(
    EVP_PKEY* recipient_public_key,
    std::string_view algorithm,
    std::string_view apu,
    std::string_view apv,
    size_t key_length_bits
) -> expected<ecdh_result>;

// Derive key from a known ephemeral key (decryption side).
auto ecdh_derive_key_from_epk(
    EVP_PKEY* recipient_private_key,
    EVP_PKEY* ephemeral_public_key,
    std::string_view algorithm,
    std::string_view apu,
    std::string_view apv,
    size_t key_length_bits
) -> expected<secure_bytes>;

} // namespace jose
