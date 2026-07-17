#pragma once

// X25519/X448 key agreement is handled by the ECDH module (jose/crypto/ecdh.hpp).
// This header provides key generation utilities specific to OKP curves.

#include "jose/crypto/openssl_util.hpp"
#include "jose/error.hpp"

namespace jose {

auto generate_x25519_keypair() -> expected<evp_pkey_ptr>;
auto generate_x448_keypair() -> expected<evp_pkey_ptr>;

} // namespace jose
