#pragma once

/// @file
/// PBES2 password-based key wrapping (PBES2-HS256+A128KW and friends; RFC
/// 7518 §4.8).

#include "jose/algorithm.hpp"
#include "jose/crypto/openssl_util.hpp"

#include <cstdint>
#include <span>
#include <string_view>

namespace jose {

/// What PBES2 key wrapping returns: the JWE Encrypted Key and the "p2s"
/// and "p2c" header values.
struct pbes2_result {
    secure_bytes encrypted_key; ///< the wrapped CEK
    secure_bytes p2s;    ///< salt input (randomly generated, at least 8 bytes)
    int p2c;             ///< iteration count
};

/// iteration_count / p2c must be in [1000, 1000000]: RFC 7518 recommends at
/// least 1000, and the upper bound guards against DoS via attacker-controlled
/// p2c on the decrypt path.
auto pbes2_key_wrap(key_algorithm alg, std::string_view password,
                    std::span<const uint8_t> cek,
                    int iteration_count = 310000) -> expected<pbes2_result>;

/// Derives the key from `password`, "p2s" and "p2c", then unwraps. `p2c`
/// out of range or a salt under 8 octets is errc::invalid_key.
auto pbes2_key_unwrap(key_algorithm alg, std::string_view password,
                      std::span<const uint8_t> encrypted_key,
                      std::span<const uint8_t> p2s,
                      int p2c) -> expected<secure_bytes>;

} // namespace jose
