#pragma once

#include "jose/algorithm.hpp"
#include "jose/crypto/openssl_util.hpp"

#include <cstdint>
#include <span>
#include <string_view>

namespace jose {

struct pbes2_result {
    secure_bytes encrypted_key;
    secure_bytes p2s;    // salt input (randomly generated, at least 8 bytes)
    int p2c;             // iteration count
};

// iteration_count / p2c must be in [1000, 1000000]: RFC 7518 recommends at
// least 1000, and the upper bound guards against DoS via attacker-controlled
// p2c on the decrypt path.
auto pbes2_key_wrap(key_algorithm alg, std::string_view password,
                    std::span<const uint8_t> cek,
                    int iteration_count = 310000) -> expected<pbes2_result>;

auto pbes2_key_unwrap(key_algorithm alg, std::string_view password,
                      std::span<const uint8_t> encrypted_key,
                      std::span<const uint8_t> p2s,
                      int p2c) -> expected<secure_bytes>;

} // namespace jose
