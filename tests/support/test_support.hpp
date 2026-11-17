#pragma once

// Test-only helpers for the RFC known-answer tests.
//
// key_from_jwk() is a deliberately minimal JWK -> EVP_PKEY importer (no
// validation beyond what OpenSSL does) so the Phase 1 primitives can be
// checked against published vectors before the real jose::jwk exists.

#include "jose/crypto/openssl_util.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace jose::test {

// Load tests/vectors/<name>.json (an array of cases).
auto load_vectors(std::string_view name) -> nlohmann::json;

// Base64url-decode a string field; fails the current test on bad input.
auto b64(const nlohmann::json& value) -> std::vector<uint8_t>;

// Same bytes, viewed as a string (for passwords, apu/apv).
auto b64_string(const nlohmann::json& value) -> std::string;

// Build an OpenSSL key from an RSA / EC / OKP JWK. Includes the private
// part when the JWK has "d". Fails the current test if import fails.
auto key_from_jwk(const nlohmann::json& jwk) -> evp_pkey_ptr;

} // namespace jose::test
