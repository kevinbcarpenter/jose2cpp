#pragma once

#include "jose/error.hpp"

#include <cstddef>
#include <string_view>

namespace jose {

// --- JWS Signing Algorithms (RFC 7518 §3.1) ---

enum class signing_algorithm {
    HS256, HS384, HS512,
    RS256, RS384, RS512,
    ES256, ES384, ES512,
    PS256, PS384, PS512,
    EdDSA,
};

auto to_string(signing_algorithm alg) -> std::string_view;
auto parse_signing_algorithm(std::string_view s) -> expected<signing_algorithm>;

// --- JWE Key Management Algorithms (RFC 7518 §4.1) ---

enum class key_algorithm {
    RSA1_5,  // legacy — requires opt-in
    RSA_OAEP,
    RSA_OAEP_256,
    A128KW,
    A192KW,
    A256KW,
    dir,
    ECDH_ES,
    ECDH_ES_A128KW,
    ECDH_ES_A192KW,
    ECDH_ES_A256KW,
    A128GCMKW,
    A192GCMKW,
    A256GCMKW,
    PBES2_HS256_A128KW,
    PBES2_HS384_A192KW,
    PBES2_HS512_A256KW,
};

auto to_string(key_algorithm alg) -> std::string_view;
auto parse_key_algorithm(std::string_view s) -> expected<key_algorithm>;
auto is_legacy_algorithm(key_algorithm alg) -> bool;

// --- JWE Content Encryption Algorithms (RFC 7518 §5.1) ---

enum class content_encryption {
    A128CBC_HS256,
    A192CBC_HS384,
    A256CBC_HS512,
    A128GCM,
    A192GCM,
    A256GCM,
};

auto to_string(content_encryption alg) -> std::string_view;
auto parse_content_encryption(std::string_view s) -> expected<content_encryption>;

// Key sizes for content encryption algorithms
auto cek_byte_size(content_encryption enc) -> size_t;
auto iv_byte_size(content_encryption enc) -> size_t;
auto tag_byte_size(content_encryption enc) -> size_t;

// --- Hash algorithm for thumbprints ---

enum class hash_algorithm {
    SHA256,
    SHA384,
    SHA512,
};

// --- EC Curves ---

enum class ec_curve {
    P256,
    P384,
    P521,
};

auto to_string(ec_curve crv) -> std::string_view;
auto parse_ec_curve(std::string_view s) -> expected<ec_curve>;

// --- OKP Curves ---

enum class okp_curve {
    Ed25519,
    Ed448,
    X25519,
    X448,
};

auto to_string(okp_curve crv) -> std::string_view;
auto parse_okp_curve(std::string_view s) -> expected<okp_curve>;

// --- Key types ---

enum class kty {
    RSA,
    EC,
    oct,
    OKP,
};

auto to_string(kty k) -> std::string_view;
auto parse_kty(std::string_view s) -> expected<kty>;

// --- Legacy opt-in ---

struct legacy_options {
    bool allow_rsa1_5 = false;
};

} // namespace jose
