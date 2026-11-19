#pragma once

/// @file
/// The JOSE algorithm identifiers (RFC 7518) as enums, with conversions to
/// and from their registered names.

#include "jose/error.hpp"

#include <cstddef>
#include <string_view>

namespace jose {

// --- JWS Signing Algorithms (RFC 7518 §3.1) ---

/// A JWS "alg" (RFC 7518 §3.1, RFC 8037 for EdDSA). "none" isn't one.
enum class signing_algorithm {
    HS256, HS384, HS512,
    RS256, RS384, RS512,
    ES256, ES384, ES512,
    PS256, PS384, PS512,
    EdDSA,
};

/// The registered name ("ES256", ...) and back. An unknown name, "none"
/// included, is errc::unsupported_algorithm. Names are case-sensitive.
///@{
auto to_string(signing_algorithm alg) -> std::string_view;
auto parse_signing_algorithm(std::string_view s) -> expected<signing_algorithm>;
///@}

// --- JWE Key Management Algorithms (RFC 7518 §4.1) ---

/// A JWE key-management "alg" (RFC 7518 §4.1). Underscores stand for the
/// name's '-' and '+': ECDH_ES_A128KW is "ECDH-ES+A128KW".
enum class key_algorithm {
    RSA1_5,  ///< legacy, requires opt-in
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

/// The registered name ("RSA-OAEP-256", ...) and back. An unknown name is
/// errc::unsupported_algorithm.
///@{
auto to_string(key_algorithm alg) -> std::string_view;
auto parse_key_algorithm(std::string_view s) -> expected<key_algorithm>;
///@}
/// True for algorithms that need a legacy_options opt-in (RSA1_5).
auto is_legacy_algorithm(key_algorithm alg) -> bool;

// --- JWE Content Encryption Algorithms (RFC 7518 §5.1) ---

/// A JWE "enc" (RFC 7518 §5.1).
enum class content_encryption {
    A128CBC_HS256,
    A192CBC_HS384,
    A256CBC_HS512,
    A128GCM,
    A192GCM,
    A256GCM,
};

/// The registered name ("A256GCM", ...) and back. An unknown name is
/// errc::unsupported_algorithm.
///@{
auto to_string(content_encryption alg) -> std::string_view;
auto parse_content_encryption(std::string_view s) -> expected<content_encryption>;
///@}

/// Sizes in octets for `enc`: the CEK (32, 48 or 64 for CBC-HMAC, which
/// splits it into MAC and encryption keys; 16, 24 or 32 for GCM), the IV
/// (16 for CBC, 12 for GCM) and the authentication tag (half the CEK for
/// CBC-HMAC, 16 for GCM).
///@{
auto cek_byte_size(content_encryption enc) -> size_t;
auto iv_byte_size(content_encryption enc) -> size_t;
auto tag_byte_size(content_encryption enc) -> size_t;
///@}

// --- Hash algorithm for thumbprints ---

/// The hash for jwk::thumbprint.
enum class hash_algorithm {
    SHA256,
    SHA384,
    SHA512,
};

// --- EC Curves ---

/// The NIST curves for EC keys ("crv": "P-256", "P-384", "P-521").
enum class ec_curve {
    P256,
    P384,
    P521,
};

/// The registered "crv" name ("P-256", ...) and back. An unknown name is
/// errc::unsupported_algorithm.
///@{
auto to_string(ec_curve crv) -> std::string_view;
auto parse_ec_curve(std::string_view s) -> expected<ec_curve>;
///@}

// --- OKP Curves ---

/// The curves for OKP keys (RFC 8037): Ed25519 and Ed448 sign, X25519 and
/// X448 do ECDH-ES key agreement.
enum class okp_curve {
    Ed25519,
    Ed448,
    X25519,
    X448,
};

/// The registered "crv" name ("Ed25519", ...) and back. An unknown name is
/// errc::unsupported_algorithm.
///@{
auto to_string(okp_curve crv) -> std::string_view;
auto parse_okp_curve(std::string_view s) -> expected<okp_curve>;
///@}

// --- Key types ---

/// A JWK "kty" (RFC 7518 §6.1, RFC 8037 for OKP).
enum class kty {
    RSA,
    EC,
    oct,
    OKP,
};

/// The registered "kty" name and back. An unknown name is
/// errc::unsupported_algorithm.
///@{
auto to_string(kty k) -> std::string_view;
auto parse_kty(std::string_view s) -> expected<kty>;
///@}

// --- Legacy opt-in ---

/// Opt-ins for algorithms that are off by default (PLAN.md §Legacy Algorithms).
struct legacy_options {
    /// Allow RSA1_5 key management (RSAES-PKCS1-v1_5), which is open to
    /// padding-oracle attacks. Needed on both the encrypt and decrypt side.
    bool allow_rsa1_5 = false;
};

} // namespace jose
