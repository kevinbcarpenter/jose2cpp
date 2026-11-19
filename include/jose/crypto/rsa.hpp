#pragma once

/// @file
/// RSA signatures (RS*, PS*) and RSA key management (RSA-OAEP, RSA-OAEP-256,
/// legacy RSA1_5).

#include "jose/algorithm.hpp"
#include "jose/crypto/openssl_util.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace jose {

// --- RSA signatures (RFC 7518 §3.3, §3.5): RS256/384/512, PS256/384/512 ---

/// Signs `data` with RS* (PKCS#1 v1.5) or PS* (PSS, salt the size of the
/// hash). The key must be RSA and at least 2048 bits. Prefer jose::sign.
auto rsa_sign(signing_algorithm alg, EVP_PKEY* key,
              std::span<const uint8_t> data) -> expected<secure_bytes>;

/// Succeeds if `signature` is valid; otherwise errc::invalid_signature.
auto rsa_verify(signing_algorithm alg, EVP_PKEY* key,
                std::span<const uint8_t> data,
                std::span<const uint8_t> signature) -> expected<void>;

// --- RSA key encryption (RFC 7518 §4.2, §4.3) ---

/// Encrypts a CEK with RSA-OAEP (SHA-1), RSA-OAEP-256 (SHA-256) or legacy
/// RSA1_5. Keys must be RSA and at least 2048 bits.
///
/// RSA1_5 is vulnerable to Bleichenbacher padding-oracle attacks and is
/// refused with errc::legacy_algorithm_disabled unless the caller passes
/// legacy_options{.allow_rsa1_5 = true}, on both the encrypt and decrypt
/// paths.
auto rsa_encrypt_key(key_algorithm alg, EVP_PKEY* public_key,
                     std::span<const uint8_t> cek,
                     legacy_options legacy = {}) -> expected<secure_bytes>;

/// `cek_len` is the CEK size required by the JWE "enc" algorithm
/// (cek_byte_size(enc)); it must be non-zero.
///
/// RSA-OAEP / RSA-OAEP-256: any failure, including a decrypted key of the
/// wrong length, returns errc::decryption_failed.
///
/// RSA1_5: a padding failure or wrong-length key does NOT return an error.
/// Instead a random CEK of `cek_len` bytes is returned, chosen in constant
/// time, so the failure surfaces later as an ordinary authentication-tag
/// failure and an attacker cannot tell the two apart (RFC 7516 §11.5;
/// same countermeasure as go-jose).
auto rsa_decrypt_key(key_algorithm alg, EVP_PKEY* private_key,
                     std::span<const uint8_t> encrypted_key, size_t cek_len,
                     legacy_options legacy = {}) -> expected<secure_bytes>;

} // namespace jose
