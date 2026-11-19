#pragma once

/// @file
/// Opaque keys: signing, verification and key decryption done by code the
/// library can't see into (an HSM, a PKCS#11 token, a cloud KMS) through
/// small interfaces modelled on go-jose v4's OpaqueSigner, OpaqueVerifier
/// and OpaqueKeyDecrypter.
///
/// @code{.cpp}
/// struct kms_signer final : jose::opaque_signer {
///     auto public_key() const -> jose::expected<jose::jwk> override { ... }
///     auto algorithms() const -> std::vector<jose::signing_algorithm> override {
///         return {jose::signing_algorithm::ES256};
///     }
///     auto sign(std::span<const uint8_t> input, jose::signing_algorithm alg)
///         -> jose::expected<std::vector<uint8_t>> override { ... }
/// };
///
/// auto signed_ = jose::jws::sign(payload, {jose::signing_algorithm::ES256,
///                                          std::make_shared<kms_signer>()});
/// auto payload = parsed->verify(my_opaque_verifier);
/// auto plaintext = parsed_jwe->decrypt(my_opaque_decrypter);
/// @endcode
///
/// These interfaces are synchronous; async.hpp has coroutine variants for
/// network-bound backends (cloud KMSs).
///
/// Errors: return errc::key_unavailable for operational failures (network,
/// permissions, device offline); the library passes those through. Any
/// other error from verify() is reported as errc::invalid_signature, and
/// from decrypt_key() as errc::decryption_failed, so failures that depend
/// on the token's contents look the same as the library's own.

#include "jose/algorithm.hpp"
#include "jose/error.hpp"
#include "jose/header.hpp"
#include "jose/jwk.hpp"
#include "jose/secure_bytes.hpp"

#include <cstdint>
#include <span>
#include <vector>

namespace jose {

/// Produces JWS signatures with a key it holds.
class opaque_signer {
public:
    virtual ~opaque_signer() = default;

    /// The public key. Its "kid" goes in the header
    /// (jws_sign_options::include_kid) and the key itself with embed_jwk. A private key may
    /// be returned; only its public part is used.
    [[nodiscard]] virtual auto public_key() const -> expected<jwk> = 0;
    /// The algorithms sign() supports; signing with any other fails with
    /// errc::algorithm_mismatch before sign() is called.
    [[nodiscard]] virtual auto algorithms() const -> std::vector<signing_algorithm> = 0;
    /// Signs the JWS signing input (RFC 7515 §5.1). The result must be in
    /// JWS form: ES* signatures are R || S (64, 96 or 132 octets), not DER.
    virtual auto sign(std::span<const uint8_t> signing_input, signing_algorithm alg)
        -> expected<std::vector<uint8_t>> = 0;

protected:
    opaque_signer() = default;
    /// Copyable by derived classes only, so a base reference can't slice.
    ///@{
    opaque_signer(const opaque_signer&) = default;
    opaque_signer& operator=(const opaque_signer&) = default;
    ///@}
};

/// Checks JWS signatures.
class opaque_verifier {
public:
    virtual ~opaque_verifier() = default;

    /// Signatures with other algorithms aren't passed to verify().
    [[nodiscard]] virtual auto algorithms() const -> std::vector<signing_algorithm> = 0;
    /// Succeeds if `signature` is valid for `signing_input` under `alg`.
    virtual auto verify(std::span<const uint8_t> signing_input, std::span<const uint8_t> signature,
                        signing_algorithm alg) -> expected<void> = 0;

protected:
    opaque_verifier() = default;
    /// Copyable by derived classes only, so a base reference can't slice.
    ///@{
    opaque_verifier(const opaque_verifier&) = default;
    opaque_verifier& operator=(const opaque_verifier&) = default;
    ///@}
};

/// Recovers a JWE content-encryption key.
class opaque_key_decrypter {
public:
    virtual ~opaque_key_decrypter() = default;

    /// Recipients with other algorithms aren't passed to decrypt_key().
    /// RSA1_5 is still refused unless jwe_decrypt_options::legacy allows it.
    [[nodiscard]] virtual auto algorithms() const -> std::vector<key_algorithm> = 0;
    /// Returns the CEK for content encryption `enc` (its length is checked).
    /// `joined` is the recipient's complete header, with "epk", "apu",
    /// "apv", "iv", "tag", "p2s" and "p2c" as the algorithm needs.
    /// `encrypted_key` is empty for "dir" and "ECDH-ES".
    ///
    /// With RSA1_5, a padding failure must not be distinguishable, by
    /// error or by timing, from success (RFC 7516 §11.5); the library
    /// can't apply its usual countermeasure inside someone else's code.
    virtual auto decrypt_key(std::span<const uint8_t> encrypted_key, key_algorithm alg, content_encryption enc,
                             const header& joined) -> expected<secure_bytes> = 0;

protected:
    opaque_key_decrypter() = default;
    /// Copyable by derived classes only, so a base reference can't slice.
    ///@{
    opaque_key_decrypter(const opaque_key_decrypter&) = default;
    opaque_key_decrypter& operator=(const opaque_key_decrypter&) = default;
    ///@}
};

} // namespace jose
