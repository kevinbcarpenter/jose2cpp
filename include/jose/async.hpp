#pragma once

/// @file
/// Async opaque keys: the coroutine counterparts of opaque.hpp, for backends
/// reached over the network, such as cloud KMSs (AWS KMS, Google Cloud KMS,
/// Azure Key Vault) and network HSMs, where blocking a thread per operation
/// is wasteful.
///
/// @code{.cpp}
/// struct kms_signer final : jose::async_opaque_signer {
///     auto public_key() -> jose::task<jose::expected<jose::jwk>> override {
///         auto pem = co_await client.get_public_key(key_arn);   // your awaitable
///         co_return jose::jwk::from_pem(pem);
///     }
///     auto algorithms() const -> std::vector<jose::signing_algorithm> override {
///         return {jose::signing_algorithm::ES256};
///     }
///     auto sign(std::span<const uint8_t> input, jose::signing_algorithm alg)
///         -> jose::task<jose::expected<std::vector<uint8_t>>> override {
///         std::vector<uint8_t> copy(input.begin(), input.end());  // see below
///         auto der = co_await client.sign(key_arn, copy);
///         co_return der_to_jws(der);
///     }
/// };
///
/// auto signed_ = co_await jose::jws::sign_async(payload, {alg, std::make_shared<kms_signer>()});
/// auto plaintext = co_await parsed_jwe.decrypt_async(my_async_decrypter);
/// @endcode
///
/// Spans passed to these methods are valid until the returned task
/// finishes. They are not copied, so a task that the implementation hands
/// to another thread or stores must copy what it needs.
///
/// The rules for errors and algorithms are those of opaque.hpp:
/// errc::key_unavailable passes through; other verifier errors become
/// errc::invalid_signature and other decrypter errors the uniform
/// errc::decryption_failed; algorithms outside algorithms() are never
/// passed in.

#include "jose/algorithm.hpp"
#include "jose/error.hpp"
#include "jose/header.hpp"
#include "jose/jwk.hpp"
#include "jose/secure_bytes.hpp"
#include "jose/task.hpp"

#include <cstdint>
#include <span>
#include <vector>

namespace jose {

/// A signing key held by a remote backend (KMS, network HSM), used through coroutines. The async counterpart of opaque_signer.
class async_opaque_signer {
public:
    virtual ~async_opaque_signer() = default;

    /// Fetched only when jws_sign_options::include_kid or embed_jwk needs it.
    virtual auto public_key() -> task<expected<jwk>> = 0;
    /// The algorithms this key signs with; jws::sign_async refuses others.
    [[nodiscard]] virtual auto algorithms() const -> std::vector<signing_algorithm> = 0;
    /// ES* signatures must be R || S (64, 96 or 132 octets), not DER.
    virtual auto sign(std::span<const uint8_t> signing_input, signing_algorithm alg)
        -> task<expected<std::vector<uint8_t>>> = 0;

protected:
    async_opaque_signer() = default;
    /// Copyable by derived classes only, so a base reference can't slice.
    ///@{
    async_opaque_signer(const async_opaque_signer&) = default;
    async_opaque_signer& operator=(const async_opaque_signer&) = default;
    ///@}
};

/// A verification key held by a remote backend, used through coroutines. The async counterpart of opaque_verifier.
class async_opaque_verifier {
public:
    virtual ~async_opaque_verifier() = default;

    /// The algorithms this key verifies; a signature with another "alg" is
    /// errc::algorithm_mismatch and never reaches verify().
    [[nodiscard]] virtual auto algorithms() const -> std::vector<signing_algorithm> = 0;
    /// Succeeds if `signature` is valid for `signing_input` under `alg`.
    /// ES* signatures arrive as R || S, not DER.
    virtual auto verify(std::span<const uint8_t> signing_input, std::span<const uint8_t> signature,
                        signing_algorithm alg) -> task<expected<void>> = 0;

protected:
    async_opaque_verifier() = default;
    /// Copyable by derived classes only, so a base reference can't slice.
    ///@{
    async_opaque_verifier(const async_opaque_verifier&) = default;
    async_opaque_verifier& operator=(const async_opaque_verifier&) = default;
    ///@}
};

/// A key-management private key held by a remote backend, used through coroutines. The async counterpart of opaque_key_decrypter.
class async_opaque_key_decrypter {
public:
    virtual ~async_opaque_key_decrypter() = default;

    /// The key-management algorithms this key handles; recipients using
    /// others are skipped.
    [[nodiscard]] virtual auto algorithms() const -> std::vector<key_algorithm> = 0;
    /// As opaque_key_decrypter::decrypt_key, including the RSA1_5 caveat.
    virtual auto decrypt_key(std::span<const uint8_t> encrypted_key, key_algorithm alg, content_encryption enc,
                             const header& joined) -> task<expected<secure_bytes>> = 0;

protected:
    async_opaque_key_decrypter() = default;
    /// Copyable by derived classes only, so a base reference can't slice.
    ///@{
    async_opaque_key_decrypter(const async_opaque_key_decrypter&) = default;
    async_opaque_key_decrypter& operator=(const async_opaque_key_decrypter&) = default;
    ///@}
};

} // namespace jose
