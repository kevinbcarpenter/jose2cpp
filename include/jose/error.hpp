#pragma once

/// @file
/// Error codes and jose::expected, the return type of everything that can
/// fail. The library doesn't throw for bad input or failed crypto.
///
/// jose::expected is std::expected when built in C++23 mode (or when
/// JOSE_USE_STD_EXPECTED=ON); otherwise the vendored expected-lite
/// polyfill provides the same interface on C++20. The selection is
/// pinned at configure time via nsel_CONFIG_SELECT_EXPECTED so that a
/// library build and its consumers always agree on the type.

#include "jose/detail/expected.hpp"

#include <string>
#include <utility>

/// jose2cpp: JWS, JWE, JWK and JWT.
namespace jose {

/// What kind of failure an error is. Messages carry the detail.
enum class errc {
    /// A malformed JWS or JWE: wrong number of parts, missing or mistyped members, more than 32 signatures or
    /// recipients. Also a JWT whose claims don't decode to the requested type.
    invalid_token,
    /// The signature doesn't verify with the key given.
    invalid_signature,
    /// The key is malformed, its "use" or "key_ops" don't permit the operation, no key in a set has the token's
    /// "kid", or an oct key is the wrong size for AES key wrap or direct encryption.
    invalid_key,
    /// The token's algorithm isn't in the caller's allowlist, or the key can't be used with it: the wrong type or
    /// curve, or a different "alg" of its own.
    algorithm_mismatch,
    /// The JWT's "exp" has passed (allowing for leeway).
    expired,
    /// The JWT's "nbf" or "iat" is in the future (allowing for leeway).
    not_yet_valid,
    /// A claim the validation requires is absent.
    missing_claim,
    /// The JWE didn't decrypt. Deliberately uniform: it doesn't say which step failed.
    decryption_failed,
    /// An algorithm, curve, key type or "zip" value this library doesn't implement, "none" included.
    unsupported_algorithm,
    /// A header parameter is missing, has the wrong type, or is out of range ("p2c", "zip", "b64", ...).
    invalid_header,
    /// JSON that can't be produced or parsed strictly: duplicate names, bad UTF-8, nesting deeper than 128.
    serialization_error,
    /// An HMAC key shorter than its algorithm requires (32, 48 or 64 octets for HS256, HS384, HS512).
    key_too_short,
    /// A base64url part has characters outside the alphabet, padding, or non-canonical trailing bits.
    invalid_base64,
    /// An OpenSSL call failed (the message names the call and OpenSSL's reason), or the secure heap was already
    /// initialised.
    openssl_error,
    /// EC key coordinates of the wrong length for the curve.
    invalid_curve_point,
    /// An RSA key under 2048 bits, generated, imported or used.
    key_size_too_small,
    /// The header lists a "crit" extension the caller didn't say it understands.
    unrecognized_critical_extension,
    /// A legacy algorithm (RSA1_5) used without legacy_options allowing it.
    legacy_algorithm_disabled,
    /// A JWE authentication tag of the wrong length, or, from aes_cbc_hmac_decrypt only, one that doesn't match.
    invalid_tag,
    /// An initialization vector of the wrong length.
    invalid_iv,
    /// "zip":"DEF" content that doesn't inflate, or inflates past the size limit.
    compression_error,
    /// The caller passed something unusable: an empty signer list, a bad option, too many recipients.
    invalid_argument,
    /// An opaque key's backend (HSM, KMS, ...) couldn't perform the
    /// operation: network, permissions, device offline. See opaque.hpp.
    key_unavailable,
    /// A JWT claim doesn't match what the caller expects ("iss", "sub",
    /// "aud", "jti"). See jwt::registered_claims::validate.
    invalid_claim,
};

/// What went wrong: a code to branch on and a message for people.
struct error {
    errc code;           ///< The kind of failure.
    std::string message; ///< Human-readable detail.

    /// Makes an error from a code and a message.
    error(errc c, std::string msg) : code(c), message(std::move(msg)) {}
};

/// A T or a jose::error.
template <typename T>
using expected = nonstd::expected<T, error>;

/// The error side of an expected, for returning failures.
using unexpected = nonstd::unexpected_type<error>;

/// Shorthand for `unexpected(error(code, message))`.
inline auto make_error(errc code, std::string message) -> unexpected {
    return unexpected(error(code, std::move(message)));
}

} // namespace jose
