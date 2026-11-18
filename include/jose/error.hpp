#pragma once

// jose::expected is std::expected when built in C++23 mode (or when
// JOSE_USE_STD_EXPECTED=ON); otherwise the vendored expected-lite
// polyfill provides the same interface on C++20. The selection is
// pinned at configure time via nsel_CONFIG_SELECT_EXPECTED so that a
// library build and its consumers always agree on the type.
#include "jose/detail/expected.hpp"

#include <string>
#include <utility>

namespace jose {

enum class errc {
    invalid_token,
    invalid_signature,
    invalid_key,
    algorithm_mismatch,
    expired,
    not_yet_valid,
    missing_claim,
    decryption_failed,
    unsupported_algorithm,
    invalid_header,
    serialization_error,
    key_too_short,
    invalid_base64,
    openssl_error,
    invalid_curve_point,
    key_size_too_small,
    unrecognized_critical_extension,
    legacy_algorithm_disabled,
    invalid_tag,
    invalid_iv,
    compression_error,
    invalid_argument,
    // An opaque key's backend (HSM, KMS, ...) couldn't perform the
    // operation: network, permissions, device offline. See opaque.hpp.
    key_unavailable,
    // A JWT claim doesn't match what the caller expects ("iss", "sub",
    // "aud", "jti"). See jwt::registered_claims::validate.
    invalid_claim,
};

struct error {
    errc code;
    std::string message;

    error(errc c, std::string msg) : code(c), message(std::move(msg)) {}
};

template <typename T>
using expected = nonstd::expected<T, error>;

using unexpected = nonstd::unexpected_type<error>;

inline auto make_error(errc code, std::string message) -> unexpected {
    return unexpected(error(code, std::move(message)));
}

} // namespace jose
