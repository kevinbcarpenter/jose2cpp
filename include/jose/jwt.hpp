#pragma once

// JSON Web Token (RFC 7519): building signed, encrypted and nested
// (signed-then-encrypted) tokens. Modelled on go-jose v4's jwt.Signed,
// jwt.Encrypted and jwt.SignedAndEncrypted builders.
//
//   auto token = jose::jwt::signed_token({jose::signing_algorithm::ES256, key})
//                    .claims({{"iss", "https://auth.example.com"}, {"sub", "kevin"}})
//                    .claims(my_private_claims)      // anything nlohmann::json can serialize to an object
//                    .serialize();                   // expected<std::string>, compact form
//
// Claims accumulate into one JSON object. A claim name given twice is an
// error (go-jose silently keeps the last one), and so is a claims value
// that isn't a JSON object, a number that isn't finite, a string that isn't
// UTF-8, or a value JSON can't represent. Errors are reported by
// serialize() / token(), so a chain needs only one check: an error in the
// builder's options first, then the first claims error.
//
// Keep a builder by value (`auto b = jwt::signed_token(...);`). claims() on
// a temporary returns the builder by value, so a reference can't be bound
// to one that is about to be destroyed.
//
// Headers: "typ":"JWT" is set unless the caller sets "typ". A nested token
// gets "cty":"JWT" on its JWE (RFC 7519 §5.2); a different "cty" there is
// an error. JWTs always use the compact serialization and a base64url
// payload, so jws_sign_options::b64 must stay true.

#include "jose/algorithm.hpp"
#include "jose/error.hpp"
#include "jose/jwe.hpp"
#include "jose/jws.hpp"

#include <nlohmann/json.hpp>

#include <concepts>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>

namespace jose::jwt {

// The claims of a token under construction. Shared by the builders.
class claim_set {
public:
    auto add(const nlohmann::json& object) -> void;
    [[nodiscard]] auto error() const noexcept -> const std::optional<jose::error>& { return error_; }
    // The claims as the JWS/JWE payload (UTF-8 JSON).
    [[nodiscard]] auto payload() const -> expected<std::string>;

private:
    nlohmann::json claims_ = nlohmann::json::object();
    std::optional<jose::error> error_;
};

// Anything nlohmann::json can serialize (e.g. a struct with to_json).
template <typename T>
concept claims_value = !std::same_as<std::remove_cvref_t<T>, nlohmann::json> && requires(const T& v) {
    nlohmann::json(v);
};

class signed_builder {
public:
    signed_builder(jws_signer signer, jws_sign_options options = {});

    auto claims(const nlohmann::json& object) & -> signed_builder& {
        claims_.add(object);
        return *this;
    }
    auto claims(const nlohmann::json& object) && -> signed_builder {
        claims_.add(object);
        return std::move(*this);
    }
    template <claims_value T>
    auto claims(const T& value) & -> signed_builder& {
        return claims(nlohmann::json(value));
    }
    template <claims_value T>
    auto claims(const T& value) && -> signed_builder {
        return std::move(*this).claims(nlohmann::json(value));
    }

    [[nodiscard]] auto token() const -> expected<jws>;
    [[nodiscard]] auto serialize() const -> expected<std::string>;

private:
    jws_signer signer_;
    jws_sign_options options_;
    claim_set claims_;
};

class encrypted_builder {
public:
    encrypted_builder(content_encryption enc, jwe_recipient recipient, jwe_encrypt_options options = {});

    auto claims(const nlohmann::json& object) & -> encrypted_builder& {
        claims_.add(object);
        return *this;
    }
    auto claims(const nlohmann::json& object) && -> encrypted_builder {
        claims_.add(object);
        return std::move(*this);
    }
    template <claims_value T>
    auto claims(const T& value) & -> encrypted_builder& {
        return claims(nlohmann::json(value));
    }
    template <claims_value T>
    auto claims(const T& value) && -> encrypted_builder {
        return std::move(*this).claims(nlohmann::json(value));
    }

    [[nodiscard]] auto token() const -> expected<jwe>;
    [[nodiscard]] auto serialize() const -> expected<std::string>;

private:
    content_encryption enc_;
    jwe_recipient recipient_;
    jwe_encrypt_options options_;
    claim_set claims_;
};

// Signs the claims, then encrypts the compact JWS (RFC 7519 §5.2, §A.2).
class nested_builder {
public:
    nested_builder(jws_signer signer, content_encryption enc, jwe_recipient recipient,
                   jws_sign_options sign_options = {}, jwe_encrypt_options encrypt_options = {});

    auto claims(const nlohmann::json& object) & -> nested_builder& {
        claims_.add(object);
        return *this;
    }
    auto claims(const nlohmann::json& object) && -> nested_builder {
        claims_.add(object);
        return std::move(*this);
    }
    template <claims_value T>
    auto claims(const T& value) & -> nested_builder& {
        return claims(nlohmann::json(value));
    }
    template <claims_value T>
    auto claims(const T& value) && -> nested_builder {
        return std::move(*this).claims(nlohmann::json(value));
    }

    // The outer JWE; its plaintext is the inner compact JWS.
    [[nodiscard]] auto token() const -> expected<jwe>;
    [[nodiscard]] auto serialize() const -> expected<std::string>;

private:
    jws_signer signer_;
    content_encryption enc_;
    jwe_recipient recipient_;
    jws_sign_options sign_options_;
    jwe_encrypt_options encrypt_options_;
    claim_set claims_;
};

inline auto signed_token(jws_signer signer, jws_sign_options options = {}) -> signed_builder {
    return {std::move(signer), options};
}

inline auto encrypted_token(content_encryption enc, jwe_recipient recipient, jwe_encrypt_options options = {})
    -> encrypted_builder {
    return {enc, std::move(recipient), std::move(options)};
}

inline auto signed_and_encrypted(jws_signer signer, content_encryption enc, jwe_recipient recipient,
                                 jws_sign_options sign_options = {}, jwe_encrypt_options encrypt_options = {})
    -> nested_builder {
    return {std::move(signer), enc, std::move(recipient), sign_options, std::move(encrypt_options)};
}

} // namespace jose::jwt
