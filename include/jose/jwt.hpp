#pragma once

// JSON Web Token (RFC 7519): building and parsing signed, encrypted and
// nested (signed-then-encrypted) tokens. Modelled on go-jose v4's jwt
// package (Signed / Encrypted / SignedAndEncrypted, ParseSigned /
// ParseEncrypted / ParseSignedAndEncrypted).
//
// Key-management algorithms (the "split rule"):
// - An encrypted-only JWT has no signature, so whoever can encrypt to the
//   recipient can mint one. With RSA or ECDH-ES that is anyone holding the
//   public key, and PBES2 is only as strong as a password. Encrypted-only
//   JWTs therefore accept only the symmetric key-wrapping algorithms: dir,
//   A128KW/A192KW/A256KW and A128GCMKW/A192GCMKW/A256GCMKW. Others are
//   errc::invalid_argument when building and when listed in a parse
//   allowlist. go-jose v4 has the same rule when parsing, but its builder
//   doesn't apply it, so go-jose can emit encrypted-only JWTs that neither
//   library will parse.
// - A nested JWT is authenticated by its inner signature, so its JWE may use
//   any key-management algorithm, including RSA-OAEP and ECDH-ES (as OIDC
//   encrypted ID tokens do). go-jose v4 applies the encrypted-only rule to
//   nested JWTs too, so a nested JWT whose JWE uses RSA, ECDH-ES or PBES2
//   can't be read by go-jose.
//
// Building:
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
//
// Parsing: every parse function takes the algorithms the caller accepts,
// and the claims are only handed out after the signature verifies or the
// JWE decrypts.
//
//   auto parsed = jose::jwt::parse_signed(token, {jose::signing_algorithm::ES256});
//   auto claims = parsed->claims(public_key);        // expected<nlohmann::json>
//   auto typed  = jose::jwt::decode<my_claims>(*claims);
//
// The claims must be a JSON object, parsed strictly (duplicate member names
// are rejected, as everywhere in jose2cpp). Checking "exp", "aud" and the
// rest is a separate step (registered_claims::validate).
//
// Async opaque keys (async.hpp): the signed and nested builders have
// token_async() / serialize_async(), and the parsed tokens claims_async()
// and decrypt_async(). They copy what they need into the task, so only the
// verifier or decrypter passed by reference must outlive it.

#include "jose/algorithm.hpp"
#include "jose/error.hpp"
#include "jose/header.hpp"
#include "jose/jwe.hpp"
#include "jose/jws.hpp"
#include "jose/jwt_claims.hpp"
#include "jose/task.hpp"

#include <nlohmann/json.hpp>

#include <concepts>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

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
    // For a signer holding an async_opaque_signer (local and sync opaque
    // signers work too). The claims, signer and options are copied into the
    // task, so the builder may be a temporary.
    [[nodiscard]] auto token_async() const -> task<expected<jws>>;
    [[nodiscard]] auto serialize_async() const -> task<expected<std::string>>;

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
    // As for signed_builder: the inner JWS is signed asynchronously, then
    // encrypted. Everything is copied into the task.
    [[nodiscard]] auto token_async() const -> task<expected<jwe>>;
    [[nodiscard]] auto serialize_async() const -> task<expected<std::string>>;

private:
    jws_signer signer_;
    content_encryption enc_;
    jwe_recipient recipient_;
    jws_sign_options sign_options_;
    jwe_encrypt_options encrypt_options_;
    claim_set claims_;
};

// ===========================================================================
// Parsing
// ===========================================================================

// Converts verified claims to `T` with nlohmann's from_json. A type mismatch
// (any nlohmann::json exception) is errc::invalid_token instead of an
// exception. Exceptions of other types thrown by your own from_json pass
// through.
template <typename T>
auto decode(const nlohmann::json& claims) -> expected<T> {
    try {
        return claims.get<T>();
    } catch (const nlohmann::json::exception& e) {
        return make_error(errc::invalid_token, std::string("JWT claims don't match the expected type: ") + e.what());
    }
}

// A parsed JWS-based JWT.
class signed_jwt {
public:
    // The signature's header (protected; a compact JWS has nothing else).
    [[nodiscard]] auto header() const noexcept -> const jose::header& { return jws_.signatures().front().joined; }
    [[nodiscard]] auto token() const noexcept -> const jws& { return jws_; }

    // Verifies the signature, then returns the claims.
    [[nodiscard]] auto claims(const jwk& key) const -> expected<nlohmann::json>;
    // The header must carry a "kid"; every key in the set with it is tried.
    [[nodiscard]] auto claims(const jwk_set& keys) const -> expected<nlohmann::json>;
    [[nodiscard]] auto claims(opaque_verifier& verifier) const -> expected<nlohmann::json>;
    // With an async opaque verifier. The token is copied into the task;
    // the verifier must outlive it.
    [[nodiscard]] auto claims_async(async_opaque_verifier& verifier) const -> task<expected<nlohmann::json>>;
    // NOT verified: only for choosing a key (by "iss", say) before claims().
    [[nodiscard]] auto unsafe_claims() const -> expected<nlohmann::json>;

private:
    friend auto parse_signed(std::string_view, const std::vector<signing_algorithm>&, const extension_set&)
        -> expected<signed_jwt>;
    explicit signed_jwt(jws token) : jws_(std::move(token)) {}
    jws jws_;
};

// A parsed encrypted-only JWT.
class encrypted_jwt {
public:
    [[nodiscard]] auto header() const noexcept -> const jose::header& { return jwe_.recipients().front().joined; }
    [[nodiscard]] auto token() const noexcept -> const jwe& { return jwe_; }

    // Decrypts, then returns the claims.
    [[nodiscard]] auto claims(const jwk& key, const jwe_decrypt_options& options = {}) const
        -> expected<nlohmann::json>;
    [[nodiscard]] auto claims(const jwk_set& keys, const jwe_decrypt_options& options = {}) const
        -> expected<nlohmann::json>;
    [[nodiscard]] auto claims(opaque_key_decrypter& decrypter, const jwe_decrypt_options& options = {}) const
        -> expected<nlohmann::json>;
    // With an async opaque key decrypter. The token and options are copied
    // into the task; the decrypter must outlive it.
    [[nodiscard]] auto claims_async(async_opaque_key_decrypter& decrypter, jwe_decrypt_options options = {}) const
        -> task<expected<nlohmann::json>>;

private:
    friend auto parse_encrypted(std::string_view, const std::vector<key_algorithm>&,
                                const std::vector<content_encryption>&, const extension_set&)
        -> expected<encrypted_jwt>;
    explicit encrypted_jwt(jwe token) : jwe_(std::move(token)) {}
    jwe jwe_;
};

// A parsed nested JWT: decrypt() opens the JWE and parses the JWS inside
// with the signature algorithms given to parse_signed_and_encrypted(). The
// plaintext must be exactly one compact JWS; anything else (the bare
// claims, a JSON JWS, another nested JWE) fails with parse_signed's error
// once decrypted. Whitespace at either end of it is ignored, as for any
// compact token (see jws::parse_compact); a line break inside it is
// refused, though go-jose's JWT parser accepts one.
class nested_jwt {
public:
    // The JWE's header.
    [[nodiscard]] auto header() const noexcept -> const jose::header& { return jwe_.recipients().front().joined; }
    [[nodiscard]] auto token() const noexcept -> const jwe& { return jwe_; }

    [[nodiscard]] auto decrypt(const jwk& key, const jwe_decrypt_options& options = {}) const
        -> expected<signed_jwt>;
    [[nodiscard]] auto decrypt(const jwk_set& keys, const jwe_decrypt_options& options = {}) const
        -> expected<signed_jwt>;
    [[nodiscard]] auto decrypt(opaque_key_decrypter& decrypter, const jwe_decrypt_options& options = {}) const
        -> expected<signed_jwt>;
    // With an async opaque key decrypter. The token, the signature
    // algorithms and `understood` given to parse_signed_and_encrypted() and
    // the options are copied into the task, so the inner JWS is held to the
    // same allowlist as decrypt(); the decrypter must outlive the task.
    [[nodiscard]] auto decrypt_async(async_opaque_key_decrypter& decrypter, jwe_decrypt_options options = {}) const
        -> task<expected<signed_jwt>>;

private:
    friend auto parse_signed_and_encrypted(std::string_view, const std::vector<key_algorithm>&,
                                           const std::vector<content_encryption>&,
                                           const std::vector<signing_algorithm>&, const extension_set&)
        -> expected<nested_jwt>;
    nested_jwt(jwe token, std::vector<signing_algorithm> signature_algorithms, extension_set understood)
        : jwe_(std::move(token)), signature_algorithms_(std::move(signature_algorithms)),
          understood_(std::move(understood)) {}
    auto inner(expected<secure_bytes> plaintext) const -> expected<signed_jwt>;

    jwe jwe_;
    std::vector<signing_algorithm> signature_algorithms_;
    extension_set understood_;
};

// A JWS compact serialization. `understood` lists critical header
// extensions the application handles, as for jws::parse.
auto parse_signed(std::string_view token, const std::vector<signing_algorithm>& algorithms,
                  const extension_set& understood = {}) -> expected<signed_jwt>;

// A JWE compact serialization whose plaintext is the claims. Only the
// symmetric key-wrapping algorithms may be listed (see the top of this
// file). A token with "cty":"JWT" is nested: use
// parse_signed_and_encrypted().
auto parse_encrypted(std::string_view token, const std::vector<key_algorithm>& key_algorithms,
                     const std::vector<content_encryption>& encryptions, const extension_set& understood = {})
    -> expected<encrypted_jwt>;

// A JWE compact serialization with "cty":"JWT" (compared case-insensitively,
// as media types are) whose plaintext is a JWS compact serialization. Any
// key-management algorithm may be listed. `understood` applies to critical
// extensions on both the JWE and the JWS inside.
auto parse_signed_and_encrypted(std::string_view token, const std::vector<key_algorithm>& key_algorithms,
                                const std::vector<content_encryption>& encryptions,
                                const std::vector<signing_algorithm>& signature_algorithms,
                                const extension_set& understood = {}) -> expected<nested_jwt>;

// ===========================================================================
// Building
// ===========================================================================

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
