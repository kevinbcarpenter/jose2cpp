#include "jose/jwt.hpp"

#include "internal/codec.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <initializer_list>
#include <string_view>

namespace jose::jwt {

namespace {

using json = nlohmann::json;

auto bad_argument(std::string message) -> unexpected {
    return make_error(errc::invalid_argument, std::move(message));
}

// Sets `name` to `value` in `target` unless one of the header parts
// already has it.
auto set_default(header& target, std::initializer_list<const header*> parts, std::string_view name,
                 std::string_view value) -> expected<void> {
    for (const header* h : parts)
        if (h->contains(name)) return {};
    return target.set(std::string(name), std::string(value));
}

// The split rule (see jwt.hpp): an encrypted-only JWT may only use a
// symmetric key-wrapping algorithm. Written as an allowlist so an algorithm
// added later is refused until someone decides otherwise.
auto forgeable_without_signature(key_algorithm alg) -> bool {
    switch (alg) {
    case key_algorithm::dir:
    case key_algorithm::A128KW:
    case key_algorithm::A192KW:
    case key_algorithm::A256KW:
    case key_algorithm::A128GCMKW:
    case key_algorithm::A192GCMKW:
    case key_algorithm::A256GCMKW:
        return false;
    default:
        return true;
    }
}

auto check_encrypted_only(key_algorithm alg) -> expected<void> {
    if (!forgeable_without_signature(alg)) return {};
    return bad_argument("an encrypted-only JWT can't use " + std::string(to_string(alg)) +
                        ": without a signature anyone who can encrypt to the recipient could forge it; use a "
                        "nested (signed and encrypted) JWT, or dir / AES key wrap");
}

auto require_b64(const jws_sign_options& options) -> expected<void> {
    if (!options.b64) return bad_argument("a JWT payload is always base64url-encoded; jws_sign_options::b64 must be true");
    return {};
}

// RFC 7519 §5.2: the JWE of a nested JWT says its content is a JWT, so a
// caller-supplied "cty" must be "JWT".
auto check_nested_cty(const jwe_recipient& recipient, const jwe_encrypt_options& options) -> expected<void> {
    for (const header* h : {&options.protected_header, &options.shared_unprotected, &recipient.parameters})
        if (auto cty = h->cty(); cty && *cty != "JWT")
            return bad_argument("a nested JWT's JWE must have \"cty\":\"JWT\", not \"" + std::string(*cty) + "\"");
    return {};
}

// Options are checked before claims: they were given first, at construction.
auto sign_claims(const claim_set& claims, jws_signer signer, const jws_sign_options& options) -> expected<jws> {
    if (auto r = require_b64(options); !r) return jose::unexpected(r.error());
    if (claims.error()) return jose::unexpected(*claims.error());
    auto payload = claims.payload();
    if (!payload) return jose::unexpected(payload.error());

    if (auto r = set_default(signer.protected_header, {&signer.protected_header, &signer.unprotected_header},
                             "typ", "JWT");
        !r)
        return jose::unexpected(r.error());
    return jws::sign(std::string_view(*payload), signer, options);
}

auto encrypt_payload(std::string_view payload, content_encryption enc, jwe_recipient recipient,
                     jwe_encrypt_options options, bool nested) -> expected<jwe> {
    const std::initializer_list<const header*> parts{&options.protected_header, &options.shared_unprotected,
                                                     &recipient.parameters};
    if (nested) {
        if (auto r = check_nested_cty(recipient, options); !r) return jose::unexpected(r.error());
        if (auto r = set_default(options.protected_header, parts, "cty", "JWT"); !r)
            return jose::unexpected(r.error());
    }
    if (auto r = set_default(options.protected_header, parts, "typ", "JWT"); !r) return jose::unexpected(r.error());
    return jwe::encrypt(payload, enc, recipient, options);
}

} // namespace

// ===========================================================================
// claim_set
// ===========================================================================

auto claim_set::add(const json& object) -> void {
    if (error_) return;
    if (!object.is_object()) {
        error_ = jose::error(errc::invalid_argument, "JWT claims must be a JSON object");
        return;
    }
    for (const auto& [name, value] : object.items()) {
        if (claims_.contains(name)) {
            error_ = jose::error(errc::invalid_argument, "JWT claim \"" + name + "\" is given more than once");
            return;
        }
        claims_[name] = value;
    }
}

namespace {

// nlohmann writes NaN and infinity as null and a discarded value as the text
// "<discarded>", and dumps binary values in a shape no other library reads.
// None of these is a JSON claim, so they are errors rather than output.
auto find_unserializable(const json& j, const std::string& where) -> std::optional<std::string> {
    if (j.is_number_float() && !std::isfinite(j.get<double>())) return where + " is not a finite number";
    if (j.is_discarded()) return where + " is a discarded (failed-parse) value";
    if (j.is_binary()) return where + " is binary data, which JSON can't represent";
    if (j.is_object()) {
        for (const auto& [name, value] : j.items())
            if (auto bad = find_unserializable(value, where + "." + name)) return bad;
    } else if (j.is_array()) {
        for (size_t i = 0; i < j.size(); ++i)
            if (auto bad = find_unserializable(j[i], where + "[" + std::to_string(i) + "]")) return bad;
    }
    return std::nullopt;
}

} // namespace

auto claim_set::payload() const -> expected<std::string> {
    if (error_) return jose::unexpected(*error_);
    for (const auto& [name, value] : claims_.items())
        if (auto bad = find_unserializable(value, "\"" + name + "\""))
            return make_error(errc::serialization_error, "JWT claim " + *bad);
    try {
        // Strict: a string that isn't valid UTF-8 is an error, not U+FFFD.
        return claims_.dump(-1, ' ', false, json::error_handler_t::strict);
    } catch (const json::exception& e) {
        return make_error(errc::serialization_error, std::string("JWT claims can't be serialized: ") + e.what());
    }
}

// ===========================================================================
// Builders
// ===========================================================================

signed_builder::signed_builder(jws_signer signer, jws_sign_options options)
    : signer_(std::move(signer)), options_(options) {}

auto signed_builder::token() const -> expected<jws> {
    return sign_claims(claims_, signer_, options_);
}

auto signed_builder::serialize() const -> expected<std::string> {
    auto t = token();
    if (!t) return jose::unexpected(t.error());
    return t->compact();
}

encrypted_builder::encrypted_builder(content_encryption enc, jwe_recipient recipient, jwe_encrypt_options options)
    : enc_(enc), recipient_(std::move(recipient)), options_(std::move(options)) {}

auto encrypted_builder::token() const -> expected<jwe> {
    if (auto r = check_encrypted_only(recipient_.alg); !r) return jose::unexpected(r.error());
    if (claims_.error()) return jose::unexpected(*claims_.error());
    auto payload = claims_.payload();
    if (!payload) return jose::unexpected(payload.error());
    return encrypt_payload(*payload, enc_, recipient_, options_, false);
}

auto encrypted_builder::serialize() const -> expected<std::string> {
    auto t = token();
    if (!t) return jose::unexpected(t.error());
    return t->compact();
}

nested_builder::nested_builder(jws_signer signer, content_encryption enc, jwe_recipient recipient,
                               jws_sign_options sign_options, jwe_encrypt_options encrypt_options)
    : signer_(std::move(signer)), enc_(enc), recipient_(std::move(recipient)), sign_options_(sign_options),
      encrypt_options_(std::move(encrypt_options)) {}

auto nested_builder::token() const -> expected<jwe> {
    if (auto r = require_b64(sign_options_); !r) return jose::unexpected(r.error());
    if (auto r = check_nested_cty(recipient_, encrypt_options_); !r) return jose::unexpected(r.error());
    auto inner = sign_claims(claims_, signer_, sign_options_);
    if (!inner) return jose::unexpected(inner.error());
    auto compact = inner->compact();
    if (!compact) return jose::unexpected(compact.error());
    return encrypt_payload(*compact, enc_, recipient_, encrypt_options_, true);
}

auto nested_builder::serialize() const -> expected<std::string> {
    auto t = token();
    if (!t) return jose::unexpected(t.error());
    return t->compact();
}

// ===========================================================================
// Parsing
// ===========================================================================

namespace {

auto bad_token(std::string message) -> unexpected {
    return make_error(errc::invalid_token, std::move(message));
}

// RFC 7519 §7.2 steps 9-10: the claims are a JSON object.
auto parse_claims(std::string_view text) -> expected<json> {
    auto claims = internal::parse_json_strict(text, "JWT claims");
    if (!claims) return claims;
    if (!claims->is_object()) return bad_token("JWT claims must be a JSON object");
    return claims;
}

auto parse_claims(std::span<const uint8_t> bytes) -> expected<json> {
    return parse_claims(std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
}

template <typename Bytes>
auto claims_of(expected<Bytes> payload) -> expected<json> {
    if (!payload) return jose::unexpected(payload.error());
    return parse_claims(std::span<const uint8_t>(payload->data(), payload->size()));
}

// Media types compare case-insensitively (RFC 7515 §4.1.10).
auto is_jwt_content_type(std::string_view cty) -> bool {
    return std::ranges::equal(cty, std::string_view("JWT"),
                              [](char a, char b) { return std::toupper(static_cast<unsigned char>(a)) == b; });
}

auto check_key_algorithms(const std::vector<key_algorithm>& algorithms) -> expected<void> {
    for (auto alg : algorithms)
        if (auto r = check_encrypted_only(alg); !r) return r;
    return {};
}

} // namespace

auto parse_signed(std::string_view token, const std::vector<signing_algorithm>& algorithms,
                  const extension_set& understood) -> expected<signed_jwt> {
    auto parsed = jws::parse_compact(token, algorithms, understood);
    if (!parsed) return jose::unexpected(parsed.error());
    // RFC 7519 §7.1: a JWT's payload is the base64url-encoded claims.
    if (!parsed->b64()) return bad_token("a JWT can't use an unencoded (\"b64\":false) payload");
    return signed_jwt(std::move(*parsed));
}

auto signed_jwt::claims(const jwk& key) const -> expected<json> {
    return claims_of(jws_.verify(key));
}

auto signed_jwt::claims(const jwk_set& keys) const -> expected<json> {
    return claims_of(jws_.verify(keys));
}

auto signed_jwt::claims(opaque_verifier& verifier) const -> expected<json> {
    return claims_of(jws_.verify(verifier));
}

auto signed_jwt::unsafe_claims() const -> expected<json> {
    return parse_claims(jws_.unsafe_payload());
}

auto parse_encrypted(std::string_view token, const std::vector<key_algorithm>& key_algorithms,
                     const std::vector<content_encryption>& encryptions, const extension_set& understood)
    -> expected<encrypted_jwt> {
    if (auto r = check_key_algorithms(key_algorithms); !r) return jose::unexpected(r.error());
    auto parsed = jwe::parse_compact(token, key_algorithms, encryptions, understood);
    if (!parsed) return jose::unexpected(parsed.error());
    if (auto cty = parsed->recipients().front().joined.cty(); cty && is_jwt_content_type(*cty))
        return make_error(errc::invalid_header,
                          "this JWT is nested (\"cty\":\"JWT\"); use jwt::parse_signed_and_encrypted");
    return encrypted_jwt(std::move(*parsed));
}

auto encrypted_jwt::claims(const jwk& key, const jwe_decrypt_options& options) const -> expected<json> {
    return claims_of(jwe_.decrypt(key, options));
}

auto encrypted_jwt::claims(const jwk_set& keys, const jwe_decrypt_options& options) const -> expected<json> {
    return claims_of(jwe_.decrypt(keys, options));
}

auto encrypted_jwt::claims(opaque_key_decrypter& decrypter, const jwe_decrypt_options& options) const
    -> expected<json> {
    return claims_of(jwe_.decrypt(decrypter, options));
}

auto parse_signed_and_encrypted(std::string_view token, const std::vector<key_algorithm>& key_algorithms,
                                const std::vector<content_encryption>& encryptions,
                                const std::vector<signing_algorithm>& signature_algorithms,
                                const extension_set& understood) -> expected<nested_jwt> {
    // Checked here too, so a bad allowlist fails before any decryption.
    if (signature_algorithms.empty()) return bad_argument("no signature algorithms given for the nested JWS");
    auto parsed = jwe::parse_compact(token, key_algorithms, encryptions, understood);
    if (!parsed) return jose::unexpected(parsed.error());
    const auto cty = parsed->recipients().front().joined.cty();
    if (!cty || !is_jwt_content_type(*cty))
        return make_error(errc::invalid_header, "a nested JWT's JWE must have \"cty\":\"JWT\"");
    return nested_jwt(std::move(*parsed), signature_algorithms, understood);
}

auto nested_jwt::inner(expected<secure_bytes> plaintext) const -> expected<signed_jwt> {
    if (!plaintext) return jose::unexpected(plaintext.error());
    const std::string_view text(reinterpret_cast<const char*>(plaintext->data()), plaintext->size());
    return parse_signed(text, signature_algorithms_, understood_);
}

auto nested_jwt::decrypt(const jwk& key, const jwe_decrypt_options& options) const -> expected<signed_jwt> {
    return inner(jwe_.decrypt(key, options));
}

auto nested_jwt::decrypt(const jwk_set& keys, const jwe_decrypt_options& options) const -> expected<signed_jwt> {
    return inner(jwe_.decrypt(keys, options));
}

auto nested_jwt::decrypt(opaque_key_decrypter& decrypter, const jwe_decrypt_options& options) const
    -> expected<signed_jwt> {
    return inner(jwe_.decrypt(decrypter, options));
}

} // namespace jose::jwt
