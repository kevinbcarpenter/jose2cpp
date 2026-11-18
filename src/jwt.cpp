#include "jose/jwt.hpp"

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

} // namespace jose::jwt
