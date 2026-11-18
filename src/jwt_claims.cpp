#include "jose/jwt_claims.hpp"

#include <algorithm>
#include <cmath>
#include <string>

namespace jose::jwt {

namespace {

using json = nlohmann::json;

// from_json reports malformed claims the way nlohmann conversions do, with a
// nlohmann::json::exception, so jwt::decode turns them into
// errc::invalid_token like any other type mismatch.
class claims_error : public json::exception {
public:
    explicit claims_error(const std::string& message)
        : json::exception(599, ("[jose2cpp.jwt] " + message).c_str()) {}
};

[[noreturn]] void fail(const std::string& message) {
    throw claims_error(message);
}

auto string_claim(const json& claims, const char* name) -> std::optional<std::string> {
    const auto it = claims.find(name);
    if (it == claims.end()) return std::nullopt;
    if (!it->is_string()) fail(std::string("JWT claim \"") + name + "\" must be a string");
    return it->get<std::string>();
}

auto date_claim(const json& claims, const char* name) -> std::optional<numeric_date> {
    const auto it = claims.find(name);
    if (it == claims.end()) return std::nullopt;
    try {
        return it->get<numeric_date>();
    } catch (const claims_error&) {
        fail(std::string("JWT claim \"") + name + "\" must be a NumericDate (seconds since the epoch, below 2^62)");
    }
}

} // namespace

// ===========================================================================
// numeric_date
// ===========================================================================

void to_json(json& j, const numeric_date& date) {
    j = date.seconds();
}

void from_json(const json& j, numeric_date& date) {
    // null is not a NumericDate. (go-jose reads null as "absent", which for
    // "exp" would mean a token that never expires.)
    constexpr auto max = numeric_date::max_seconds;
    if (j.is_number_unsigned()) {
        const auto v = j.get<std::uint64_t>();
        if (v >= static_cast<std::uint64_t>(max)) fail("NumericDate out of range");
        date = numeric_date::from_seconds(static_cast<std::int64_t>(v));
    } else if (j.is_number_integer()) {
        const auto v = j.get<std::int64_t>();
        if (v >= max || v <= -max) fail("NumericDate out of range");
        date = numeric_date::from_seconds(v);
    } else if (j.is_number_float()) {
        // RFC 7519 §2 allows fractions; truncate toward zero, as go-jose does.
        const auto v = j.get<double>();
        if (!std::isfinite(v) || v >= static_cast<double>(max) || v <= -static_cast<double>(max))
            fail("NumericDate out of range");
        date = numeric_date::from_seconds(static_cast<std::int64_t>(v));
    } else {
        fail("NumericDate must be a number");
    }
}

// ===========================================================================
// audience
// ===========================================================================

auto audience::contains(std::string_view value) const -> bool {
    return std::ranges::find(values_, value) != values_.end();
}

void to_json(json& j, const audience& aud) {
    if (aud.size() == 1)
        j = aud.values().front();
    else
        j = std::vector<std::string>(aud.values().begin(), aud.values().end());
}

void from_json(const json& j, audience& aud) {
    if (j.is_string()) {
        aud = audience{j.get<std::string>()};
        return;
    }
    if (!j.is_array()) fail("an audience must be a string or an array of strings");
    std::vector<std::string> values;
    values.reserve(j.size());
    for (const auto& v : j) {
        if (!v.is_string()) fail("an audience must be a string or an array of strings");
        values.push_back(v.get<std::string>());
    }
    aud = audience(std::move(values));
}

// ===========================================================================
// registered_claims
// ===========================================================================

void to_json(json& j, const registered_claims& c) {
    j = json::object();
    if (c.issuer) j["iss"] = *c.issuer;
    if (c.subject) j["sub"] = *c.subject;
    if (!c.audience.empty()) j["aud"] = c.audience;
    if (c.expiry) j["exp"] = *c.expiry;
    if (c.not_before) j["nbf"] = *c.not_before;
    if (c.issued_at) j["iat"] = *c.issued_at;
    if (c.id) j["jti"] = *c.id;
}

void from_json(const json& j, registered_claims& c) {
    if (!j.is_object()) fail("JWT claims must be a JSON object");
    registered_claims out;
    out.issuer = string_claim(j, "iss");
    out.subject = string_claim(j, "sub");
    if (const auto it = j.find("aud"); it != j.end()) {
        try {
            out.audience = it->get<audience>();
        } catch (const claims_error&) {
            fail("JWT claim \"aud\" must be a string or an array of strings");
        }
    }
    out.expiry = date_claim(j, "exp");
    out.not_before = date_claim(j, "nbf");
    out.issued_at = date_claim(j, "iat");
    out.id = string_claim(j, "jti");
    c = std::move(out);
}

} // namespace jose::jwt
