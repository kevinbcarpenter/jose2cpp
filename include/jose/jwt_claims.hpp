#pragma once

// The registered JWT claims (RFC 7519 §4.1) and their value types, modelled
// on go-jose v4's jwt.Claims, jwt.NumericDate and jwt.Audience.
//
//   jose::jwt::registered_claims claims{
//       .issuer = "https://auth.example.com",
//       .subject = "kevin",
//       .audience = {"api", "web"},
//       .expiry = jose::jwt::numeric_date::now() + std::chrono::minutes(15),
//   };
//   auto token = jose::jwt::signed_token(signer).claims(claims).claims(private_claims).serialize();
//
//   auto verified = parsed->claims(key);                                  // nlohmann::json
//   auto standard = jose::jwt::decode<jose::jwt::registered_claims>(*verified);
//   if (!standard) return standard.error();                             // a malformed claim
//   auto ok = standard->validate({.issuer = "https://auth.example.com", .any_audience = {"api"}});
//
// Conversion to and from JSON goes through nlohmann's to_json / from_json,
// so these types also work as members of your own claims structs. A
// malformed value ("exp" as a string, an "aud" array holding a number, a
// date out of range) is an error from jwt::decode (errc::invalid_token);
// called directly, from_json throws a nlohmann::json::exception, as
// nlohmann conversions do.

#include "jose/error.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <compare>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace jose::jwt {

// RFC 7519 §2: seconds since 1970-01-01T00:00:00Z, ignoring leap seconds.
//
// Serialized as an integer. When parsing, a fractional value is truncated
// toward zero (as go-jose does) and a value of 2^62 seconds or more in
// either direction is refused, so adding a realistic duration (a leeway, a
// lifetime) to a parsed date can't overflow and turn a future "nbf" into a
// past one. Values you construct yourself aren't range-checked: keep them
// within ±2^62 seconds, as signed overflow in the arithmetic below is
// undefined and to_json would write a date that jose2cpp refuses to read.
class numeric_date {
public:
    static constexpr std::int64_t max_seconds = std::int64_t{1} << 62;

    constexpr numeric_date() = default; // the epoch
    constexpr explicit numeric_date(std::chrono::sys_seconds time) : time_(time) {}

    // Truncates to whole seconds (toward the past).
    static auto from_time(std::chrono::system_clock::time_point time) -> numeric_date {
        return numeric_date(std::chrono::floor<std::chrono::seconds>(time));
    }
    static constexpr auto from_seconds(std::int64_t seconds) -> numeric_date {
        return numeric_date(std::chrono::sys_seconds(std::chrono::seconds(seconds)));
    }
    static auto now() -> numeric_date { return from_time(std::chrono::system_clock::now()); }

    [[nodiscard]] constexpr auto time() const noexcept -> std::chrono::sys_seconds { return time_; }
    [[nodiscard]] constexpr auto seconds() const noexcept -> std::int64_t { return time_.time_since_epoch().count(); }

    constexpr auto operator+=(std::chrono::seconds d) -> numeric_date& {
        time_ += d;
        return *this;
    }
    constexpr auto operator-=(std::chrono::seconds d) -> numeric_date& {
        time_ -= d;
        return *this;
    }
    friend constexpr auto operator+(numeric_date n, std::chrono::seconds d) -> numeric_date { return n += d; }
    friend constexpr auto operator-(numeric_date n, std::chrono::seconds d) -> numeric_date { return n -= d; }

    friend constexpr auto operator<=>(const numeric_date&, const numeric_date&) = default;

private:
    std::chrono::sys_seconds time_{};
};

void to_json(nlohmann::json& j, const numeric_date& date);
void from_json(const nlohmann::json& j, numeric_date& date);

// RFC 7519 §4.1.3 "aud": one string or an array of strings. Parsing accepts
// either; serializing writes a single value as a string and several as an
// array, as go-jose does. Values are compared case-sensitively.
class audience {
public:
    audience() = default;
    audience(std::initializer_list<std::string> values) : values_(values) {}
    explicit audience(std::vector<std::string> values) : values_(std::move(values)) {}

    [[nodiscard]] auto values() const noexcept -> std::span<const std::string> { return values_; }
    [[nodiscard]] auto empty() const noexcept -> bool { return values_.empty(); }
    [[nodiscard]] auto size() const noexcept -> std::size_t { return values_.size(); }
    [[nodiscard]] auto contains(std::string_view value) const -> bool;

    friend auto operator==(const audience&, const audience&) -> bool = default;

private:
    std::vector<std::string> values_;
};

void to_json(nlohmann::json& j, const audience& aud);
void from_json(const nlohmann::json& j, audience& aud);

// What registered_claims::validate checks, like go-jose's jwt.Expected.
// Every member is optional; one left unset isn't checked. An empty string
// is an expectation like any other (go-jose reads "" as "don't check").
struct expected_claims {
    std::optional<std::string> issuer = std::nullopt;   // "iss" must equal this
    std::optional<std::string> subject = std::nullopt;  // "sub" must equal this
    jwt::audience any_audience = {};                    // "aud" must hold at least one of these
    std::optional<std::string> id = std::nullopt;       // "jti" must equal this
    // The time to check "nbf", "exp" and "iat" against; unset means now.
    std::optional<std::chrono::system_clock::time_point> time = std::nullopt;
};

// go-jose's DefaultLeeway. It lets a token through for a minute after it
// expires, which suits a server allowing for clock skew; a client asking
// "will the server still take this?" should pass zero or a negative leeway.
inline constexpr std::chrono::seconds default_leeway = std::chrono::minutes(1);

// RFC 7519 §4.1. A claim that is absent is std::nullopt (or an empty
// audience). Two differences from go-jose: an empty string is kept as
// present, and a registered claim set to null is malformed rather than
// absent (go-jose reads null as absent for every registered claim but
// "aud", so "exp": null there means "never expires"). Claims that aren't
// registered are ignored here: read them from the JSON, or decode them
// into your own struct.
struct registered_claims {
    std::optional<std::string> issuer = std::nullopt;       // "iss"
    std::optional<std::string> subject = std::nullopt;      // "sub"
    jwt::audience audience = {};                            // "aud"
    std::optional<numeric_date> expiry = std::nullopt;      // "exp"
    std::optional<numeric_date> not_before = std::nullopt;  // "nbf"
    std::optional<numeric_date> issued_at = std::nullopt;   // "iat"
    std::optional<std::string> id = std::nullopt;           // "jti"

    // Checks the claims against `want`, in go-jose's order (iss, sub, jti,
    // aud, nbf, exp, iat), and reports the first failure:
    //
    //   errc::missing_claim   an expected iss, sub, jti or aud is absent
    //   errc::invalid_claim   it's present but doesn't match
    //   errc::not_yet_valid   time + leeway is before "nbf", or before "iat"
    //                         (a token issued in the future)
    //   errc::expired         time - leeway is at or after "exp"
    //   errc::invalid_argument  |leeway| is 2^62 seconds or more
    //
    // Absent time claims aren't required: a token without "exp" never
    // expires, as in go-jose. Require one by checking for it yourself.
    // Nor is "aud" checked unless any_audience is set, as in go-jose, even
    // though RFC 7519 §4.1.3 says a recipient that doesn't find itself in
    // "aud" must reject the token. Enforcing that here would make "aud"
    // required as soon as a token carries one, so a caller who forgot
    // any_audience would see good tokens fail. Set any_audience whenever
    // tokens carry one.
    //
    // Two differences from go-jose: at exactly "exp" (plus leeway) the token
    // is expired, as RFC 7519 §4.1.4 says ("on or after"), where go-jose
    // still accepts it at that instant; and an empty-string expectation is
    // checked (see expected_claims), where go-jose reads "" as "don't check".
    [[nodiscard]] auto validate(const expected_claims& want, std::chrono::seconds leeway = default_leeway) const
        -> jose::expected<void>;

    friend auto operator==(const registered_claims&, const registered_claims&) -> bool = default;
};

// Writes only the claims that are present.
void to_json(nlohmann::json& j, const registered_claims& claims);
void from_json(const nlohmann::json& j, registered_claims& claims);

} // namespace jose::jwt
