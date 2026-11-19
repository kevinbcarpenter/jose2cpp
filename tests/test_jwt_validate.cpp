#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include "jose/jose.hpp"

#include <chrono>
#include <string>

using namespace jose;
using json = nlohmann::json;
using Catch::Matchers::ContainsSubstring;
using namespace std::chrono_literals;
using jwt::numeric_date;

namespace {

auto at(std::int64_t seconds) -> std::chrono::system_clock::time_point {
    return std::chrono::system_clock::time_point(std::chrono::seconds(seconds));
}

auto error_of(const expected<void>& v) -> errc {
    REQUIRE_FALSE(v.has_value());
    return v.error().code;
}

const jwt::registered_claims claims{
    .issuer = "https://auth.example.com",
    .subject = "kevin",
    .audience = {"api", "web"},
    .expiry = numeric_date::from_seconds(2000),
    .not_before = numeric_date::from_seconds(1000),
    .issued_at = numeric_date::from_seconds(1000),
    .id = "token-1",
};

} // namespace

TEST_CASE("validate: string claims", "[jwt][validate]") {
    const auto t = at(1500);
    CHECK(claims.validate({.time = t}));
    CHECK(claims.validate({.issuer = "https://auth.example.com", .subject = "kevin", .id = "token-1", .time = t}));

    SECTION("a mismatch is invalid_claim, naming the claim") {
        for (const auto& [want, name] : {std::pair{jwt::expected_claims{.issuer = "https://evil.example"}, "\"iss\""},
                                         std::pair{jwt::expected_claims{.subject = "Kevin"}, "\"sub\""},
                                         std::pair{jwt::expected_claims{.id = "token-2"}, "\"jti\""}}) {
            auto w = want;
            w.time = t;
            auto r = claims.validate(w);
            CHECK(error_of(r) == errc::invalid_claim);
            CHECK_THAT(r.error().message, ContainsSubstring(name));
        }
    }
    SECTION("an expected claim that's absent is missing_claim") {
        const jwt::registered_claims bare{};
        CHECK(error_of(bare.validate({.issuer = "x", .time = t})) == errc::missing_claim);
        CHECK(error_of(bare.validate({.subject = "x", .time = t})) == errc::missing_claim);
        CHECK(error_of(bare.validate({.id = "x", .time = t})) == errc::missing_claim);
    }
    SECTION("an empty expectation is still checked") {
        CHECK(error_of(claims.validate({.issuer = "", .time = t})) == errc::invalid_claim);
        CHECK(jwt::registered_claims{.issuer = ""}.validate({.issuer = "", .time = t}));
        CHECK(error_of(jwt::registered_claims{}.validate({.issuer = "", .time = t})) == errc::missing_claim);
    }
    SECTION("checked in go-jose's order: iss, sub, jti, aud, then nbf, exp, iat") {
        const auto fails_on = [](const expected<void>& r, const char* name) {
            REQUIRE_FALSE(r.has_value());
            CHECK_THAT(r.error().message, ContainsSubstring(name));
        };
        fails_on(claims.validate({.issuer = "x", .subject = "x", .any_audience = {"x"}, .id = "x", .time = at(9999)}),
                 "\"iss\"");
        fails_on(claims.validate({.subject = "x", .any_audience = {"x"}, .id = "x", .time = at(9999)}), "\"sub\"");
        fails_on(claims.validate({.any_audience = {"x"}, .id = "x", .time = at(9999)}), "\"jti\"");
        fails_on(claims.validate({.any_audience = {"x"}, .time = at(9999)}), "\"aud\"");
        CHECK(error_of(claims.validate({.time = at(9999)})) == errc::expired);
        // nbf and iat both fail here; nbf is reported.
        fails_on(claims.validate({.time = at(999)}, 0s), "\"nbf\"");
        // exp has passed and iat is in the future; exp is reported.
        const jwt::registered_claims odd{.expiry = numeric_date::from_seconds(2000),
                                         .issued_at = numeric_date::from_seconds(3000)};
        auto r = odd.validate({.time = at(2500)}, 0s);
        CHECK(error_of(r) == errc::expired);
        fails_on(r, "\"exp\"");
    }
}

TEST_CASE("validate: audience", "[jwt][validate]") {
    const auto t = at(1500);
    CHECK(claims.validate({.any_audience = {"api"}, .time = t}));
    CHECK(claims.validate({.any_audience = {"other", "web"}, .time = t}));
    CHECK(error_of(claims.validate({.any_audience = {"API"}, .time = t})) == errc::invalid_claim);
    CHECK(error_of(claims.validate({.any_audience = {"other"}, .time = t})) == errc::invalid_claim);
    CHECK(error_of(jwt::registered_claims{}.validate({.any_audience = {"api"}, .time = t})) == errc::missing_claim);
    // Not checked unless asked for, as in go-jose.
    CHECK(claims.validate({.time = t}));
}

TEST_CASE("validate: time claims with leeway", "[jwt][validate]") {
    SECTION("no leeway: valid from nbf up to, not including, exp") {
        auto early = claims.validate({.time = at(999)}, 0s);
        CHECK(error_of(early) == errc::not_yet_valid);
        CHECK_THAT(early.error().message, ContainsSubstring("\"nbf\""));
        CHECK(claims.validate({.time = at(1000)}, 0s));
        CHECK(claims.validate({.time = at(1999)}, 0s));
        CHECK(error_of(claims.validate({.time = at(2000)}, 0s)) == errc::expired);
    }
    SECTION("sub-second times compare exactly") {
        constexpr auto tick = std::chrono::system_clock::duration{1}; // the clock's resolution
        CHECK(error_of(claims.validate({.time = at(1000) - tick}, 0s)) == errc::not_yet_valid);
        CHECK(claims.validate({.time = at(2000) - tick}, 0s));
        CHECK(error_of(claims.validate({.time = at(2000) + tick}, 0s)) == errc::expired);
        // Before the epoch, flooring goes toward the past, not toward zero.
        const jwt::registered_claims epoch{.not_before = numeric_date::from_seconds(0)};
        CHECK(error_of(epoch.validate({.time = at(0) - tick}, 0s)) == errc::not_yet_valid);
        CHECK(epoch.validate({.time = at(0)}, 0s));
    }
    SECTION("the default leeway is a minute either side") {
        STATIC_REQUIRE(jwt::default_leeway == 60s);
        CHECK(error_of(claims.validate({.time = at(939)})) == errc::not_yet_valid);
        CHECK(claims.validate({.time = at(940)}));
        CHECK(claims.validate({.time = at(2059)}));
        CHECK(error_of(claims.validate({.time = at(2060)})) == errc::expired);
    }
    SECTION("a negative leeway narrows the window") {
        CHECK(error_of(claims.validate({.time = at(1009)}, -10s)) == errc::not_yet_valid);
        CHECK(claims.validate({.time = at(1010)}, -10s));
        CHECK(claims.validate({.time = at(1989)}, -10s));
        CHECK(error_of(claims.validate({.time = at(1990)}, -10s)) == errc::expired);
    }
    SECTION("iat in the future is not_yet_valid") {
        const jwt::registered_claims future{.issued_at = numeric_date::from_seconds(1000)};
        CHECK(future.validate({.time = at(1000)}, 0s));
        auto r = future.validate({.time = at(999)}, 0s);
        CHECK(error_of(r) == errc::not_yet_valid);
        CHECK_THAT(r.error().message, ContainsSubstring("\"iat\""));
        CHECK(future.validate({.time = at(940)}));
    }
    SECTION("absent time claims aren't required") {
        CHECK(jwt::registered_claims{}.validate({.time = at(-4000000000)}, 0s));
        CHECK(jwt::registered_claims{}.validate({.time = at(4000000000)}, 0s));
    }
    SECTION("without a time, now is used") {
        const auto now = numeric_date::now();
        CHECK(jwt::registered_claims{.expiry = now + 3600s, .not_before = now - 3600s}.validate({}));
        CHECK(error_of(jwt::registered_claims{.expiry = now - 3600s}.validate({})) == errc::expired);
        CHECK(error_of(jwt::registered_claims{.not_before = now + 3600s}.validate({})) == errc::not_yet_valid);
    }
    SECTION("extreme dates and leeways don't overflow") {
        constexpr auto max = numeric_date::max_seconds;
        const auto far = std::chrono::seconds(max - 1);
        const jwt::registered_claims edges{.expiry = numeric_date::from_seconds(max - 1),
                                           .not_before = numeric_date::from_seconds(-max + 1)};
        CHECK(edges.validate({.time = at(0)}, far));
        CHECK(edges.validate({.time = at(0)}, -std::chrono::seconds(1000)));
        CHECK(error_of(jwt::registered_claims{.expiry = numeric_date::from_seconds(0)}.validate({.time = at(0)}, -far)) ==
              errc::expired);
        // Dates parsed from JSON stay in range, so these are the edge.
        const auto parsed = jwt::decode<jwt::registered_claims>(json{{"exp", max - 1}, {"nbf", -max + 1}});
        REQUIRE(parsed);
        CHECK(*parsed == edges);
        for (const auto bad : {std::chrono::seconds(max), -std::chrono::seconds(max), std::chrono::seconds::max(),
                               std::chrono::seconds::min()}) {
            CHECK(error_of(edges.validate({.time = at(0)}, bad)) == errc::invalid_argument);
        }
    }
}

TEST_CASE("validate: a parsed token end to end", "[jwt][validate]") {
    auto key = jwk::generate_ec(ec_curve::P256);
    REQUIRE(key);
    const auto now = numeric_date::now();
    const jwt::registered_claims issued{
        .issuer = "https://auth.example.com",
        .audience = {"api"},
        .expiry = now + 15min,
        .issued_at = now,
    };
    auto token = jwt::signed_token({signing_algorithm::ES256, *key}).claims(issued).serialize();
    REQUIRE(token);

    auto parsed = jwt::parse_signed(*token, {signing_algorithm::ES256});
    REQUIRE(parsed);
    auto verified = parsed->claims(*key->public_key());
    REQUIRE(verified);
    auto standard = jwt::decode<jwt::registered_claims>(*verified);
    REQUIRE(standard);
    CHECK(standard->validate({.issuer = "https://auth.example.com", .any_audience = {"api"}}));
    CHECK(error_of(standard->validate({.any_audience = {"billing"}})) == errc::invalid_claim);
    CHECK(error_of(standard->validate({.time = (now + 16min).time()})) == errc::expired);
    CHECK(standard->validate({.time = (now + 15min).time()}));       // inside the default leeway
    CHECK(error_of(standard->validate({.time = (now + 15min).time()}, 0s)) == errc::expired);
}
