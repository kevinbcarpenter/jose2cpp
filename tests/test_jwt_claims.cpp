#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include "jose/jose.hpp"

#include <chrono>
#include <cmath>
#include <cstdint>
#include <string>
#include <vector>

using namespace jose;
using json = nlohmann::json;
using Catch::Matchers::ContainsSubstring;
using namespace std::chrono_literals;

namespace {

template <typename T>
auto must(expected<T> v) -> T {
    INFO((v ? std::string("ok") : v.error().message));
    REQUIRE(v.has_value());
    return std::move(*v);
}

template <typename T>
auto error_of(const expected<T>& v) -> errc {
    REQUIRE_FALSE(v.has_value());
    return v.error().code;
}

// A caller's own claims type with the jose2cpp value types as members.
struct session {
    jwt::numeric_date started;
    jwt::audience services;
};

void to_json(json& j, const session& s) {
    j = json{{"started", s.started}, {"services", s.services}};
}

void from_json(const json& j, session& s) {
    j.at("started").get_to(s.started);
    j.at("services").get_to(s.services);
}

} // namespace

TEST_CASE("numeric_date", "[jwt][claims]") {
    using jwt::numeric_date;
    constexpr auto max = numeric_date::max_seconds;

    STATIC_REQUIRE(numeric_date::from_seconds(1900000000).seconds() == 1900000000);
    STATIC_REQUIRE(numeric_date{} == numeric_date::from_seconds(0));
    STATIC_REQUIRE(numeric_date::from_seconds(10) + 5s == numeric_date::from_seconds(15));
    STATIC_REQUIRE(numeric_date::from_seconds(10) < numeric_date::from_seconds(11));

    SECTION("from a time_point, truncating toward the past") {
        const auto epoch = std::chrono::system_clock::time_point{};
        CHECK(numeric_date::from_time(epoch + 1900ms).seconds() == 1);
        CHECK(numeric_date::from_time(epoch - 500ms).seconds() == -1);
        const auto now = numeric_date::now();
        CHECK(now.seconds() > 1700000000);
        CHECK(now.time() <= std::chrono::system_clock::now());
    }
    SECTION("to JSON as an integer") {
        CHECK(json(numeric_date::from_seconds(1900000000)) == json(1900000000));
        CHECK(json(numeric_date::from_seconds(1900000000)).is_number_integer());
    }
    SECTION("from JSON") {
        CHECK(json(1900000000).get<numeric_date>().seconds() == 1900000000);
        CHECK(json(-86400).get<numeric_date>().seconds() == -86400);
        CHECK(json::parse("18446744073709551615").is_number_unsigned());
        // Fractions are allowed and truncate toward zero.
        CHECK(json(1900000000.9).get<numeric_date>().seconds() == 1900000000);
        CHECK(json(-1.9).get<numeric_date>().seconds() == -1);
        // Just inside the bound, through each of nlohmann's number types.
        CHECK(json(max - 1).get<numeric_date>().seconds() == max - 1);
        CHECK(json(-max + 1).get<numeric_date>().seconds() == -max + 1);
        const auto unsigned_below = json::parse("4611686018427387903");
        REQUIRE(unsigned_below.is_number_unsigned());
        CHECK(unsigned_below.get<numeric_date>().seconds() == max - 1);
        const double largest_double_below = std::nextafter(static_cast<double>(max), 0.0);
        CHECK(json(largest_double_below).get<numeric_date>().seconds() ==
              static_cast<std::int64_t>(largest_double_below));
        CHECK(json(-largest_double_below).get<numeric_date>().seconds() ==
              -static_cast<std::int64_t>(largest_double_below));
    }
    SECTION("refused") {
        for (const json& bad : {json(max), json(-max), json(static_cast<double>(max)), json(1e300),
                                json::parse("18446744073709551615"), json("1900000000"), json(nullptr),
                                json(true), json::array({1}), json::object()}) {
            INFO(bad.dump());
            CHECK_THROWS_AS(bad.get<numeric_date>(), json::exception);
        }
    }
}

TEST_CASE("audience", "[jwt][claims]") {
    using jwt::audience;

    SECTION("one string or an array of strings") {
        auto single = json("api").get<audience>();
        CHECK(single.size() == 1);
        CHECK(single.contains("api"));
        auto many = json::array({"api", "web"}).get<audience>();
        CHECK(many == audience{"api", "web"});
        CHECK(json::array().get<audience>().empty());
    }
    SECTION("a single value is written as a string, several as an array") {
        CHECK(json(audience{"api"}) == json("api"));
        CHECK(json(audience{"api", "web"}) == json::array({"api", "web"}));
    }
    SECTION("contains is exact and case-sensitive") {
        const audience aud{"https://api.example.com"};
        CHECK(aud.contains("https://api.example.com"));
        CHECK_FALSE(aud.contains("https://API.example.com"));
        CHECK_FALSE(aud.contains("https://api.example.com/"));
        CHECK_FALSE(audience{}.contains(""));
    }
    SECTION("refused") {
        for (const json& bad : {json(42), json(nullptr), json::object(), json::array({"api", 1}),
                                json::array({json::array({"api"})})}) {
            INFO(bad.dump());
            CHECK_THROWS_AS(bad.get<audience>(), json::exception);
        }
    }
}

TEST_CASE("registered_claims", "[jwt][claims]") {
    const jwt::registered_claims full{
        .issuer = "https://auth.example.com",
        .subject = "kevin",
        .audience = {"api", "web"},
        .expiry = jwt::numeric_date::from_seconds(1900000000),
        .not_before = jwt::numeric_date::from_seconds(1700000000),
        .issued_at = jwt::numeric_date::from_seconds(1700000000),
        .id = "token-1",
    };

    SECTION("round trip") {
        const json j = full;
        CHECK(j == json{{"iss", "https://auth.example.com"},
                        {"sub", "kevin"},
                        {"aud", json::array({"api", "web"})},
                        {"exp", 1900000000},
                        {"nbf", 1700000000},
                        {"iat", 1700000000},
                        {"jti", "token-1"}});
        CHECK(must(jwt::decode<jwt::registered_claims>(j)) == full);
    }
    SECTION("absent claims are omitted and read back as absent") {
        const jwt::registered_claims sparse{.subject = "kevin"};
        CHECK(json(sparse) == json{{"sub", "kevin"}});
        const auto back = must(jwt::decode<jwt::registered_claims>(json::object()));
        CHECK_FALSE(back.issuer);
        CHECK(back.audience.empty());
        CHECK_FALSE(back.expiry);
    }
    SECTION("an empty string is present, not absent") {
        CHECK(json(jwt::registered_claims{.issuer = ""}) == json{{"iss", ""}});
        CHECK(must(jwt::decode<jwt::registered_claims>(json{{"iss", ""}})).issuer == "");
    }
    SECTION("private claims are ignored") {
        auto c = must(jwt::decode<jwt::registered_claims>(json{{"sub", "kevin"}, {"role", "admin"}}));
        CHECK(c == jwt::registered_claims{.subject = "kevin"});
    }
    SECTION("malformed registered claims are invalid_token from decode") {
        const std::vector<std::pair<json, std::string>> bad{
            {{{"exp", "1900000000"}}, "\"exp\""},
            {{{"exp", nullptr}}, "\"exp\""},
            {{{"nbf", 1e300}}, "\"nbf\""},
            {{{"iat", true}}, "\"iat\""},
            {{{"iss", 42}}, "\"iss\""},
            {{{"sub", nullptr}}, "\"sub\""},
            {{{"jti", json::array()}}, "\"jti\""},
            {{{"aud", 7}}, "\"aud\""},
            {{{"aud", json::array({"api", 7})}}, "\"aud\""},
        };
        for (const auto& [claims, name] : bad) {
            INFO(claims.dump());
            auto r = jwt::decode<jwt::registered_claims>(claims);
            CHECK(error_of(r) == errc::invalid_token);
            CHECK_THAT(r.error().message, ContainsSubstring(name));
        }
        CHECK(error_of(jwt::decode<jwt::registered_claims>(json::array())) == errc::invalid_token);
    }
}

TEST_CASE("registered claims through the builder and parser", "[jwt][claims]") {
    const auto key = must(jwk::generate_ec(ec_curve::P256));
    const jwt::registered_claims standard{
        .issuer = "https://auth.example.com",
        .subject = "kevin",
        .audience = {"api"},
        .expiry = jwt::numeric_date::from_seconds(1900000000),
    };
    const session extra{jwt::numeric_date::from_seconds(1700000000), {"billing", "search"}};

    const auto token = must(jwt::signed_token({signing_algorithm::ES256, key}).claims(standard).claims(extra).serialize());
    const auto verified = must(must(jwt::parse_signed(token, {signing_algorithm::ES256})).claims(must(key.public_key())));

    CHECK(verified.at("aud") == json("api")); // a single audience is a string on the wire
    CHECK(must(jwt::decode<jwt::registered_claims>(verified)) == standard);
    const auto back = must(jwt::decode<session>(verified));
    CHECK(back.started == extra.started);
    CHECK(back.services == extra.services);

    SECTION("an audience under another name isn't reported as \"aud\"") {
        auto r = jwt::decode<session>(json{{"started", 0}, {"services", 7}});
        CHECK(error_of(r) == errc::invalid_token);
        CHECK_THAT(r.error().message, ContainsSubstring("audience"));
        CHECK_THAT(r.error().message, !ContainsSubstring("\"aud\""));
    }

    SECTION("a private claim can't shadow a registered one") {
        auto r = jwt::signed_token({signing_algorithm::ES256, key}).claims(standard).claims({{"exp", 0}}).serialize();
        CHECK(error_of(r) == errc::invalid_argument);
        CHECK_THAT(r.error().message, ContainsSubstring("\"exp\" is given more than once"));
    }
}
