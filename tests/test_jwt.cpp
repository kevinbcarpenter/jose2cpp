#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include "jose/jose.hpp"

#include <openssl/err.h>

#include <limits>
#include <string>
#include <type_traits>
#include <vector>

using namespace jose;
using json = nlohmann::json;
using Catch::Matchers::ContainsSubstring;

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

auto as_json(std::span<const uint8_t> bytes) -> json {
    return json::parse(std::string(bytes.begin(), bytes.end()));
}

auto as_string(std::span<const uint8_t> bytes) -> std::string {
    return {bytes.begin(), bytes.end()};
}

// A private claims type, serialized through nlohmann's ADL hook.
struct session_claims {
    std::string role;
    int level;
};

void to_json(json& j, const session_claims& c) {
    j = json{{"role", c.role}, {"level", c.level}};
}

const json k_standard{{"iss", "https://auth.example.com"}, {"sub", "kevin"}, {"exp", 1900000000}};

} // namespace

TEST_CASE("signed JWT", "[jwt][builder]") {
    const auto key = must(jwk::generate_ec(ec_curve::P256));
    const auto token = must(jwt::signed_token({signing_algorithm::ES256, key})
                                .claims(k_standard)
                                .claims(session_claims{"admin", 3})
                                .serialize());

    auto parsed = must(jws::parse_compact(token, {signing_algorithm::ES256}));
    const auto& h = parsed.signatures().front().protected_header;
    CHECK(h.typ() == "JWT");
    CHECK(h.alg() == "ES256");

    const auto claims = as_json(must(parsed.verify(must(key.public_key()))));
    CHECK(claims == json{{"iss", "https://auth.example.com"},
                         {"sub", "kevin"},
                         {"exp", 1900000000},
                         {"role", "admin"},
                         {"level", 3}});

    SECTION("token() gives the JWS itself") {
        auto jws_token = must(jwt::signed_token({signing_algorithm::ES256, key}).claims(k_standard).token());
        CHECK(as_json(jws_token.unsafe_payload()) == k_standard);
    }
    SECTION("a caller-set typ is kept") {
        jws_signer signer{signing_algorithm::HS256, must(jwk::generate_oct(32))};
        REQUIRE(signer.protected_header.set("typ", "at+jwt"));
        auto t = must(jwt::signed_token(signer).claims(k_standard).token());
        CHECK(t.signatures().front().protected_header.typ() == "at+jwt");
    }
    SECTION("no claims is an empty object") {
        auto t = must(jwt::signed_token({signing_algorithm::ES256, key}).token());
        CHECK(as_string(t.unsafe_payload()) == "{}");
    }
}

TEST_CASE("encrypted JWT", "[jwt][builder]") {
    const auto key = must(jwk::generate_rsa(2048));
    const auto token = must(jwt::encrypted_token(content_encryption::A256GCM,
                                                 {key_algorithm::RSA_OAEP_256, must(key.public_key())})
                                .claims(k_standard)
                                .serialize());

    auto parsed = must(jwe::parse_compact(token, {key_algorithm::RSA_OAEP_256}, {content_encryption::A256GCM}));
    CHECK(parsed.protected_header().typ() == "JWT");
    CHECK_FALSE(parsed.protected_header().cty());
    CHECK(as_json(must(parsed.decrypt(key))) == k_standard);

    SECTION("a caller-set typ in any JWE header part is kept") {
        const auto kek = must(jwk::generate_oct(16));
        jwe_encrypt_options options;
        REQUIRE(options.protected_header.set("typ", "secevent+jwt"));
        auto t = must(jwt::encrypted_token(content_encryption::A128GCM, {key_algorithm::A128KW, kek}, options)
                          .claims(k_standard)
                          .token());
        CHECK(t.protected_header().typ() == "secevent+jwt");

        jwe_recipient recipient{key_algorithm::A128KW, kek};
        REQUIRE(recipient.parameters.set("typ", "logout+jwt"));
        t = must(jwt::encrypted_token(content_encryption::A128GCM, recipient).claims(k_standard).token());
        CHECK(t.protected_header().typ() == "logout+jwt");
    }
    SECTION("compression") {
        auto t = must(jwt::encrypted_token(content_encryption::A128GCM, {key_algorithm::A128KW,
                                                                         must(jwk::generate_oct(16))},
                                           {.compress = true})
                          .claims(k_standard)
                          .token());
        CHECK(t.protected_header().zip() == "DEF");
    }
}

TEST_CASE("nested (signed then encrypted) JWT", "[jwt][builder]") {
    const auto signing_key = must(jwk::generate_okp(okp_curve::Ed25519));
    const auto encryption_key = must(jwk::generate_ec(ec_curve::P384));
    const auto token = must(jwt::signed_and_encrypted({signing_algorithm::EdDSA, signing_key},
                                                      content_encryption::A256CBC_HS512,
                                                      {key_algorithm::ECDH_ES_A256KW,
                                                       must(encryption_key.public_key())})
                                .claims(k_standard)
                                .serialize());

    auto outer = must(jwe::parse_compact(token, {key_algorithm::ECDH_ES_A256KW},
                                         {content_encryption::A256CBC_HS512}));
    CHECK(outer.protected_header().cty() == "JWT");
    CHECK(outer.protected_header().typ() == "JWT");

    const auto inner_token = as_string(must(outer.decrypt(encryption_key)));
    auto inner = must(jws::parse_compact(inner_token, {signing_algorithm::EdDSA}));
    CHECK(inner.signatures().front().protected_header.typ() == "JWT");
    CHECK(as_json(must(inner.verify(must(signing_key.public_key())))) == k_standard);

    SECTION("a conflicting cty is refused") {
        jwe_encrypt_options options;
        REQUIRE(options.protected_header.set("cty", "json"));
        auto r = jwt::signed_and_encrypted({signing_algorithm::EdDSA, signing_key}, content_encryption::A256GCM,
                                           {key_algorithm::ECDH_ES, must(encryption_key.public_key())}, {}, options)
                     .claims(k_standard)
                     .serialize();
        CHECK(error_of(r) == errc::invalid_argument);
    }
    SECTION("a conflicting cty in the recipient's parameters is refused too") {
        jwe_recipient recipient{key_algorithm::ECDH_ES, must(encryption_key.public_key())};
        REQUIRE(recipient.parameters.set("cty", "json"));
        auto r = jwt::signed_and_encrypted({signing_algorithm::EdDSA, signing_key}, content_encryption::A256GCM,
                                           recipient)
                     .claims(k_standard)
                     .serialize();
        CHECK(error_of(r) == errc::invalid_argument);
    }
    SECTION("a caller-set typ on the inner JWS leaves the JWE's typ alone") {
        jws_signer signer{signing_algorithm::EdDSA, signing_key};
        REQUIRE(signer.protected_header.set("typ", "at+jwt"));
        auto t = must(jwt::signed_and_encrypted(signer, content_encryption::A256GCM,
                                                {key_algorithm::ECDH_ES, must(encryption_key.public_key())})
                          .claims(k_standard)
                          .token());
        CHECK(t.protected_header().typ() == "JWT");
        auto inner = must(jws::parse_compact(as_string(must(t.decrypt(encryption_key))), {signing_algorithm::EdDSA}));
        CHECK(inner.signatures().front().protected_header.typ() == "at+jwt");
    }
    SECTION("an explicit cty of JWT is fine") {
        jwe_encrypt_options options;
        REQUIRE(options.protected_header.set("cty", "JWT"));
        auto t = must(jwt::signed_and_encrypted({signing_algorithm::EdDSA, signing_key},
                                                content_encryption::A256GCM,
                                                {key_algorithm::ECDH_ES, must(encryption_key.public_key())}, {},
                                                options)
                          .claims(k_standard)
                          .token());
        CHECK(t.protected_header().cty() == "JWT");
    }
}

TEST_CASE("JWT claims misuse is reported once, at the end of the chain", "[jwt][builder][validation]") {
    const auto key = must(jwk::generate_oct(32));
    const jws_signer signer{signing_algorithm::HS256, key};

    SECTION("a claim name given twice") {
        auto r = jwt::signed_token(signer).claims(k_standard).claims({{"sub", "someone else"}}).serialize();
        CHECK(error_of(r) == errc::invalid_argument);
        CHECK_THAT(r.error().message, ContainsSubstring("\"sub\""));
    }
    SECTION("claims that aren't an object") {
        CHECK(error_of(jwt::signed_token(signer).claims(json::array({1, 2})).serialize()) == errc::invalid_argument);
        CHECK(error_of(jwt::signed_token(signer).claims(std::string("sub")).serialize()) == errc::invalid_argument);
    }
    SECTION("the first error wins") {
        auto r = jwt::signed_token(signer).claims(json(42)).claims(k_standard).claims(k_standard).serialize();
        CHECK_THAT(r.error().message, ContainsSubstring("JSON object"));
    }
    SECTION("a string that isn't UTF-8") {
        auto r = jwt::signed_token(signer).claims({{"name", std::string("\xff\xfe")}}).serialize();
        CHECK(error_of(r) == errc::serialization_error);
    }
    SECTION("numbers that aren't finite") {
        for (double bad : {std::numeric_limits<double>::infinity(), -std::numeric_limits<double>::infinity(),
                           std::numeric_limits<double>::quiet_NaN()}) {
            auto r = jwt::signed_token(signer).claims({{"exp", bad}}).serialize();
            CHECK(error_of(r) == errc::serialization_error);
            CHECK_THAT(r.error().message, ContainsSubstring("\"exp\""));
        }
        // Nested inside objects and arrays as well.
        auto r = jwt::signed_token(signer).claims({{"cnf", {{"w", json::array({1.0, std::nan("")})}}}}).serialize();
        CHECK(error_of(r) == errc::serialization_error);
        CHECK_THAT(r.error().message, ContainsSubstring("\"cnf\".w[1]"));
    }
    SECTION("values JSON can't represent") {
        CHECK(error_of(jwt::signed_token(signer).claims({{"x", json(json::value_t::discarded)}}).serialize()) ==
              errc::serialization_error);
        CHECK(error_of(jwt::signed_token(signer)
                           .claims({{"x", {{"y", json::parse("{", nullptr, false)}}}})
                           .serialize()) == errc::serialization_error);
        CHECK(error_of(jwt::signed_token(signer).claims({{"x", json::binary({1, 2, 3})}}).serialize()) ==
              errc::serialization_error);
    }
    SECTION("an option error is reported before a claims error") {
        auto r = jwt::signed_token(signer, {.b64 = false}).claims(json(42)).serialize();
        CHECK_THAT(r.error().message, ContainsSubstring("b64"));

        const auto ec = must(jwk::generate_ec(ec_curve::P256));
        jwe_encrypt_options options;
        REQUIRE(options.protected_header.set("cty", "json"));
        auto nested = jwt::signed_and_encrypted(signer, content_encryption::A256GCM,
                                                {key_algorithm::ECDH_ES, must(ec.public_key())}, {}, options)
                          .claims(json(42))
                          .serialize();
        CHECK_THAT(nested.error().message, ContainsSubstring("cty"));
    }
    SECTION("b64=false") {
        CHECK(error_of(jwt::signed_token(signer, {.b64 = false}).claims(k_standard).serialize()) ==
              errc::invalid_argument);
    }
    SECTION("errors from JWS/JWE pass through") {
        CHECK(error_of(jwt::signed_token({signing_algorithm::ES256, key}).claims(k_standard).serialize()) ==
              errc::algorithm_mismatch);
        jws_signer with_unprotected = signer;
        REQUIRE(with_unprotected.unprotected_header.set("x-note", "compact can't carry this"));
        CHECK(error_of(jwt::signed_token(with_unprotected).claims(k_standard).serialize()) ==
              errc::invalid_argument);
    }
    CHECK(ERR_peek_error() == 0);
}

// claims() on a temporary returns the builder by value, so a reference
// can't be bound to a builder that is about to be destroyed.
TEST_CASE("JWT builders chain safely", "[jwt][builder]") {
    const jws_signer signer{signing_algorithm::HS256, must(jwk::generate_oct(32))};
    STATIC_REQUIRE(std::is_same_v<decltype(jwt::signed_token(signer).claims(json::object())), jwt::signed_builder>);
    STATIC_REQUIRE(std::is_same_v<decltype(jwt::signed_token(signer).claims(session_claims{})),
                                  jwt::signed_builder>);
    auto builder = jwt::signed_token(signer);
    STATIC_REQUIRE(std::is_same_v<decltype(builder.claims(json::object())), jwt::signed_builder&>);

    // Kept by value and extended in steps, as a caller assembling claims would.
    builder.claims(k_standard);
    builder.claims(session_claims{"reader", 1});
    auto claims = as_json(must(builder.token()).unsafe_payload());
    CHECK(claims.size() == k_standard.size() + 2);
}
