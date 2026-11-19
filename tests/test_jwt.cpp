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

auto with_kid(jwk key, std::string kid) -> jwk {
    key.set_key_id(std::move(kid));
    return key;
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
    const auto key = must(jwk::generate_oct(32));
    const auto token = must(jwt::encrypted_token(content_encryption::A256GCM, {key_algorithm::A256KW, key})
                                .claims(k_standard)
                                .serialize());

    auto parsed = must(jwe::parse_compact(token, {key_algorithm::A256KW}, {content_encryption::A256GCM}));
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
    SECTION("only symmetric key wrapping: anyone could forge an unsigned token sent to a public key") {
        const auto rsa = must(jwk::generate_rsa(2048));
        const auto ec = must(jwk::generate_ec(ec_curve::P256));
        const auto password = must(jwk::from_oct(std::vector<uint8_t>{'h', 'u', 'n', 't', 'e', 'r', '2', '!'}));
        const std::vector<jwe_recipient> refused{
            {key_algorithm::RSA_OAEP, must(rsa.public_key())},
            {key_algorithm::RSA_OAEP_256, must(rsa.public_key())},
            {key_algorithm::ECDH_ES, must(ec.public_key())},
            {key_algorithm::ECDH_ES_A128KW, must(ec.public_key())},
            {key_algorithm::ECDH_ES_A256KW, must(ec.public_key())},
            {key_algorithm::PBES2_HS256_A128KW, password},
            {key_algorithm::PBES2_HS512_A256KW, password},
        };
        for (const auto& r : refused) {
            INFO(to_string(r.alg));
            auto built = jwt::encrypted_token(content_encryption::A128GCM, r).claims(k_standard).serialize();
            CHECK(error_of(built) == errc::invalid_argument);
            CHECK_THAT(built.error().message, ContainsSubstring("nested"));
        }
        auto legacy = jwt::encrypted_token(content_encryption::A128GCM, {key_algorithm::RSA1_5, must(rsa.public_key())},
                                           {.legacy = {.allow_rsa1_5 = true}})
                          .claims(k_standard)
                          .serialize();
        CHECK(error_of(legacy) == errc::invalid_argument);
        // dir and AES-GCM key wrap are fine.
        CHECK(jwt::encrypted_token(content_encryption::A128GCM, {key_algorithm::dir, must(jwk::generate_oct(16))})
                  .claims(k_standard)
                  .serialize());
        CHECK(jwt::encrypted_token(content_encryption::A128GCM, {key_algorithm::A192GCMKW, must(jwk::generate_oct(24))})
                  .claims(k_standard)
                  .serialize());
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

// ===========================================================================
// Parsing
// ===========================================================================

namespace {

struct typed_claims {
    std::string iss;
    std::string sub;
};

void from_json(const json& j, typed_claims& c) {
    j.at("iss").get_to(c.iss);
    j.at("sub").get_to(c.sub);
}

// A compact JWS over an arbitrary payload, to test what the parser does
// with payloads the JWT builder would never produce.
auto raw_jws(std::string_view payload, const jwk& key, jws_sign_options options = {}) -> std::string {
    return must(must(jws::sign(payload, {signing_algorithm::HS256, key}, options)).compact());
}

} // namespace

TEST_CASE("parse_signed", "[jwt][parse]") {
    const auto key = with_kid(must(jwk::generate_ec(ec_curve::P256)), "signing-1");
    const auto pub = must(key.public_key());
    const auto token = must(jwt::signed_token({signing_algorithm::ES256, key}).claims(k_standard).serialize());

    auto parsed = must(jwt::parse_signed(token, {signing_algorithm::ES256}));
    CHECK(parsed.header().typ() == "JWT");
    CHECK(parsed.header().kid() == "signing-1");
    CHECK(must(parsed.claims(pub)) == k_standard);
    CHECK(must(parsed.unsafe_claims()) == k_standard);

    auto set = must(jwk_set::from_json(json{{"keys", json::array({must(pub.to_json())})}}));
    CHECK(must(parsed.claims(set)) == k_standard);

    auto typed = must(jwt::decode<typed_claims>(must(parsed.claims(pub))));
    CHECK(typed.iss == "https://auth.example.com");
    CHECK(typed.sub == "kevin");

    SECTION("the wrong key") {
        CHECK(error_of(parsed.claims(must(must(jwk::generate_ec(ec_curve::P256)).public_key()))) ==
              errc::invalid_signature);
    }
    SECTION("an algorithm outside the allowlist") {
        CHECK(error_of(jwt::parse_signed(token, {signing_algorithm::ES384})) == errc::algorithm_mismatch);
    }
    SECTION("a tampered signature") {
        auto tampered = token;
        auto& c = tampered[tampered.size() - 5]; // inside the signature, clear of its padding bits
        c = c == 'A' ? 'B' : 'A';
        auto t = must(jwt::parse_signed(tampered, {signing_algorithm::ES256}));
        CHECK(error_of(t.claims(pub)) == errc::invalid_signature);
        // unsafe_claims() still reads them: that is what "unsafe" means.
        CHECK(must(t.unsafe_claims()) == k_standard);
    }
    SECTION("a JWE isn't a signed JWT") {
        const auto kek = must(jwk::generate_oct(16));
        auto jwe_token = must(jwt::encrypted_token(content_encryption::A128GCM, {key_algorithm::A128KW, kek})
                                  .claims(k_standard)
                                  .serialize());
        CHECK(error_of(jwt::parse_signed(jwe_token, {signing_algorithm::ES256})) == errc::invalid_token);
    }
    SECTION("a type mismatch in decode") {
        auto mismatch = jwt::decode<typed_claims>(json{{"iss", 42}, {"sub", "x"}});
        CHECK(error_of(mismatch) == errc::invalid_token);
    }
}

TEST_CASE("signed JWT payloads must be a strict JSON object", "[jwt][parse][validation]") {
    const auto key = must(jwk::generate_oct(32));
    const std::vector algs{signing_algorithm::HS256};
    auto claims_of = [&](std::string_view payload) {
        return must(jwt::parse_signed(raw_jws(payload, key), algs)).claims(key);
    };

    CHECK(error_of(claims_of("[1,2]")) == errc::invalid_token);
    CHECK(error_of(claims_of("\"sub\"")) == errc::invalid_token);
    CHECK(error_of(claims_of("not json")) == errc::serialization_error);
    CHECK(error_of(claims_of(R"({"sub":"a","sub":"b"})")) == errc::serialization_error);
    CHECK(error_of(must(jwt::parse_signed(raw_jws("[]", key), algs)).unsafe_claims()) == errc::invalid_token);

    // RFC 7797 unencoded payloads aren't JWTs.
    CHECK(error_of(jwt::parse_signed(raw_jws("{}", key, {.b64 = false}), algs)) == errc::invalid_token);
    CHECK(ERR_peek_error() == 0);
}

TEST_CASE("parse_encrypted", "[jwt][parse]") {
    const auto kek = with_kid(must(jwk::generate_oct(32)), "kek-1");
    const auto token = must(jwt::encrypted_token(content_encryption::A256GCM, {key_algorithm::A256KW, kek})
                                .claims(k_standard)
                                .serialize());

    auto parsed = must(jwt::parse_encrypted(token, {key_algorithm::A256KW}, {content_encryption::A256GCM}));
    CHECK(parsed.header().typ() == "JWT");
    CHECK(must(parsed.claims(kek)) == k_standard);
    auto set = must(jwk_set::from_json(json{{"keys", json::array({must(kek.to_json())})}}));
    CHECK(must(parsed.claims(set)) == k_standard);

    SECTION("the wrong key") {
        CHECK(error_of(parsed.claims(must(jwk::generate_oct(32)))) == errc::decryption_failed);
    }
    SECTION("forgeable key algorithms can't even be listed") {
        for (auto alg : {key_algorithm::RSA1_5, key_algorithm::RSA_OAEP, key_algorithm::RSA_OAEP_256,
                         key_algorithm::ECDH_ES, key_algorithm::ECDH_ES_A192KW, key_algorithm::PBES2_HS384_A192KW}) {
            INFO(to_string(alg));
            CHECK(error_of(jwt::parse_encrypted(token, {key_algorithm::A256KW, alg}, {content_encryption::A256GCM})) ==
                  errc::invalid_argument);
        }
    }
    SECTION("a nested JWT is pointed at parse_signed_and_encrypted") {
        auto nested = must(jwt::signed_and_encrypted({signing_algorithm::HS256, must(jwk::generate_oct(32))},
                                                     content_encryption::A256GCM, {key_algorithm::A256KW, kek})
                               .claims(k_standard)
                               .serialize());
        auto r = jwt::parse_encrypted(nested, {key_algorithm::A256KW}, {content_encryption::A256GCM});
        CHECK(error_of(r) == errc::invalid_header);
        CHECK_THAT(r.error().message, ContainsSubstring("parse_signed_and_encrypted"));

        // Media types compare case-insensitively, so "jwt" is nested too.
        const auto inner = must(jwt::signed_token({signing_algorithm::HS256, must(jwk::generate_oct(32))})
                                    .claims(k_standard)
                                    .serialize());
        jwe_encrypt_options lower;
        REQUIRE(lower.protected_header.set("cty", "jwt"));
        auto lowercase = must(must(jwe::encrypt(inner, content_encryption::A256GCM, {key_algorithm::A256KW, kek}, lower))
                                  .compact());
        CHECK(error_of(jwt::parse_encrypted(lowercase, {key_algorithm::A256KW}, {content_encryption::A256GCM})) ==
              errc::invalid_header);
    }
}

TEST_CASE("parse_signed_and_encrypted", "[jwt][parse]") {
    const auto signing_key = must(jwk::generate_ec(ec_curve::P384));
    const auto signing_pub = must(signing_key.public_key());

    SECTION("RSA-OAEP, ECDH-ES and PBES2 are fine for nested tokens") {
        const auto rsa = must(jwk::generate_rsa(2048));
        const auto ec = must(jwk::generate_ec(ec_curve::P256));
        const auto password = must(jwk::from_oct(std::vector<uint8_t>{'c', 'o', 'r', 'r', 'e', 'c', 't', '!'}));
        const std::vector<std::pair<jwe_recipient, jwk>> cases{
            {{key_algorithm::RSA_OAEP_256, must(rsa.public_key())}, rsa},
            {{key_algorithm::ECDH_ES_A256KW, must(ec.public_key())}, ec},
            {{key_algorithm::ECDH_ES, must(ec.public_key())}, ec},
            {{key_algorithm::PBES2_HS256_A128KW, password}, password},
        };
        for (const auto& [recipient, decryption_key] : cases) {
            INFO(to_string(recipient.alg));
            auto token = must(jwt::signed_and_encrypted({signing_algorithm::ES384, signing_key},
                                                        content_encryption::A256GCM, recipient)
                                  .claims(k_standard)
                                  .serialize());
            auto parsed = must(jwt::parse_signed_and_encrypted(token, {recipient.alg}, {content_encryption::A256GCM},
                                                               {signing_algorithm::ES384}));
            CHECK(parsed.header().cty() == "JWT");
            auto inner = must(parsed.decrypt(decryption_key));
            CHECK(inner.header().typ() == "JWT");
            CHECK(must(inner.claims(signing_pub)) == k_standard);
        }
    }

    const auto kek = must(jwk::generate_oct(16));
    const auto token = must(jwt::signed_and_encrypted({signing_algorithm::ES384, signing_key},
                                                      content_encryption::A128CBC_HS256, {key_algorithm::A128KW, kek})
                                .claims(k_standard)
                                .serialize());
    auto parsed = must(jwt::parse_signed_and_encrypted(token, {key_algorithm::A128KW},
                                                       {content_encryption::A128CBC_HS256},
                                                       {signing_algorithm::ES384}));

    SECTION("the wrong decryption key") {
        CHECK(error_of(parsed.decrypt(must(jwk::generate_oct(16)))) == errc::decryption_failed);
    }
    SECTION("the inner signature algorithm must be allowed") {
        auto other = must(jwt::parse_signed_and_encrypted(token, {key_algorithm::A128KW},
                                                          {content_encryption::A128CBC_HS256},
                                                          {signing_algorithm::ES256}));
        CHECK(error_of(other.decrypt(kek)) == errc::algorithm_mismatch);
    }
    SECTION("the inner signature is checked") {
        auto inner = must(parsed.decrypt(kek));
        CHECK(error_of(inner.claims(must(must(jwk::generate_ec(ec_curve::P384)).public_key()))) ==
              errc::invalid_signature);
    }
    SECTION("no signature algorithms") {
        CHECK(error_of(jwt::parse_signed_and_encrypted(token, {key_algorithm::A128KW},
                                                       {content_encryption::A128CBC_HS256}, {})) ==
              errc::invalid_argument);
    }
    SECTION("cty must say JWT, in any case") {
        const auto hmac = must(jwk::generate_oct(32));
        const auto inner_jwt = must(jwt::signed_token({signing_algorithm::HS256, hmac}).claims(k_standard).serialize());

        // A JWS encrypted without "cty".
        auto without = must(must(jwe::encrypt(inner_jwt, content_encryption::A128GCM, {key_algorithm::A128KW, kek}))
                                .compact());
        CHECK(error_of(jwt::parse_signed_and_encrypted(without, {key_algorithm::A128KW}, {content_encryption::A128GCM},
                                                       {signing_algorithm::HS256})) == errc::invalid_header);

        jwe_encrypt_options lower;
        REQUIRE(lower.protected_header.set("cty", "jwt"));
        auto lowercase = must(must(jwe::encrypt(inner_jwt, content_encryption::A128GCM,
                                                {key_algorithm::A128KW, kek}, lower))
                                  .compact());
        auto ok = must(jwt::parse_signed_and_encrypted(lowercase, {key_algorithm::A128KW},
                                                       {content_encryption::A128GCM}, {signing_algorithm::HS256}));
        CHECK(must(must(ok.decrypt(kek)).claims(hmac)) == k_standard);
    }
    CHECK(ERR_peek_error() == 0);
}

namespace {

// A KMS-style decrypter for A128KW, for nested JWTs.
struct kw_decrypter final : opaque_key_decrypter {
    jwk key;
    int calls = 0;
    explicit kw_decrypter(jwk k) : key(std::move(k)) {}
    auto algorithms() const -> std::vector<key_algorithm> override { return {key_algorithm::A128KW}; }
    auto decrypt_key(std::span<const uint8_t> encrypted_key, key_algorithm alg, content_encryption,
                     const header&) -> expected<secure_bytes> override {
        ++calls;
        return aes_key_unwrap(alg, key.oct(), encrypted_key);
    }
};

} // namespace

TEST_CASE("nested JWT: decrypting and what the JWE may hold", "[jwt][parse][nested]") {
    const auto kek = with_kid(must(jwk::generate_oct(16)), "kek-1");
    const auto hmac = must(jwk::generate_oct(32));
    const std::vector<key_algorithm> kas{key_algorithm::A128KW};
    const std::vector<content_encryption> encs{content_encryption::A128GCM};
    const std::vector<signing_algorithm> sigs{signing_algorithm::HS256};

    // Encrypts any plaintext as a nested JWT's JWE would be.
    const auto wrap = [&](std::string_view plaintext, bool compress = false) {
        jwe_encrypt_options o{.compress = compress};
        REQUIRE(o.protected_header.set("cty", "JWT"));
        return must(must(jwe::encrypt(plaintext, content_encryption::A128GCM, {key_algorithm::A128KW, kek}, o))
                        .compact());
    };
    const auto open = [&](const std::string& token) -> expected<json> {
        auto parsed = jwt::parse_signed_and_encrypted(token, kas, encs, sigs);
        if (!parsed) return jose::unexpected(parsed.error());
        auto inner = parsed->decrypt(kek);
        if (!inner) return jose::unexpected(inner.error());
        return inner->claims(hmac);
    };
    const auto inner_jwt = must(jwt::signed_token({signing_algorithm::HS256, hmac}).claims(k_standard).serialize());

    SECTION("a compact JWS inside is read") {
        CHECK(must(open(wrap(inner_jwt))) == k_standard);
        CHECK(must(open(wrap(inner_jwt + "\n"))) == k_standard); // whitespace at the ends is ignored
    }
    SECTION("compressed (\"zip\":\"DEF\") works") {
        const auto zipped = wrap(inner_jwt, true);
        const auto parsed = must(jwt::parse_signed_and_encrypted(zipped, kas, encs, sigs));
        const auto* zip = parsed.header().get("zip");
        REQUIRE(zip);
        CHECK(*zip == "DEF");
        CHECK(must(open(zipped)) == k_standard);
        const auto built = must(jwt::signed_and_encrypted({signing_algorithm::HS256, hmac}, content_encryption::A128GCM,
                                                          {key_algorithm::A128KW, kek}, {}, {.compress = true})
                                    .claims(k_standard)
                                    .serialize());
        CHECK(must(open(built)) == k_standard);
    }
    SECTION("decrypting with a key set or an opaque decrypter") {
        const auto token = wrap(inner_jwt);
        const auto parsed = must(jwt::parse_signed_and_encrypted(token, kas, encs, sigs));
        auto set = must(jwk_set::from_json(json{{"keys", json::array({must(kek.to_json())})}}));
        CHECK(must(must(parsed.decrypt(set)).claims(hmac)) == k_standard);
        kw_decrypter kms(kek);
        CHECK(must(must(parsed.decrypt(kms)).claims(hmac)) == k_standard);
        CHECK(kms.calls == 1);
    }
    SECTION("anything but a compact JWS inside is refused, after decrypting") {
        const auto flattened = must(must(jws::sign(k_standard.dump(), {signing_algorithm::HS256, hmac}))
                                        .to_json_string(jws_json_format::flattened));
        struct bad_case {
            const char* what;
            std::string plaintext;
            errc code; // parse_signed's, for the same string
        };
        const std::vector<bad_case> bad{
            {"the bare claims", R"({"sub":"kevin"})", errc::invalid_token},    // not three parts
            {"a flattened JSON JWS", flattened, errc::invalid_token},          // not three parts
            {"a JWS with a line break inside", inner_jwt.substr(0, 20) + "\r\n" + inner_jwt.substr(20),
             errc::invalid_base64}, // go-jose's JWT parser accepts it
            {"an unencoded-payload JWS", raw_jws(R"({"sub":"kevin"})", hmac, {.b64 = false}), errc::invalid_token},
            {"empty", "", errc::invalid_token},
            {"a JWT nested twice", wrap(inner_jwt), errc::invalid_token}, // five parts
        };
        for (const auto& c : bad) {
            INFO(c.what);
            const auto token = wrap(c.plaintext);
            auto parsed = must(jwt::parse_signed_and_encrypted(token, kas, encs, sigs)); // the JWE itself is fine
            auto inner = parsed.decrypt(kek);
            CHECK(error_of(inner) == c.code);
            CHECK(error_of(jwt::parse_signed(c.plaintext, sigs)) == c.code);
        }
    }
    SECTION("the decompression cap applies") {
        const std::string big(100000, 'a');
        const auto padded = must(jwt::signed_token({signing_algorithm::HS256, hmac})
                                     .claims(k_standard)
                                     .claims({{"pad", big}})
                                     .serialize());
        const auto parsed = must(jwt::parse_signed_and_encrypted(wrap(padded, true), kas, encs, sigs));
        CHECK(error_of(parsed.decrypt(kek, {.max_decompressed_size = 1000})) == errc::compression_error);
        CHECK(must(parsed.decrypt(kek, {.max_decompressed_size = 200000})).unsafe_claims());
    }
    SECTION("understood critical extensions cover both the JWE and the JWS inside") {
        const auto crit = must(header::from_json({{"crit", {"x-audit"}}, {"x-audit", "42"}}));
        const extension_set understood{"x-audit"};

        // On the inner JWS.
        const auto inner_crit = must(
            jwt::signed_token({.alg = signing_algorithm::HS256, .key = hmac, .protected_header = crit})
                .claims(k_standard)
                .serialize());
        const auto token = wrap(inner_crit);
        CHECK(error_of(must(jwt::parse_signed_and_encrypted(token, kas, encs, sigs)).decrypt(kek)) ==
              errc::unrecognized_critical_extension);
        CHECK(must(must(must(jwt::parse_signed_and_encrypted(token, kas, encs, sigs, understood)).decrypt(kek))
                       .claims(hmac)) == k_standard);

        // On the JWE, refused before anything is decrypted.
        jwe_encrypt_options o{.protected_header = crit};
        REQUIRE(o.protected_header.set("cty", "JWT"));
        const auto outer_crit = must(
            must(jwe::encrypt(inner_jwt, content_encryption::A128GCM, {key_algorithm::A128KW, kek}, o)).compact());
        CHECK(error_of(jwt::parse_signed_and_encrypted(outer_crit, kas, encs, sigs)) ==
              errc::unrecognized_critical_extension);
        CHECK(must(must(must(jwt::parse_signed_and_encrypted(outer_crit, kas, encs, sigs, understood)).decrypt(kek))
                       .claims(hmac)) == k_standard);
    }
    CHECK(ERR_peek_error() == 0);
}
