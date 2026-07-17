#include <catch2/catch_test_macros.hpp>

#include "jose/algorithm.hpp"

#include <string_view>

using namespace jose;

// --- signing_algorithm ---

TEST_CASE("signing_algorithm round-trip", "[algorithm]") {
    constexpr signing_algorithm all[] = {
        signing_algorithm::HS256, signing_algorithm::HS384, signing_algorithm::HS512,
        signing_algorithm::RS256, signing_algorithm::RS384, signing_algorithm::RS512,
        signing_algorithm::ES256, signing_algorithm::ES384, signing_algorithm::ES512,
        signing_algorithm::PS256, signing_algorithm::PS384, signing_algorithm::PS512,
        signing_algorithm::EdDSA,
    };
    for (auto alg : all) {
        auto s = to_string(alg);
        auto parsed = parse_signing_algorithm(s);
        REQUIRE(parsed.has_value());
        CHECK(*parsed == alg);
    }
}

TEST_CASE("signing_algorithm exact strings", "[algorithm]") {
    CHECK(to_string(signing_algorithm::HS256) == "HS256");
    CHECK(to_string(signing_algorithm::HS384) == "HS384");
    CHECK(to_string(signing_algorithm::HS512) == "HS512");
    CHECK(to_string(signing_algorithm::RS256) == "RS256");
    CHECK(to_string(signing_algorithm::RS384) == "RS384");
    CHECK(to_string(signing_algorithm::RS512) == "RS512");
    CHECK(to_string(signing_algorithm::ES256) == "ES256");
    CHECK(to_string(signing_algorithm::ES384) == "ES384");
    CHECK(to_string(signing_algorithm::ES512) == "ES512");
    CHECK(to_string(signing_algorithm::PS256) == "PS256");
    CHECK(to_string(signing_algorithm::PS384) == "PS384");
    CHECK(to_string(signing_algorithm::PS512) == "PS512");
    CHECK(to_string(signing_algorithm::EdDSA) == "EdDSA");
}

// --- key_algorithm ---

TEST_CASE("key_algorithm round-trip", "[algorithm]") {
    constexpr key_algorithm all[] = {
        key_algorithm::RSA1_5, key_algorithm::RSA_OAEP, key_algorithm::RSA_OAEP_256,
        key_algorithm::A128KW, key_algorithm::A192KW, key_algorithm::A256KW,
        key_algorithm::dir,
        key_algorithm::ECDH_ES, key_algorithm::ECDH_ES_A128KW,
        key_algorithm::ECDH_ES_A192KW, key_algorithm::ECDH_ES_A256KW,
        key_algorithm::A128GCMKW, key_algorithm::A192GCMKW, key_algorithm::A256GCMKW,
        key_algorithm::PBES2_HS256_A128KW, key_algorithm::PBES2_HS384_A192KW,
        key_algorithm::PBES2_HS512_A256KW,
    };
    for (auto alg : all) {
        auto s = to_string(alg);
        auto parsed = parse_key_algorithm(s);
        REQUIRE(parsed.has_value());
        CHECK(*parsed == alg);
    }
}

TEST_CASE("key_algorithm exact strings (RFC 7518)", "[algorithm]") {
    CHECK(to_string(key_algorithm::RSA1_5) == "RSA1_5");
    CHECK(to_string(key_algorithm::RSA_OAEP) == "RSA-OAEP");
    CHECK(to_string(key_algorithm::RSA_OAEP_256) == "RSA-OAEP-256");
    CHECK(to_string(key_algorithm::A128KW) == "A128KW");
    CHECK(to_string(key_algorithm::A192KW) == "A192KW");
    CHECK(to_string(key_algorithm::A256KW) == "A256KW");
    CHECK(to_string(key_algorithm::dir) == "dir");
    CHECK(to_string(key_algorithm::ECDH_ES) == "ECDH-ES");
    CHECK(to_string(key_algorithm::ECDH_ES_A128KW) == "ECDH-ES+A128KW");
    CHECK(to_string(key_algorithm::ECDH_ES_A192KW) == "ECDH-ES+A192KW");
    CHECK(to_string(key_algorithm::ECDH_ES_A256KW) == "ECDH-ES+A256KW");
    CHECK(to_string(key_algorithm::A128GCMKW) == "A128GCMKW");
    CHECK(to_string(key_algorithm::A192GCMKW) == "A192GCMKW");
    CHECK(to_string(key_algorithm::A256GCMKW) == "A256GCMKW");
    CHECK(to_string(key_algorithm::PBES2_HS256_A128KW) == "PBES2-HS256+A128KW");
    CHECK(to_string(key_algorithm::PBES2_HS384_A192KW) == "PBES2-HS384+A192KW");
    CHECK(to_string(key_algorithm::PBES2_HS512_A256KW) == "PBES2-HS512+A256KW");
}

// --- content_encryption ---

TEST_CASE("content_encryption round-trip", "[algorithm]") {
    constexpr content_encryption all[] = {
        content_encryption::A128CBC_HS256, content_encryption::A192CBC_HS384,
        content_encryption::A256CBC_HS512,
        content_encryption::A128GCM, content_encryption::A192GCM,
        content_encryption::A256GCM,
    };
    for (auto enc : all) {
        auto s = to_string(enc);
        auto parsed = parse_content_encryption(s);
        REQUIRE(parsed.has_value());
        CHECK(*parsed == enc);
    }
}

TEST_CASE("content_encryption exact strings (RFC 7518)", "[algorithm]") {
    CHECK(to_string(content_encryption::A128CBC_HS256) == "A128CBC-HS256");
    CHECK(to_string(content_encryption::A192CBC_HS384) == "A192CBC-HS384");
    CHECK(to_string(content_encryption::A256CBC_HS512) == "A256CBC-HS512");
    CHECK(to_string(content_encryption::A128GCM) == "A128GCM");
    CHECK(to_string(content_encryption::A192GCM) == "A192GCM");
    CHECK(to_string(content_encryption::A256GCM) == "A256GCM");
}

// --- ec_curve ---

TEST_CASE("ec_curve round-trip", "[algorithm]") {
    constexpr ec_curve all[] = {ec_curve::P256, ec_curve::P384, ec_curve::P521};
    for (auto crv : all) {
        auto s = to_string(crv);
        auto parsed = parse_ec_curve(s);
        REQUIRE(parsed.has_value());
        CHECK(*parsed == crv);
    }
}

TEST_CASE("ec_curve exact strings", "[algorithm]") {
    CHECK(to_string(ec_curve::P256) == "P-256");
    CHECK(to_string(ec_curve::P384) == "P-384");
    CHECK(to_string(ec_curve::P521) == "P-521");
}

// --- okp_curve ---

TEST_CASE("okp_curve round-trip", "[algorithm]") {
    constexpr okp_curve all[] = {
        okp_curve::Ed25519, okp_curve::Ed448, okp_curve::X25519, okp_curve::X448,
    };
    for (auto crv : all) {
        auto s = to_string(crv);
        auto parsed = parse_okp_curve(s);
        REQUIRE(parsed.has_value());
        CHECK(*parsed == crv);
    }
}

TEST_CASE("okp_curve exact strings", "[algorithm]") {
    CHECK(to_string(okp_curve::Ed25519) == "Ed25519");
    CHECK(to_string(okp_curve::Ed448) == "Ed448");
    CHECK(to_string(okp_curve::X25519) == "X25519");
    CHECK(to_string(okp_curve::X448) == "X448");
}

// --- kty ---

TEST_CASE("kty round-trip", "[algorithm]") {
    constexpr kty all[] = {kty::RSA, kty::EC, kty::oct, kty::OKP};
    for (auto k : all) {
        auto s = to_string(k);
        auto parsed = parse_kty(s);
        REQUIRE(parsed.has_value());
        CHECK(*parsed == k);
    }
}

TEST_CASE("kty exact strings", "[algorithm]") {
    CHECK(to_string(kty::RSA) == "RSA");
    CHECK(to_string(kty::EC) == "EC");
    CHECK(to_string(kty::oct) == "oct");
    CHECK(to_string(kty::OKP) == "OKP");
}

// --- Unknown strings return errors ---

TEST_CASE("unknown strings return errors", "[algorithm]") {
    SECTION("signing_algorithm") {
        auto r = parse_signing_algorithm("BOGUS");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().code == errc::unsupported_algorithm);
    }
    SECTION("key_algorithm") {
        auto r = parse_key_algorithm("BOGUS");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().code == errc::unsupported_algorithm);
    }
    SECTION("content_encryption") {
        auto r = parse_content_encryption("BOGUS");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().code == errc::unsupported_algorithm);
    }
    SECTION("ec_curve") {
        auto r = parse_ec_curve("P-999");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().code == errc::unsupported_algorithm);
    }
    SECTION("okp_curve") {
        auto r = parse_okp_curve("Ed99999");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().code == errc::unsupported_algorithm);
    }
    SECTION("kty") {
        auto r = parse_kty("NOPE");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().code == errc::unsupported_algorithm);
    }
}

// --- is_legacy_algorithm ---

TEST_CASE("is_legacy_algorithm", "[algorithm]") {
    CHECK(is_legacy_algorithm(key_algorithm::RSA1_5));

    // All others should be false
    CHECK_FALSE(is_legacy_algorithm(key_algorithm::RSA_OAEP));
    CHECK_FALSE(is_legacy_algorithm(key_algorithm::RSA_OAEP_256));
    CHECK_FALSE(is_legacy_algorithm(key_algorithm::A128KW));
    CHECK_FALSE(is_legacy_algorithm(key_algorithm::A256KW));
    CHECK_FALSE(is_legacy_algorithm(key_algorithm::dir));
    CHECK_FALSE(is_legacy_algorithm(key_algorithm::ECDH_ES));
    CHECK_FALSE(is_legacy_algorithm(key_algorithm::ECDH_ES_A128KW));
    CHECK_FALSE(is_legacy_algorithm(key_algorithm::A128GCMKW));
    CHECK_FALSE(is_legacy_algorithm(key_algorithm::PBES2_HS256_A128KW));
    CHECK_FALSE(is_legacy_algorithm(key_algorithm::PBES2_HS384_A192KW));
    CHECK_FALSE(is_legacy_algorithm(key_algorithm::PBES2_HS512_A256KW));
}

// --- cek_byte_size, iv_byte_size, tag_byte_size ---

TEST_CASE("cek_byte_size", "[algorithm]") {
    CHECK(cek_byte_size(content_encryption::A128CBC_HS256) == 32);
    CHECK(cek_byte_size(content_encryption::A192CBC_HS384) == 48);
    CHECK(cek_byte_size(content_encryption::A256CBC_HS512) == 64);
    CHECK(cek_byte_size(content_encryption::A128GCM) == 16);
    CHECK(cek_byte_size(content_encryption::A192GCM) == 24);
    CHECK(cek_byte_size(content_encryption::A256GCM) == 32);
}

TEST_CASE("iv_byte_size", "[algorithm]") {
    // CBC uses 16-byte IV
    CHECK(iv_byte_size(content_encryption::A128CBC_HS256) == 16);
    CHECK(iv_byte_size(content_encryption::A192CBC_HS384) == 16);
    CHECK(iv_byte_size(content_encryption::A256CBC_HS512) == 16);
    // GCM uses 12-byte IV
    CHECK(iv_byte_size(content_encryption::A128GCM) == 12);
    CHECK(iv_byte_size(content_encryption::A192GCM) == 12);
    CHECK(iv_byte_size(content_encryption::A256GCM) == 12);
}

TEST_CASE("tag_byte_size", "[algorithm]") {
    // CBC-HMAC tag is half the HMAC output
    CHECK(tag_byte_size(content_encryption::A128CBC_HS256) == 16);
    CHECK(tag_byte_size(content_encryption::A192CBC_HS384) == 24);
    CHECK(tag_byte_size(content_encryption::A256CBC_HS512) == 32);
    // GCM tag is always 16
    CHECK(tag_byte_size(content_encryption::A128GCM) == 16);
    CHECK(tag_byte_size(content_encryption::A192GCM) == 16);
    CHECK(tag_byte_size(content_encryption::A256GCM) == 16);
}
