#include <catch2/catch_test_macros.hpp>

#include "jose/algorithm.hpp"
#include "jose/crypto/hmac.hpp"
#include "jose/crypto/rsa.hpp"
#include "jose/crypto/ec.hpp"
#include "jose/crypto/eddsa.hpp"
#include "jose/crypto/openssl_util.hpp"

#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#include <array>
#include <cstdint>
#include <span>
#include <vector>

using namespace jose;

namespace {

auto make_data(std::string_view s) -> std::vector<uint8_t> {
    return {s.begin(), s.end()};
}

auto generate_random_key(size_t len) -> std::vector<uint8_t> {
    std::vector<uint8_t> key(len);
    RAND_bytes(key.data(), static_cast<int>(len));
    return key;
}

auto generate_rsa_key(int bits = 2048) -> evp_pkey_ptr {
    auto ctx = make_evp_pkey_ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
    EVP_PKEY_keygen_init(ctx.get());
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits);
    EVP_PKEY* raw = nullptr;
    EVP_PKEY_keygen(ctx.get(), &raw);
    return make_evp_pkey_ptr(raw);
}

auto generate_ec_key(const char* group_name) -> evp_pkey_ptr {
    auto ctx = make_evp_pkey_ctx(
        EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    EVP_PKEY_keygen_init(ctx.get());
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("group",
            const_cast<char*>(group_name), 0),
        OSSL_PARAM_construct_end()
    };
    EVP_PKEY_CTX_set_params(ctx.get(), params);
    EVP_PKEY* raw = nullptr;
    EVP_PKEY_keygen(ctx.get(), &raw);
    return make_evp_pkey_ptr(raw);
}

auto generate_ed_key(int nid) -> evp_pkey_ptr {
    auto ctx = make_evp_pkey_ctx(EVP_PKEY_CTX_new_id(nid, nullptr));
    EVP_PKEY_keygen_init(ctx.get());
    EVP_PKEY* raw = nullptr;
    EVP_PKEY_keygen(ctx.get(), &raw);
    return make_evp_pkey_ptr(raw);
}

} // namespace

// ---------------------------------------------------------------------------
// HMAC
// ---------------------------------------------------------------------------

TEST_CASE("HMAC sign and verify", "[signing][hmac]") {
    auto data = make_data("test payload for HMAC signing");

    SECTION("HS256 round-trip") {
        auto key = generate_random_key(32);
        auto sig = hmac_sign(signing_algorithm::HS256, key, data);
        REQUIRE(sig.has_value());
        auto ok = hmac_verify(signing_algorithm::HS256, key, data, to_span(*sig));
        REQUIRE(ok.has_value());
    }

    SECTION("HS384 round-trip") {
        auto key = generate_random_key(48);
        auto sig = hmac_sign(signing_algorithm::HS384, key, data);
        REQUIRE(sig.has_value());
        auto ok = hmac_verify(signing_algorithm::HS384, key, data, to_span(*sig));
        REQUIRE(ok.has_value());
    }

    SECTION("HS512 round-trip") {
        auto key = generate_random_key(64);
        auto sig = hmac_sign(signing_algorithm::HS512, key, data);
        REQUIRE(sig.has_value());
        auto ok = hmac_verify(signing_algorithm::HS512, key, data, to_span(*sig));
        REQUIRE(ok.has_value());
    }

    SECTION("verify with wrong data fails") {
        auto key = generate_random_key(32);
        auto sig = hmac_sign(signing_algorithm::HS256, key, data);
        REQUIRE(sig.has_value());

        auto bad_data = make_data("tampered payload");
        auto result = hmac_verify(signing_algorithm::HS256, key, bad_data,
                                  to_span(*sig));
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("verify with wrong key fails") {
        auto key = generate_random_key(32);
        auto sig = hmac_sign(signing_algorithm::HS256, key, data);
        REQUIRE(sig.has_value());

        auto wrong_key = generate_random_key(32);
        auto result = hmac_verify(signing_algorithm::HS256, wrong_key, data,
                                  to_span(*sig));
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("key too short returns errc::key_too_short") {
        auto short_key = generate_random_key(16); // HS256 needs 32
        auto result = hmac_sign(signing_algorithm::HS256, short_key, data);
        REQUIRE_FALSE(result.has_value());
        REQUIRE(result.error().code == errc::key_too_short);
    }
}

// ---------------------------------------------------------------------------
// RSA (PKCS#1 v1.5 and PSS)
// ---------------------------------------------------------------------------

TEST_CASE("RSA sign and verify", "[signing][rsa]") {
    auto data = make_data("test payload for RSA signing");
    auto key = generate_rsa_key(2048);
    REQUIRE(key != nullptr);

    SECTION("RS256 round-trip") {
        auto sig = rsa_sign(signing_algorithm::RS256, key.get(), data);
        REQUIRE(sig.has_value());
        auto ok = rsa_verify(signing_algorithm::RS256, key.get(), data,
                             to_span(*sig));
        REQUIRE(ok.has_value());
    }

    SECTION("RS256 verify with wrong data fails") {
        auto sig = rsa_sign(signing_algorithm::RS256, key.get(), data);
        REQUIRE(sig.has_value());

        auto bad_data = make_data("tampered payload");
        auto result = rsa_verify(signing_algorithm::RS256, key.get(), bad_data,
                                 to_span(*sig));
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("RS256 verify with wrong key fails") {
        auto sig = rsa_sign(signing_algorithm::RS256, key.get(), data);
        REQUIRE(sig.has_value());

        auto wrong_key = generate_rsa_key(2048);
        auto result = rsa_verify(signing_algorithm::RS256, wrong_key.get(),
                                 data, to_span(*sig));
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("PS256 round-trip") {
        auto sig = rsa_sign(signing_algorithm::PS256, key.get(), data);
        REQUIRE(sig.has_value());
        auto ok = rsa_verify(signing_algorithm::PS256, key.get(), data,
                             to_span(*sig));
        REQUIRE(ok.has_value());
    }

    SECTION("PS256 verify with wrong data fails") {
        auto sig = rsa_sign(signing_algorithm::PS256, key.get(), data);
        REQUIRE(sig.has_value());

        auto bad_data = make_data("tampered payload");
        auto result = rsa_verify(signing_algorithm::PS256, key.get(), bad_data,
                                 to_span(*sig));
        REQUIRE_FALSE(result.has_value());
    }
}

// ---------------------------------------------------------------------------
// ECDSA
// ---------------------------------------------------------------------------

TEST_CASE("ECDSA sign and verify", "[signing][ec]") {
    auto data = make_data("test payload for ECDSA signing");

    SECTION("ES256 round-trip and fixed-size signature") {
        auto key = generate_ec_key("P-256");
        REQUIRE(key != nullptr);

        auto sig = ec_sign(signing_algorithm::ES256, key.get(), data);
        REQUIRE(sig.has_value());
        REQUIRE(sig->size() == 64);

        auto ok = ec_verify(signing_algorithm::ES256, key.get(), data,
                            to_span(*sig));
        REQUIRE(ok.has_value());
    }

    SECTION("ES384 round-trip and fixed-size signature") {
        auto key = generate_ec_key("P-384");
        REQUIRE(key != nullptr);

        auto sig = ec_sign(signing_algorithm::ES384, key.get(), data);
        REQUIRE(sig.has_value());
        REQUIRE(sig->size() == 96);

        auto ok = ec_verify(signing_algorithm::ES384, key.get(), data,
                            to_span(*sig));
        REQUIRE(ok.has_value());
    }

    SECTION("ES512 round-trip and fixed-size signature") {
        auto key = generate_ec_key("P-521");
        REQUIRE(key != nullptr);

        auto sig = ec_sign(signing_algorithm::ES512, key.get(), data);
        REQUIRE(sig.has_value());
        REQUIRE(sig->size() == 132);

        auto ok = ec_verify(signing_algorithm::ES512, key.get(), data,
                            to_span(*sig));
        REQUIRE(ok.has_value());
    }

    SECTION("ES256 verify with wrong data fails") {
        auto key = generate_ec_key("P-256");
        REQUIRE(key != nullptr);

        auto sig = ec_sign(signing_algorithm::ES256, key.get(), data);
        REQUIRE(sig.has_value());

        auto bad_data = make_data("tampered payload");
        auto result = ec_verify(signing_algorithm::ES256, key.get(), bad_data,
                                to_span(*sig));
        REQUIRE_FALSE(result.has_value());
    }
}

// ---------------------------------------------------------------------------
// EdDSA
// ---------------------------------------------------------------------------

TEST_CASE("EdDSA sign and verify", "[signing][eddsa]") {
    auto data = make_data("test payload for EdDSA signing");

    SECTION("Ed25519 round-trip") {
        auto key = generate_ed_key(EVP_PKEY_ED25519);
        REQUIRE(key != nullptr);

        auto sig = eddsa_sign(key.get(), data);
        REQUIRE(sig.has_value());

        auto ok = eddsa_verify(key.get(), data, to_span(*sig));
        REQUIRE(ok.has_value());
    }

    SECTION("Ed448 round-trip") {
        auto key = generate_ed_key(EVP_PKEY_ED448);
        REQUIRE(key != nullptr);

        auto sig = eddsa_sign(key.get(), data);
        REQUIRE(sig.has_value());

        auto ok = eddsa_verify(key.get(), data, to_span(*sig));
        REQUIRE(ok.has_value());
    }

    SECTION("Ed25519 verify with wrong data fails") {
        auto key = generate_ed_key(EVP_PKEY_ED25519);
        REQUIRE(key != nullptr);

        auto sig = eddsa_sign(key.get(), data);
        REQUIRE(sig.has_value());

        auto bad_data = make_data("tampered payload");
        auto result = eddsa_verify(key.get(), bad_data, to_span(*sig));
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("Ed448 verify with wrong data fails") {
        auto key = generate_ed_key(EVP_PKEY_ED448);
        REQUIRE(key != nullptr);

        auto sig = eddsa_sign(key.get(), data);
        REQUIRE(sig.has_value());

        auto bad_data = make_data("tampered payload");
        auto result = eddsa_verify(key.get(), bad_data, to_span(*sig));
        REQUIRE_FALSE(result.has_value());
    }
}
