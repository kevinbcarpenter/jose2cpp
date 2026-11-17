#include <catch2/catch_test_macros.hpp>

#include "jose/jose.hpp"

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <cstdint>
#include <string_view>
#include <vector>

using namespace jose;

namespace {

auto make_data(std::string_view s) -> std::vector<uint8_t> {
    return {s.begin(), s.end()};
}

// Deliberately bypasses jose::generate_rsa_key to make a weak key for
// negative tests.
auto generate_small_rsa_key(int bits) -> evp_pkey_ptr {
    auto ctx = make_evp_pkey_ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
    EVP_PKEY_keygen_init(ctx.get());
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits);
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
        auto key = random_bytes(32).value();
        auto sig = hmac_sign(signing_algorithm::HS256, key, data);
        REQUIRE(sig.has_value());
        auto ok = hmac_verify(signing_algorithm::HS256, key, data, *sig);
        REQUIRE(ok.has_value());
    }

    SECTION("HS384 round-trip") {
        auto key = random_bytes(48).value();
        auto sig = hmac_sign(signing_algorithm::HS384, key, data);
        REQUIRE(sig.has_value());
        auto ok = hmac_verify(signing_algorithm::HS384, key, data, *sig);
        REQUIRE(ok.has_value());
    }

    SECTION("HS512 round-trip") {
        auto key = random_bytes(64).value();
        auto sig = hmac_sign(signing_algorithm::HS512, key, data);
        REQUIRE(sig.has_value());
        auto ok = hmac_verify(signing_algorithm::HS512, key, data, *sig);
        REQUIRE(ok.has_value());
    }

    SECTION("verify with wrong data fails") {
        auto key = random_bytes(32).value();
        auto sig = hmac_sign(signing_algorithm::HS256, key, data);
        REQUIRE(sig.has_value());

        auto bad_data = make_data("tampered payload");
        auto result = hmac_verify(signing_algorithm::HS256, key, bad_data, *sig);
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("verify with wrong key fails") {
        auto key = random_bytes(32).value();
        auto sig = hmac_sign(signing_algorithm::HS256, key, data);
        REQUIRE(sig.has_value());

        auto wrong_key = random_bytes(32).value();
        auto result = hmac_verify(signing_algorithm::HS256, wrong_key, data, *sig);
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("key too short returns errc::key_too_short") {
        auto short_key = random_bytes(16).value(); // HS256 needs 32
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
    auto key = generate_rsa_key(2048).value();
    REQUIRE(key != nullptr);

    SECTION("RS256 round-trip") {
        auto sig = rsa_sign(signing_algorithm::RS256, key.get(), data);
        REQUIRE(sig.has_value());
        auto ok = rsa_verify(signing_algorithm::RS256, key.get(), data, *sig);
        REQUIRE(ok.has_value());
    }

    SECTION("RS256 verify with wrong data fails") {
        auto sig = rsa_sign(signing_algorithm::RS256, key.get(), data);
        REQUIRE(sig.has_value());

        auto bad_data = make_data("tampered payload");
        auto result = rsa_verify(signing_algorithm::RS256, key.get(), bad_data, *sig);
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("RS256 verify with wrong key fails") {
        auto sig = rsa_sign(signing_algorithm::RS256, key.get(), data);
        REQUIRE(sig.has_value());

        auto wrong_key = generate_rsa_key(2048).value();
        auto result = rsa_verify(signing_algorithm::RS256, wrong_key.get(),
                                 data, *sig);
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("PS256 round-trip") {
        auto sig = rsa_sign(signing_algorithm::PS256, key.get(), data);
        REQUIRE(sig.has_value());
        auto ok = rsa_verify(signing_algorithm::PS256, key.get(), data, *sig);
        REQUIRE(ok.has_value());
    }

    SECTION("PS256 verify with wrong data fails") {
        auto sig = rsa_sign(signing_algorithm::PS256, key.get(), data);
        REQUIRE(sig.has_value());

        auto bad_data = make_data("tampered payload");
        auto result = rsa_verify(signing_algorithm::PS256, key.get(), bad_data, *sig);
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("every RS*/PS* algorithm round-trips and is hash-bound") {
        for (auto alg : {signing_algorithm::RS256, signing_algorithm::RS384,
                         signing_algorithm::RS512, signing_algorithm::PS256,
                         signing_algorithm::PS384, signing_algorithm::PS512}) {
            INFO(to_string(alg));
            auto sig = rsa_sign(alg, key.get(), data);
            REQUIRE(sig.has_value());
            REQUIRE(sig->size() == 256);
            REQUIRE(rsa_verify(alg, key.get(), data, *sig).has_value());
        }

        // A signature made with one hash must not verify under another.
        auto rs256 = rsa_sign(signing_algorithm::RS256, key.get(), data).value();
        REQUIRE_FALSE(rsa_verify(signing_algorithm::RS384, key.get(), data, rs256).has_value());
        auto ps384 = rsa_sign(signing_algorithm::PS384, key.get(), data).value();
        REQUIRE_FALSE(rsa_verify(signing_algorithm::PS512, key.get(), data, ps384).has_value());
        REQUIRE_FALSE(rsa_verify(signing_algorithm::RS384, key.get(), data, ps384).has_value());
    }
}

TEST_CASE("RSA minimum key size is enforced", "[signing][rsa]") {
    auto data = make_data("payload");

    SECTION("generate_rsa_key rejects < 2048 bits") {
        auto key = generate_rsa_key(1024);
        REQUIRE_FALSE(key.has_value());
        REQUIRE(key.error().code == errc::key_size_too_small);
    }

    SECTION("rsa_sign rejects a 1024-bit key") {
        auto weak = generate_small_rsa_key(1024);
        REQUIRE(weak != nullptr);
        auto sig = rsa_sign(signing_algorithm::RS256, weak.get(), data);
        REQUIRE_FALSE(sig.has_value());
        REQUIRE(sig.error().code == errc::key_size_too_small);
    }
}

// ---------------------------------------------------------------------------
// ECDSA
// ---------------------------------------------------------------------------

TEST_CASE("ECDSA sign and verify", "[signing][ec]") {
    auto data = make_data("test payload for ECDSA signing");

    SECTION("ES256 round-trip and fixed-size signature") {
        auto key = generate_ec_key(ec_curve::P256).value();
        auto sig = ec_sign(signing_algorithm::ES256, key.get(), data);
        REQUIRE(sig.has_value());
        REQUIRE(sig->size() == 64);

        auto ok = ec_verify(signing_algorithm::ES256, key.get(), data, *sig);
        REQUIRE(ok.has_value());
    }

    SECTION("ES384 round-trip and fixed-size signature") {
        auto key = generate_ec_key(ec_curve::P384).value();
        auto sig = ec_sign(signing_algorithm::ES384, key.get(), data);
        REQUIRE(sig.has_value());
        REQUIRE(sig->size() == 96);

        auto ok = ec_verify(signing_algorithm::ES384, key.get(), data, *sig);
        REQUIRE(ok.has_value());
    }

    SECTION("ES512 round-trip and fixed-size signature") {
        auto key = generate_ec_key(ec_curve::P521).value();
        auto sig = ec_sign(signing_algorithm::ES512, key.get(), data);
        REQUIRE(sig.has_value());
        REQUIRE(sig->size() == 132);

        auto ok = ec_verify(signing_algorithm::ES512, key.get(), data, *sig);
        REQUIRE(ok.has_value());
    }

    SECTION("ES256 verify with wrong data fails") {
        auto key = generate_ec_key(ec_curve::P256).value();
        auto sig = ec_sign(signing_algorithm::ES256, key.get(), data);
        REQUIRE(sig.has_value());

        auto bad_data = make_data("tampered payload");
        auto result = ec_verify(signing_algorithm::ES256, key.get(), bad_data, *sig);
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("curve/algorithm mismatch is rejected") {
        auto p384_key = generate_ec_key(ec_curve::P384).value();
        auto sig = ec_sign(signing_algorithm::ES256, p384_key.get(), data);
        REQUIRE_FALSE(sig.has_value());
        REQUIRE(sig.error().code == errc::algorithm_mismatch);
    }
}

// ---------------------------------------------------------------------------
// EdDSA
// ---------------------------------------------------------------------------

TEST_CASE("EdDSA sign and verify", "[signing][eddsa]") {
    auto data = make_data("test payload for EdDSA signing");

    SECTION("Ed25519 round-trip") {
        auto key = generate_okp_key(okp_curve::Ed25519).value();
        auto sig = eddsa_sign(key.get(), data);
        REQUIRE(sig.has_value());

        auto ok = eddsa_verify(key.get(), data, *sig);
        REQUIRE(ok.has_value());
    }

    SECTION("Ed448 round-trip") {
        auto key = generate_okp_key(okp_curve::Ed448).value();
        auto sig = eddsa_sign(key.get(), data);
        REQUIRE(sig.has_value());

        auto ok = eddsa_verify(key.get(), data, *sig);
        REQUIRE(ok.has_value());
    }

    SECTION("Ed25519 verify with wrong data fails") {
        auto key = generate_okp_key(okp_curve::Ed25519).value();
        auto sig = eddsa_sign(key.get(), data);
        REQUIRE(sig.has_value());

        auto bad_data = make_data("tampered payload");
        auto result = eddsa_verify(key.get(), bad_data, *sig);
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("Ed448 verify with wrong data fails") {
        auto key = generate_okp_key(okp_curve::Ed448).value();
        auto sig = eddsa_sign(key.get(), data);
        REQUIRE(sig.has_value());

        auto bad_data = make_data("tampered payload");
        auto result = eddsa_verify(key.get(), bad_data, *sig);
        REQUIRE_FALSE(result.has_value());
    }
}

// ---------------------------------------------------------------------------
// Unified sign/verify
// ---------------------------------------------------------------------------

TEST_CASE("unified sign/verify dispatches by algorithm", "[signing][unified]") {
    auto data = make_data("unified API payload");

    SECTION("HS256 with oct key") {
        auto key = random_bytes(32).value();
        auto sig = sign(signing_algorithm::HS256, key, data);
        REQUIRE(sig.has_value());
        REQUIRE(verify(signing_algorithm::HS256, key, data, *sig).has_value());
    }

    SECTION("RS256 with RSA key") {
        auto key = generate_rsa_key().value();
        auto sig = sign(signing_algorithm::RS256, key.get(), data);
        REQUIRE(sig.has_value());
        REQUIRE(verify(signing_algorithm::RS256, key.get(), data, *sig).has_value());
    }

    SECTION("ES256 with EC key") {
        auto key = generate_ec_key(ec_curve::P256).value();
        auto sig = sign(signing_algorithm::ES256, key.get(), data);
        REQUIRE(sig.has_value());
        REQUIRE(verify(signing_algorithm::ES256, key.get(), data, *sig).has_value());
    }

    SECTION("EdDSA with Ed25519 key") {
        auto key = generate_okp_key(okp_curve::Ed25519).value();
        auto sig = sign(signing_algorithm::EdDSA, key.get(), data);
        REQUIRE(sig.has_value());
        REQUIRE(verify(signing_algorithm::EdDSA, key.get(), data, *sig).has_value());
    }

    SECTION("asymmetric algorithm with oct key is rejected") {
        auto key = random_bytes(32).value();
        auto sig = sign(signing_algorithm::RS256, to_span(key), data);
        REQUIRE_FALSE(sig.has_value());
        REQUIRE(sig.error().code == errc::algorithm_mismatch);
    }

    SECTION("HMAC algorithm with asymmetric key is rejected") {
        auto key = generate_rsa_key().value();
        auto sig = sign(signing_algorithm::HS256, key.get(), data);
        REQUIRE_FALSE(sig.has_value());
        REQUIRE(sig.error().code == errc::algorithm_mismatch);
    }
}
