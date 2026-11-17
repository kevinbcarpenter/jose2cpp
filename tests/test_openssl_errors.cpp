// OpenSSL keeps a per-thread error queue. Library calls must not leave
// entries behind when they fail, and an OpenSSL error reported to the
// caller must describe the failure that just happened, not a stale one.

#include <catch2/catch_test_macros.hpp>

#include "jose/jose.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>

#include <string>
#include <vector>

using namespace jose;

namespace {

auto flip_first_bit(secure_bytes v) -> secure_bytes {
    v[0] ^= 0x01;
    return v;
}

} // namespace

TEST_CASE("failed operations leave the OpenSSL error queue empty", "[openssl-errors]") {
    const std::vector<uint8_t> data{'d', 'a', 't', 'a'};
    ERR_clear_error();

    SECTION("AES key unwrap with the wrong KEK") {
        auto kek = random_bytes(16).value();
        auto wrapped = aes_key_wrap(key_algorithm::A128KW, kek, random_bytes(16).value()).value();
        REQUIRE_FALSE(aes_key_unwrap(key_algorithm::A128KW, random_bytes(16).value(), wrapped));
    }

    SECTION("AES-GCM decrypt with a bad tag") {
        auto enc = content_encryption::A128GCM;
        auto cek = generate_cek(enc).value();
        auto iv = generate_iv(enc).value();
        auto sealed = encrypt(enc, cek, iv, data, {}).value();
        REQUIRE_FALSE(decrypt(enc, cek, iv, sealed.ciphertext, {}, flip_first_bit(sealed.tag)));
    }

    SECTION("AES-CBC decrypt with bad padding behind a valid tag") {
        // Forge a correctly-tagged junk block so decryption gets past the
        // HMAC check and fails in OpenSSL's padding check (RFC 7518 §5.2.2.1:
        // tag = first 16 bytes of HMAC-SHA256(MAC_KEY, AAD || IV || E || AL)).
        auto enc = content_encryption::A128CBC_HS256;
        auto cek = generate_cek(enc).value();
        auto iv = generate_iv(enc).value();
        const std::span<const uint8_t> mac_key(cek.data(), 16);

        bool reached_padding_failure = false;
        for (int attempt = 0; attempt < 16 && !reached_padding_failure; ++attempt) {
            auto block = random_bytes(16).value();
            std::vector<uint8_t> mac_input(iv.begin(), iv.end());
            mac_input.insert(mac_input.end(), block.begin(), block.end());
            for (int i = 0; i < 8; ++i) mac_input.push_back(0); // AL = 0 (no AAD)

            // jose::sign(HS256) enforces a 32-byte key; MAC_KEY here is 16.
            unsigned char md[EVP_MAX_MD_SIZE];
            size_t md_len = 0;
            REQUIRE(EVP_Q_mac(nullptr, "HMAC", nullptr, "SHA256", nullptr,
                              mac_key.data(), mac_key.size(), mac_input.data(),
                              mac_input.size(), md, sizeof(md), &md_len) != nullptr);
            const std::vector<uint8_t> tag(md, md + 16);

            auto r = decrypt(enc, cek, iv, block, {}, tag);
            // ~1/256 of random blocks happen to carry valid padding.
            if (!r) {
                REQUIRE(r.error().code == errc::decryption_failed);
                reached_padding_failure = true;
            }
        }
        REQUIRE(reached_padding_failure);
    }

    SECTION("ECDSA verify with a bad signature") {
        auto key = generate_ec_key(ec_curve::P256).value();
        auto sig = sign(signing_algorithm::ES256, key.get(), data).value();
        REQUIRE_FALSE(verify(signing_algorithm::ES256, key.get(), data, flip_first_bit(sig)));
    }

    SECTION("ECDSA with a non-EC key") {
        auto key = generate_okp_key(okp_curve::Ed25519).value();
        REQUIRE_FALSE(sign(signing_algorithm::ES256, key.get(), data));
    }

    SECTION("EdDSA verify with a bad signature") {
        auto key = generate_okp_key(okp_curve::Ed25519).value();
        auto sig = sign(signing_algorithm::EdDSA, key.get(), data).value();
        REQUIRE_FALSE(verify(signing_algorithm::EdDSA, key.get(), data, flip_first_bit(sig)));
    }

    SECTION("RSA verify with a bad signature") {
        auto key = generate_rsa_key(2048).value();
        auto sig = sign(signing_algorithm::PS256, key.get(), data).value();
        REQUIRE_FALSE(verify(signing_algorithm::PS256, key.get(), data, flip_first_bit(sig)));
    }

    SECTION("ECDH with mismatched curves (reported as an OpenSSL error)") {
        auto a = generate_ec_key(ec_curve::P256).value();
        auto b = generate_ec_key(ec_curve::P384).value();
        auto r = ecdh_derive_key_from_epk(a.get(), b.get(), "ECDH-ES", "", "", 128);
        REQUIRE_FALSE(r);
        REQUIRE(r.error().code == errc::openssl_error);
    }

    CHECK(ERR_peek_error() == 0);
}

TEST_CASE("OpenSSL errors report the current failure, not a stale one", "[openssl-errors]") {
    ERR_clear_error();
    // Simulate something earlier in the thread (another library, or user
    // code) leaving an unrelated error on the queue.
    ERR_raise(ERR_LIB_EVP, EVP_R_BAD_DECRYPT);
    const std::string stale = ERR_reason_error_string(ERR_peek_error());
    REQUIRE_FALSE(stale.empty());

    auto a = generate_ec_key(ec_curve::P256).value();
    auto b = generate_okp_key(okp_curve::X25519).value();
    auto r = ecdh_derive_key_from_epk(a.get(), b.get(), "ECDH-ES", "", "", 128);
    REQUIRE_FALSE(r);
    REQUIRE(r.error().code == errc::openssl_error);
    INFO("message: " << r.error().message);
    CHECK(r.error().message.find(stale) == std::string::npos);
    CHECK(ERR_peek_error() == 0);
}
