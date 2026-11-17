#include <catch2/catch_test_macros.hpp>

#include "jose/jose.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <algorithm>
#include <cstdint>
#include <string_view>
#include <vector>

using namespace jose;

namespace {

auto make_plaintext(std::string_view s) -> std::vector<uint8_t> {
    return {s.begin(), s.end()};
}

} // namespace

// ---------------------------------------------------------------------------
// AES-CBC-HMAC
// ---------------------------------------------------------------------------

TEST_CASE("AES-CBC-HMAC round-trip", "[encryption][aes-cbc-hmac]") {
    auto plaintext = make_plaintext("The quick brown fox jumps over the lazy dog");
    auto aad = make_plaintext("authenticated-but-not-encrypted");

    for (auto enc : {content_encryption::A128CBC_HS256,
                     content_encryption::A192CBC_HS384,
                     content_encryption::A256CBC_HS512}) {
        auto cek = generate_cek(enc).value();
        auto iv  = generate_iv(enc).value();

        auto sealed = aes_cbc_hmac_encrypt(enc, cek, iv, plaintext, aad);
        REQUIRE(sealed.has_value());

        auto opened = aes_cbc_hmac_decrypt(enc, cek, iv, sealed->ciphertext,
                                           aad, sealed->tag);
        REQUIRE(opened.has_value());
        REQUIRE(std::equal(opened->begin(), opened->end(),
                           plaintext.begin(), plaintext.end()));
    }
}

TEST_CASE("AES-CBC-HMAC tampered ciphertext", "[encryption][aes-cbc-hmac]") {
    auto enc = content_encryption::A128CBC_HS256;
    auto cek = generate_cek(enc).value();
    auto iv  = generate_iv(enc).value();
    auto plaintext = make_plaintext("sensitive data");
    auto aad = make_plaintext("header");

    auto sealed = aes_cbc_hmac_encrypt(enc, cek, iv, plaintext, aad);
    REQUIRE(sealed.has_value());

    // Flip a byte in the ciphertext
    sealed->ciphertext[0] ^= 0xFF;

    auto opened = aes_cbc_hmac_decrypt(enc, cek, iv, sealed->ciphertext,
                                       aad, sealed->tag);
    REQUIRE_FALSE(opened.has_value());
}

TEST_CASE("AES-CBC-HMAC wrong CEK", "[encryption][aes-cbc-hmac]") {
    auto enc = content_encryption::A128CBC_HS256;
    auto cek = generate_cek(enc).value();
    auto wrong_cek = generate_cek(enc).value();
    auto iv  = generate_iv(enc).value();
    auto plaintext = make_plaintext("secret");
    auto aad = make_plaintext("aad");

    auto sealed = aes_cbc_hmac_encrypt(enc, cek, iv, plaintext, aad);
    REQUIRE(sealed.has_value());

    auto opened = aes_cbc_hmac_decrypt(enc, wrong_cek, iv, sealed->ciphertext,
                                       aad, sealed->tag);
    REQUIRE_FALSE(opened.has_value());
}

// ---------------------------------------------------------------------------
// AES-GCM
// ---------------------------------------------------------------------------

TEST_CASE("AES-GCM round-trip", "[encryption][aes-gcm]") {
    auto plaintext = make_plaintext("Hello, AES-GCM encryption!");
    auto aad = make_plaintext("additional data");

    for (auto enc : {content_encryption::A128GCM,
                     content_encryption::A192GCM,
                     content_encryption::A256GCM}) {
        auto key = generate_cek(enc).value();
        auto iv  = generate_iv(enc).value();

        auto sealed = aes_gcm_encrypt(enc, key, iv, plaintext, aad);
        REQUIRE(sealed.has_value());

        auto opened = aes_gcm_decrypt(enc, key, iv, sealed->ciphertext,
                                      aad, sealed->tag);
        REQUIRE(opened.has_value());
        REQUIRE(std::equal(opened->begin(), opened->end(),
                           plaintext.begin(), plaintext.end()));
    }
}

TEST_CASE("AES-GCM tampered ciphertext", "[encryption][aes-gcm]") {
    auto enc = content_encryption::A128GCM;
    auto key = generate_cek(enc).value();
    auto iv  = generate_iv(enc).value();
    auto plaintext = make_plaintext("tamper test");
    auto aad = make_plaintext("aad");

    auto sealed = aes_gcm_encrypt(enc, key, iv, plaintext, aad);
    REQUIRE(sealed.has_value());

    sealed->ciphertext[0] ^= 0xFF;

    auto opened = aes_gcm_decrypt(enc, key, iv, sealed->ciphertext,
                                  aad, sealed->tag);
    REQUIRE_FALSE(opened.has_value());
}

TEST_CASE("AES-GCM wrong key", "[encryption][aes-gcm]") {
    auto enc = content_encryption::A256GCM;
    auto key = generate_cek(enc).value();
    auto wrong_key = generate_cek(enc).value();
    auto iv  = generate_iv(enc).value();
    auto plaintext = make_plaintext("wrong key test");
    auto aad = make_plaintext("aad");

    auto sealed = aes_gcm_encrypt(enc, key, iv, plaintext, aad);
    REQUIRE(sealed.has_value());

    auto opened = aes_gcm_decrypt(enc, wrong_key, iv, sealed->ciphertext,
                                  aad, sealed->tag);
    REQUIRE_FALSE(opened.has_value());
}

// ---------------------------------------------------------------------------
// Unified encrypt/decrypt
// ---------------------------------------------------------------------------

TEST_CASE("unified encrypt/decrypt covers every algorithm", "[encryption][unified]") {
    auto plaintext = make_plaintext("unified API payload");
    auto aad = make_plaintext("protected header");

    for (auto enc : {content_encryption::A128CBC_HS256,
                     content_encryption::A192CBC_HS384,
                     content_encryption::A256CBC_HS512,
                     content_encryption::A128GCM,
                     content_encryption::A192GCM,
                     content_encryption::A256GCM}) {
        auto cek = generate_cek(enc).value();
        auto iv  = generate_iv(enc).value();
        REQUIRE(cek.size() == cek_byte_size(enc));
        REQUIRE(iv.size() == iv_byte_size(enc));

        auto sealed = encrypt(enc, cek, iv, plaintext, aad);
        REQUIRE(sealed.has_value());
        REQUIRE(sealed->tag.size() == tag_byte_size(enc));

        auto opened = decrypt(enc, cek, iv, sealed->ciphertext, aad, sealed->tag);
        REQUIRE(opened.has_value());
        REQUIRE(std::equal(opened->begin(), opened->end(),
                           plaintext.begin(), plaintext.end()));

        // Tampering with the AAD must fail authentication
        auto bad_aad = make_plaintext("tampered header");
        auto tampered = decrypt(enc, cek, iv, sealed->ciphertext, bad_aad,
                                sealed->tag);
        REQUIRE_FALSE(tampered.has_value());
    }
}

TEST_CASE("unified encrypt/decrypt handles empty plaintext and AAD",
          "[encryption][unified]") {
    for (auto enc : {content_encryption::A128CBC_HS256,
                     content_encryption::A128GCM}) {
        auto cek = generate_cek(enc).value();
        auto iv  = generate_iv(enc).value();

        auto sealed = encrypt(enc, cek, iv, {}, {});
        REQUIRE(sealed.has_value());

        auto opened = decrypt(enc, cek, iv, sealed->ciphertext, {}, sealed->tag);
        REQUIRE(opened.has_value());
        REQUIRE(opened->empty());
    }
}

// ---------------------------------------------------------------------------
// AES Key Wrap
// ---------------------------------------------------------------------------

TEST_CASE("AES Key Wrap round-trip", "[encryption][aes-kw]") {
    struct { key_algorithm alg; size_t kek_len; } cases[] = {
        {key_algorithm::A128KW, 16},
        {key_algorithm::A192KW, 24},
        {key_algorithm::A256KW, 32},
    };

    for (auto [alg, kek_len] : cases) {
        DYNAMIC_SECTION(to_string(alg)) {
            auto kek = random_bytes(kek_len).value();
            auto cek = random_bytes(kek_len).value();

            auto wrapped = aes_key_wrap(alg, kek, cek);
            REQUIRE(wrapped.has_value());
            REQUIRE(wrapped->size() == cek.size() + 8);

            auto unwrapped = aes_key_unwrap(alg, kek, *wrapped);
            REQUIRE(unwrapped.has_value());
            REQUIRE(*unwrapped == cek);

            // KEK of the wrong size for the algorithm is rejected up front.
            auto short_kek = random_bytes(kek_len - 8).value();
            REQUIRE_FALSE(aes_key_wrap(alg, short_kek, cek).has_value());
        }
    }
}

TEST_CASE("AES Key Wrap wrong KEK", "[encryption][aes-kw]") {
    auto kek = random_bytes(16).value();
    auto wrong_kek = random_bytes(16).value();
    auto cek = random_bytes(16).value();

    auto wrapped = aes_key_wrap(key_algorithm::A128KW, kek, cek);
    REQUIRE(wrapped.has_value());

    auto unwrapped = aes_key_unwrap(key_algorithm::A128KW, wrong_kek, *wrapped);
    REQUIRE_FALSE(unwrapped.has_value());
}

TEST_CASE("AES Key Wrap output is 8 bytes longer", "[encryption][aes-kw]") {
    auto kek = random_bytes(32).value();

    for (size_t cek_len : {16, 24, 32}) {
        auto cek = random_bytes(cek_len).value();
        auto wrapped = aes_key_wrap(key_algorithm::A256KW, kek, cek);
        REQUIRE(wrapped.has_value());
        REQUIRE(wrapped->size() == cek_len + 8);
    }
}

// ---------------------------------------------------------------------------
// AES-GCM Key Wrap
// ---------------------------------------------------------------------------

TEST_CASE("AES-GCM Key Wrap round-trip", "[encryption][aes-gcm-kw]") {
    struct { key_algorithm alg; size_t key_len; } cases[] = {
        {key_algorithm::A128GCMKW, 16},
        {key_algorithm::A192GCMKW, 24},
        {key_algorithm::A256GCMKW, 32},
    };

    for (auto [alg, key_len] : cases) {
        auto kek = random_bytes(key_len).value();
        auto cek = random_bytes(key_len).value();

        auto result = aes_gcm_key_wrap(alg, kek, cek);
        REQUIRE(result.has_value());
        REQUIRE(result->iv.size() == 12);
        REQUIRE(result->tag.size() == 16);

        auto unwrapped = aes_gcm_key_unwrap(alg, kek, result->encrypted_key,
                                            result->iv, result->tag);
        REQUIRE(unwrapped.has_value());
        REQUIRE(*unwrapped == cek);
    }
}

TEST_CASE("AES-GCM Key Wrap wrong KEK", "[encryption][aes-gcm-kw]") {
    auto kek = random_bytes(16).value();
    auto wrong_kek = random_bytes(16).value();
    auto cek = random_bytes(16).value();

    auto result = aes_gcm_key_wrap(key_algorithm::A128GCMKW, kek, cek);
    REQUIRE(result.has_value());

    auto unwrapped = aes_gcm_key_unwrap(key_algorithm::A128GCMKW, wrong_kek,
                                        result->encrypted_key,
                                        result->iv, result->tag);
    REQUIRE_FALSE(unwrapped.has_value());
}

// ---------------------------------------------------------------------------
// RSA key encryption
// ---------------------------------------------------------------------------

TEST_CASE("RSA-OAEP / RSA-OAEP-256 round-trip", "[encryption][rsa-kek]") {
    auto key = generate_rsa_key(2048).value();
    auto cek = random_bytes(32).value();

    for (auto alg : {key_algorithm::RSA_OAEP, key_algorithm::RSA_OAEP_256}) {
        DYNAMIC_SECTION(to_string(alg)) {
            auto ek = rsa_encrypt_key(alg, key.get(), cek);
            REQUIRE(ek.has_value());
            REQUIRE(ek->size() == 256);

            auto back = rsa_decrypt_key(alg, key.get(), *ek, cek.size());
            REQUIRE(back.has_value());
            REQUIRE(*back == cek);

            // Randomized: encrypting twice gives different ciphertexts.
            auto ek2 = rsa_encrypt_key(alg, key.get(), cek);
            REQUIRE(ek2.has_value());
            REQUIRE(*ek2 != *ek);
        }
    }
}

TEST_CASE("RSA-OAEP failures are explicit errors", "[encryption][rsa-kek]") {
    auto key = generate_rsa_key(2048).value();
    auto cek = random_bytes(32).value();
    auto ek = rsa_encrypt_key(key_algorithm::RSA_OAEP_256, key.get(), cek).value();

    SECTION("tampered ciphertext") {
        auto bad = ek;
        bad[10] ^= 0x01;
        auto r = rsa_decrypt_key(key_algorithm::RSA_OAEP_256, key.get(), bad, cek.size());
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().code == errc::decryption_failed);
    }

    SECTION("OAEP-256 ciphertext does not decrypt as OAEP (SHA-1)") {
        auto r = rsa_decrypt_key(key_algorithm::RSA_OAEP, key.get(), ek, cek.size());
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().code == errc::decryption_failed);
    }

    SECTION("decrypted key of the wrong length") {
        auto r = rsa_decrypt_key(key_algorithm::RSA_OAEP_256, key.get(), ek, 16);
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().code == errc::decryption_failed);
    }

    SECTION("wrong private key") {
        auto other = generate_rsa_key(2048).value();
        auto r = rsa_decrypt_key(key_algorithm::RSA_OAEP_256, other.get(), ek, cek.size());
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().code == errc::decryption_failed);
    }

    SECTION("no stale OpenSSL error is left behind") {
        auto bad = ek;
        bad[0] ^= 0x01;
        (void)rsa_decrypt_key(key_algorithm::RSA_OAEP_256, key.get(), bad, cek.size());
        REQUIRE(ERR_peek_error() == 0);
    }
}

TEST_CASE("RSA key encryption rejects bad keys and arguments", "[encryption][rsa-kek]") {
    auto cek = random_bytes(32).value();

    SECTION("non-RSA key") {
        auto ec = generate_ec_key(ec_curve::P256).value();
        auto r = rsa_encrypt_key(key_algorithm::RSA_OAEP, ec.get(), cek);
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().code == errc::invalid_key);
    }

    SECTION("RSA key below 2048 bits") {
        auto ctx = make_evp_pkey_ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
        REQUIRE(EVP_PKEY_keygen_init(ctx.get()) == 1);
        REQUIRE(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 1024) == 1);
        EVP_PKEY* raw = nullptr;
        REQUIRE(EVP_PKEY_keygen(ctx.get(), &raw) == 1);
        auto weak = make_evp_pkey_ptr(raw);

        auto r = rsa_encrypt_key(key_algorithm::RSA_OAEP, weak.get(), cek);
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().code == errc::key_size_too_small);
    }

    SECTION("non-RSA algorithm") {
        auto key = generate_rsa_key(2048).value();
        auto r = rsa_encrypt_key(key_algorithm::A128KW, key.get(), cek);
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().code == errc::unsupported_algorithm);
    }

    SECTION("zero expected CEK length") {
        auto key = generate_rsa_key(2048).value();
        auto ek = rsa_encrypt_key(key_algorithm::RSA_OAEP, key.get(), cek).value();
        auto r = rsa_decrypt_key(key_algorithm::RSA_OAEP, key.get(), ek, 0);
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().code == errc::invalid_argument);
    }
}

TEST_CASE("RSA1_5 requires explicit opt-in", "[encryption][rsa-kek][legacy]") {
    auto key = generate_rsa_key(2048).value();
    auto cek = random_bytes(32).value();
    const legacy_options allow{.allow_rsa1_5 = true};

    SECTION("encrypt refused by default") {
        auto r = rsa_encrypt_key(key_algorithm::RSA1_5, key.get(), cek);
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().code == errc::legacy_algorithm_disabled);
    }

    SECTION("decrypt refused by default") {
        auto ek = rsa_encrypt_key(key_algorithm::RSA1_5, key.get(), cek, allow).value();
        auto r = rsa_decrypt_key(key_algorithm::RSA1_5, key.get(), ek, cek.size());
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().code == errc::legacy_algorithm_disabled);
    }

    SECTION("round-trip with opt-in") {
        auto ek = rsa_encrypt_key(key_algorithm::RSA1_5, key.get(), cek, allow);
        REQUIRE(ek.has_value());
        auto back = rsa_decrypt_key(key_algorithm::RSA1_5, key.get(), *ek, cek.size(), allow);
        REQUIRE(back.has_value());
        REQUIRE(*back == cek);
    }
}

TEST_CASE("RSA1_5 decryption failure is indistinguishable", "[encryption][rsa-kek][legacy]") {
    // Bleichenbacher countermeasure: bad padding or a wrong-length key must
    // yield a random CEK of the expected length, not an error.
    auto key = generate_rsa_key(2048).value();
    auto cek = random_bytes(32).value();
    const legacy_options allow{.allow_rsa1_5 = true};
    auto ek = rsa_encrypt_key(key_algorithm::RSA1_5, key.get(), cek, allow).value();

    SECTION("corrupted ciphertext") {
        auto bad = ek;
        bad[5] ^= 0xFF;
        auto r1 = rsa_decrypt_key(key_algorithm::RSA1_5, key.get(), bad, cek.size(), allow);
        REQUIRE(r1.has_value());
        REQUIRE(r1->size() == cek.size());
        REQUIRE(*r1 != cek);
        REQUIRE(ERR_peek_error() == 0);
    }

    SECTION("valid padding but wrong CEK length") {
        auto r = rsa_decrypt_key(key_algorithm::RSA1_5, key.get(), ek, 16, allow);
        REQUIRE(r.has_value());
        REQUIRE(r->size() == 16);
        REQUIRE(!std::equal(r->begin(), r->end(), cek.begin()));
    }

    SECTION("substitute key is fresh each time") {
        auto bad = ek;
        bad[5] ^= 0xFF;
        auto r1 = rsa_decrypt_key(key_algorithm::RSA1_5, key.get(), bad, cek.size(), allow);
        auto r2 = rsa_decrypt_key(key_algorithm::RSA1_5, key.get(), bad, cek.size(), allow);
        REQUIRE(r1.has_value());
        REQUIRE(r2.has_value());
        REQUIRE(*r1 != *r2);
    }
}

// ---------------------------------------------------------------------------
// ECDH-ES
// ---------------------------------------------------------------------------

TEST_CASE("ECDH-ES key agreement on every curve", "[encryption][ecdh]") {
    struct curve_case {
        const char* name;
        evp_pkey_ptr (*make)();
    };
    const curve_case curves[] = {
        {"P-256", [] { return generate_ec_key(ec_curve::P256).value(); }},
        {"P-384", [] { return generate_ec_key(ec_curve::P384).value(); }},
        {"P-521", [] { return generate_ec_key(ec_curve::P521).value(); }},
        {"X25519", [] { return generate_okp_key(okp_curve::X25519).value(); }},
        {"X448", [] { return generate_okp_key(okp_curve::X448).value(); }},
    };

    for (const auto& curve : curves) {
        DYNAMIC_SECTION(curve.name) {
            auto recipient_key = curve.make();

            // 512 bits exercises a multi-round Concat KDF.
            for (size_t key_bits : {128, 256, 512}) {
                auto enc_result = ecdh_derive_key(recipient_key.get(), "ECDH-ES",
                                                  "alice", "bob", key_bits);
                REQUIRE(enc_result.has_value());
                REQUIRE(enc_result->derived_key.size() == key_bits / 8);
                REQUIRE(enc_result->ephemeral_key.get() != nullptr);
                REQUIRE(EVP_PKEY_base_id(enc_result->ephemeral_key.get()) ==
                        EVP_PKEY_base_id(recipient_key.get()));

                auto dec_result = ecdh_derive_key_from_epk(
                    recipient_key.get(), enc_result->ephemeral_key.get(),
                    "ECDH-ES", "alice", "bob", key_bits);
                REQUIRE(dec_result.has_value());
                REQUIRE(*dec_result == enc_result->derived_key);

                // Different PartyVInfo must yield a different key.
                auto other = ecdh_derive_key_from_epk(
                    recipient_key.get(), enc_result->ephemeral_key.get(),
                    "ECDH-ES", "alice", "eve", key_bits);
                REQUIRE(other.has_value());
                REQUIRE(*other != enc_result->derived_key);
            }
        }
    }
}

TEST_CASE("ECDH-ES rejects mismatched curves", "[encryption][ecdh]") {
    auto p256 = generate_ec_key(ec_curve::P256).value();
    auto p384 = generate_ec_key(ec_curve::P384).value();
    auto x25519 = generate_okp_key(okp_curve::X25519).value();

    REQUIRE_FALSE(ecdh_derive_key_from_epk(p256.get(), p384.get(), "ECDH-ES",
                                           "", "", 128).has_value());
    REQUIRE_FALSE(ecdh_derive_key_from_epk(p256.get(), x25519.get(), "ECDH-ES",
                                           "", "", 128).has_value());
}

TEST_CASE("ECDH-ES derived key length matches request", "[encryption][ecdh]") {
    auto key = generate_ec_key(ec_curve::P256).value();

    for (size_t bits : {128, 192, 256}) {
        auto result = ecdh_derive_key(key.get(), "ECDH-ES", "", "", bits);
        REQUIRE(result.has_value());
        REQUIRE(result->derived_key.size() == bits / 8);
    }
}

// ---------------------------------------------------------------------------
// PBES2
// ---------------------------------------------------------------------------

TEST_CASE("PBES2 round-trip", "[encryption][pbes2]") {
    auto cek = random_bytes(32).value();
    std::string_view password = "correct-horse-battery-staple";

    for (auto alg : {key_algorithm::PBES2_HS256_A128KW,
                     key_algorithm::PBES2_HS384_A192KW,
                     key_algorithm::PBES2_HS512_A256KW}) {
        DYNAMIC_SECTION(to_string(alg)) {
            auto wrap_result = pbes2_key_wrap(alg, password, cek, 1000);
            REQUIRE(wrap_result.has_value());
            REQUIRE(wrap_result->p2s.size() >= 8);
            REQUIRE(wrap_result->p2c == 1000);

            auto unwrapped = pbes2_key_unwrap(alg, password,
                                              wrap_result->encrypted_key,
                                              wrap_result->p2s,
                                              wrap_result->p2c);
            REQUIRE(unwrapped.has_value());
            REQUIRE(*unwrapped == cek);
        }
    }
}

TEST_CASE("PBES2 wrong password", "[encryption][pbes2]") {
    auto cek = random_bytes(16).value();

    auto wrap_result = pbes2_key_wrap(key_algorithm::PBES2_HS256_A128KW,
                                      "right-password", cek, 1000);
    REQUIRE(wrap_result.has_value());

    auto unwrapped = pbes2_key_unwrap(key_algorithm::PBES2_HS256_A128KW,
                                      "wrong-password",
                                      wrap_result->encrypted_key,
                                      wrap_result->p2s,
                                      wrap_result->p2c);
    REQUIRE_FALSE(unwrapped.has_value());
}

TEST_CASE("PBES2 iteration count bounds", "[encryption][pbes2]") {
    auto cek = random_bytes(16).value();
    std::string_view password = "pw";

    SECTION("wrap rejects too few iterations") {
        auto result = pbes2_key_wrap(key_algorithm::PBES2_HS256_A128KW,
                                     password, cek, 999);
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("unwrap rejects attacker-sized p2c") {
        auto wrapped = pbes2_key_wrap(key_algorithm::PBES2_HS256_A128KW,
                                      password, cek, 1000);
        REQUIRE(wrapped.has_value());

        auto result = pbes2_key_unwrap(key_algorithm::PBES2_HS256_A128KW,
                                       password,
                                       wrapped->encrypted_key,
                                       wrapped->p2s,
                                       50'000'000); // DoS-sized
        REQUIRE_FALSE(result.has_value());
    }
}
