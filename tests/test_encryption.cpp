#include <catch2/catch_test_macros.hpp>

#include "jose/jose.hpp"

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
    SECTION("A128KW") {
        auto kek = random_bytes(16).value();
        auto cek = random_bytes(16).value();

        auto wrapped = aes_key_wrap(key_algorithm::A128KW, kek, cek);
        REQUIRE(wrapped.has_value());
        REQUIRE(wrapped->size() == cek.size() + 8);

        auto unwrapped = aes_key_unwrap(key_algorithm::A128KW, kek, *wrapped);
        REQUIRE(unwrapped.has_value());
        REQUIRE(*unwrapped == cek);
    }

    SECTION("A256KW") {
        auto kek = random_bytes(32).value();
        auto cek = random_bytes(32).value();

        auto wrapped = aes_key_wrap(key_algorithm::A256KW, kek, cek);
        REQUIRE(wrapped.has_value());
        REQUIRE(wrapped->size() == cek.size() + 8);

        auto unwrapped = aes_key_unwrap(key_algorithm::A256KW, kek, *wrapped);
        REQUIRE(unwrapped.has_value());
        REQUIRE(*unwrapped == cek);
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
// ECDH-ES
// ---------------------------------------------------------------------------

TEST_CASE("ECDH-ES P-256 key agreement", "[encryption][ecdh]") {
    auto recipient_key = generate_ec_key(ec_curve::P256).value();

    constexpr size_t key_bits = 128;
    auto enc_result = ecdh_derive_key(recipient_key.get(), "ECDH-ES",
                                      "alice", "bob", key_bits);
    REQUIRE(enc_result.has_value());
    REQUIRE(enc_result->derived_key.size() == key_bits / 8);
    REQUIRE(enc_result->ephemeral_key.get() != nullptr);

    auto dec_result = ecdh_derive_key_from_epk(recipient_key.get(),
                                               enc_result->ephemeral_key.get(),
                                               "ECDH-ES",
                                               "alice", "bob", key_bits);
    REQUIRE(dec_result.has_value());
    REQUIRE(*dec_result == enc_result->derived_key);
}

TEST_CASE("ECDH-ES X25519 key agreement", "[encryption][ecdh]") {
    auto recipient_key = generate_okp_key(okp_curve::X25519).value();

    constexpr size_t key_bits = 256;
    auto enc_result = ecdh_derive_key(recipient_key.get(), "ECDH-ES",
                                      "sender", "receiver", key_bits);
    REQUIRE(enc_result.has_value());
    REQUIRE(enc_result->derived_key.size() == key_bits / 8);

    auto dec_result = ecdh_derive_key_from_epk(recipient_key.get(),
                                               enc_result->ephemeral_key.get(),
                                               "ECDH-ES",
                                               "sender", "receiver", key_bits);
    REQUIRE(dec_result.has_value());
    REQUIRE(*dec_result == enc_result->derived_key);
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
    auto cek = random_bytes(16).value();
    std::string_view password = "correct-horse-battery-staple";

    auto wrap_result = pbes2_key_wrap(key_algorithm::PBES2_HS256_A128KW,
                                      password, cek, 1000);
    REQUIRE(wrap_result.has_value());
    REQUIRE(wrap_result->p2s.size() >= 8);
    REQUIRE(wrap_result->p2c == 1000);

    auto unwrapped = pbes2_key_unwrap(key_algorithm::PBES2_HS256_A128KW,
                                      password,
                                      wrap_result->encrypted_key,
                                      wrap_result->p2s,
                                      wrap_result->p2c);
    REQUIRE(unwrapped.has_value());
    REQUIRE(*unwrapped == cek);
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
