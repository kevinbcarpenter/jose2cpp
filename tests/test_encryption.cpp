#include <catch2/catch_test_macros.hpp>

#include "jose/algorithm.hpp"
#include "jose/crypto/aes_cbc_hmac.hpp"
#include "jose/crypto/aes_gcm.hpp"
#include "jose/crypto/aes_kw.hpp"
#include "jose/crypto/aes_gcm_kw.hpp"
#include "jose/crypto/ecdh.hpp"
#include "jose/crypto/pbes2.hpp"
#include "jose/crypto/openssl_util.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

using namespace jose;

namespace {

auto rand_bytes(size_t len) -> secure_bytes {
    secure_bytes buf(len);
    RAND_bytes(buf.data(), static_cast<int>(len));
    return buf;
}

auto make_plaintext(std::string_view s) -> std::vector<uint8_t> {
    return {s.begin(), s.end()};
}

auto generate_ec_key(const char* group_name) -> evp_pkey_ptr {
    auto ctx = make_evp_pkey_ctx(
        EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    EVP_PKEY_keygen_init(ctx.get());
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(
            "group", const_cast<char*>(group_name), 0),
        OSSL_PARAM_construct_end()
    };
    EVP_PKEY_CTX_set_params(ctx.get(), params);
    EVP_PKEY* raw = nullptr;
    EVP_PKEY_keygen(ctx.get(), &raw);
    return make_evp_pkey_ptr(raw);
}

auto generate_x25519_key() -> evp_pkey_ptr {
    auto ctx = make_evp_pkey_ctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr));
    EVP_PKEY_keygen_init(ctx.get());
    EVP_PKEY* raw = nullptr;
    EVP_PKEY_keygen(ctx.get(), &raw);
    return make_evp_pkey_ptr(raw);
}

} // namespace

// ---------------------------------------------------------------------------
// AES-CBC-HMAC
// ---------------------------------------------------------------------------

TEST_CASE("AES-CBC-HMAC round-trip", "[encryption][aes-cbc-hmac]") {
    auto plaintext = make_plaintext("The quick brown fox jumps over the lazy dog");
    auto aad = make_plaintext("authenticated-but-not-encrypted");

    SECTION("A128CBC-HS256") {
        auto enc = content_encryption::A128CBC_HS256;
        auto cek = rand_bytes(cek_byte_size(enc));
        auto iv  = rand_bytes(iv_byte_size(enc));

        auto enc_result = aes_cbc_hmac_encrypt(enc, to_span(cek), to_span(iv),
                                               plaintext, aad);
        REQUIRE(enc_result.has_value());
        auto& [ciphertext, tag] = *enc_result;

        auto dec_result = aes_cbc_hmac_decrypt(enc, to_span(cek), to_span(iv),
                                               to_span(ciphertext), aad,
                                               to_span(tag));
        REQUIRE(dec_result.has_value());
        REQUIRE(std::equal(dec_result->begin(), dec_result->end(),
                           plaintext.begin(), plaintext.end()));
    }

    SECTION("A256CBC-HS512") {
        auto enc = content_encryption::A256CBC_HS512;
        auto cek = rand_bytes(cek_byte_size(enc));
        auto iv  = rand_bytes(iv_byte_size(enc));

        auto enc_result = aes_cbc_hmac_encrypt(enc, to_span(cek), to_span(iv),
                                               plaintext, aad);
        REQUIRE(enc_result.has_value());
        auto& [ciphertext, tag] = *enc_result;

        auto dec_result = aes_cbc_hmac_decrypt(enc, to_span(cek), to_span(iv),
                                               to_span(ciphertext), aad,
                                               to_span(tag));
        REQUIRE(dec_result.has_value());
        REQUIRE(std::equal(dec_result->begin(), dec_result->end(),
                           plaintext.begin(), plaintext.end()));
    }
}

TEST_CASE("AES-CBC-HMAC tampered ciphertext", "[encryption][aes-cbc-hmac]") {
    auto enc = content_encryption::A128CBC_HS256;
    auto cek = rand_bytes(cek_byte_size(enc));
    auto iv  = rand_bytes(iv_byte_size(enc));
    auto plaintext = make_plaintext("sensitive data");
    auto aad = make_plaintext("header");

    auto enc_result = aes_cbc_hmac_encrypt(enc, to_span(cek), to_span(iv),
                                           plaintext, aad);
    REQUIRE(enc_result.has_value());
    auto [ciphertext, tag] = std::move(*enc_result);

    // Flip a byte in the ciphertext
    ciphertext[0] ^= 0xFF;

    auto dec_result = aes_cbc_hmac_decrypt(enc, to_span(cek), to_span(iv),
                                           to_span(ciphertext), aad,
                                           to_span(tag));
    REQUIRE_FALSE(dec_result.has_value());
}

TEST_CASE("AES-CBC-HMAC wrong CEK", "[encryption][aes-cbc-hmac]") {
    auto enc = content_encryption::A128CBC_HS256;
    auto cek = rand_bytes(cek_byte_size(enc));
    auto wrong_cek = rand_bytes(cek_byte_size(enc));
    auto iv  = rand_bytes(iv_byte_size(enc));
    auto plaintext = make_plaintext("secret");
    auto aad = make_plaintext("aad");

    auto enc_result = aes_cbc_hmac_encrypt(enc, to_span(cek), to_span(iv),
                                           plaintext, aad);
    REQUIRE(enc_result.has_value());
    auto& [ciphertext, tag] = *enc_result;

    auto dec_result = aes_cbc_hmac_decrypt(enc, to_span(wrong_cek), to_span(iv),
                                           to_span(ciphertext), aad,
                                           to_span(tag));
    REQUIRE_FALSE(dec_result.has_value());
}

// ---------------------------------------------------------------------------
// AES-GCM
// ---------------------------------------------------------------------------

TEST_CASE("AES-GCM round-trip", "[encryption][aes-gcm]") {
    auto plaintext = make_plaintext("Hello, AES-GCM encryption!");
    auto aad = make_plaintext("additional data");

    SECTION("A128GCM") {
        auto enc = content_encryption::A128GCM;
        auto key = rand_bytes(cek_byte_size(enc));
        auto iv  = rand_bytes(iv_byte_size(enc));

        auto enc_result = aes_gcm_encrypt(enc, to_span(key), to_span(iv),
                                          plaintext, aad);
        REQUIRE(enc_result.has_value());
        auto& [ciphertext, tag] = *enc_result;

        auto dec_result = aes_gcm_decrypt(enc, to_span(key), to_span(iv),
                                          to_span(ciphertext), aad,
                                          to_span(tag));
        REQUIRE(dec_result.has_value());
        REQUIRE(std::equal(dec_result->begin(), dec_result->end(),
                           plaintext.begin(), plaintext.end()));
    }

    SECTION("A256GCM") {
        auto enc = content_encryption::A256GCM;
        auto key = rand_bytes(cek_byte_size(enc));
        auto iv  = rand_bytes(iv_byte_size(enc));

        auto enc_result = aes_gcm_encrypt(enc, to_span(key), to_span(iv),
                                          plaintext, aad);
        REQUIRE(enc_result.has_value());
        auto& [ciphertext, tag] = *enc_result;

        auto dec_result = aes_gcm_decrypt(enc, to_span(key), to_span(iv),
                                          to_span(ciphertext), aad,
                                          to_span(tag));
        REQUIRE(dec_result.has_value());
        REQUIRE(std::equal(dec_result->begin(), dec_result->end(),
                           plaintext.begin(), plaintext.end()));
    }
}

TEST_CASE("AES-GCM tampered ciphertext", "[encryption][aes-gcm]") {
    auto enc = content_encryption::A128GCM;
    auto key = rand_bytes(cek_byte_size(enc));
    auto iv  = rand_bytes(iv_byte_size(enc));
    auto plaintext = make_plaintext("tamper test");
    auto aad = make_plaintext("aad");

    auto enc_result = aes_gcm_encrypt(enc, to_span(key), to_span(iv),
                                      plaintext, aad);
    REQUIRE(enc_result.has_value());
    auto [ciphertext, tag] = std::move(*enc_result);

    ciphertext[0] ^= 0xFF;

    auto dec_result = aes_gcm_decrypt(enc, to_span(key), to_span(iv),
                                      to_span(ciphertext), aad,
                                      to_span(tag));
    REQUIRE_FALSE(dec_result.has_value());
}

TEST_CASE("AES-GCM wrong key", "[encryption][aes-gcm]") {
    auto enc = content_encryption::A256GCM;
    auto key = rand_bytes(cek_byte_size(enc));
    auto wrong_key = rand_bytes(cek_byte_size(enc));
    auto iv  = rand_bytes(iv_byte_size(enc));
    auto plaintext = make_plaintext("wrong key test");
    auto aad = make_plaintext("aad");

    auto enc_result = aes_gcm_encrypt(enc, to_span(key), to_span(iv),
                                      plaintext, aad);
    REQUIRE(enc_result.has_value());
    auto& [ciphertext, tag] = *enc_result;

    auto dec_result = aes_gcm_decrypt(enc, to_span(wrong_key), to_span(iv),
                                      to_span(ciphertext), aad,
                                      to_span(tag));
    REQUIRE_FALSE(dec_result.has_value());
}

// ---------------------------------------------------------------------------
// AES Key Wrap
// ---------------------------------------------------------------------------

TEST_CASE("AES Key Wrap round-trip", "[encryption][aes-kw]") {
    SECTION("A128KW") {
        auto kek = rand_bytes(16); // 128-bit KEK
        auto cek = rand_bytes(16); // 128-bit CEK

        auto wrapped = aes_key_wrap(key_algorithm::A128KW, to_span(kek),
                                    to_span(cek));
        REQUIRE(wrapped.has_value());
        REQUIRE(wrapped->size() == cek.size() + 8);

        auto unwrapped = aes_key_unwrap(key_algorithm::A128KW, to_span(kek),
                                        to_span(*wrapped));
        REQUIRE(unwrapped.has_value());
        REQUIRE(std::equal(unwrapped->begin(), unwrapped->end(),
                           cek.begin(), cek.end()));
    }

    SECTION("A256KW") {
        auto kek = rand_bytes(32); // 256-bit KEK
        auto cek = rand_bytes(32); // 256-bit CEK

        auto wrapped = aes_key_wrap(key_algorithm::A256KW, to_span(kek),
                                    to_span(cek));
        REQUIRE(wrapped.has_value());
        REQUIRE(wrapped->size() == cek.size() + 8);

        auto unwrapped = aes_key_unwrap(key_algorithm::A256KW, to_span(kek),
                                        to_span(*wrapped));
        REQUIRE(unwrapped.has_value());
        REQUIRE(std::equal(unwrapped->begin(), unwrapped->end(),
                           cek.begin(), cek.end()));
    }
}

TEST_CASE("AES Key Wrap wrong KEK", "[encryption][aes-kw]") {
    auto kek = rand_bytes(16);
    auto wrong_kek = rand_bytes(16);
    auto cek = rand_bytes(16);

    auto wrapped = aes_key_wrap(key_algorithm::A128KW, to_span(kek),
                                to_span(cek));
    REQUIRE(wrapped.has_value());

    auto unwrapped = aes_key_unwrap(key_algorithm::A128KW, to_span(wrong_kek),
                                    to_span(*wrapped));
    REQUIRE_FALSE(unwrapped.has_value());
}

TEST_CASE("AES Key Wrap output is 8 bytes longer", "[encryption][aes-kw]") {
    auto kek = rand_bytes(32);

    for (size_t cek_len : {16, 24, 32}) {
        auto cek = rand_bytes(cek_len);
        auto wrapped = aes_key_wrap(key_algorithm::A256KW, to_span(kek),
                                    to_span(cek));
        REQUIRE(wrapped.has_value());
        REQUIRE(wrapped->size() == cek_len + 8);
    }
}

// ---------------------------------------------------------------------------
// AES-GCM Key Wrap
// ---------------------------------------------------------------------------

TEST_CASE("AES-GCM Key Wrap round-trip", "[encryption][aes-gcm-kw]") {
    SECTION("A128GCMKW") {
        auto kek = rand_bytes(16);
        auto cek = rand_bytes(16);

        auto result = aes_gcm_key_wrap(key_algorithm::A128GCMKW, to_span(kek),
                                       to_span(cek));
        REQUIRE(result.has_value());
        REQUIRE(result->iv.size() == 12);
        REQUIRE(result->tag.size() == 16);

        auto unwrapped = aes_gcm_key_unwrap(key_algorithm::A128GCMKW,
                                            to_span(kek),
                                            to_span(result->encrypted_key),
                                            to_span(result->iv),
                                            to_span(result->tag));
        REQUIRE(unwrapped.has_value());
        REQUIRE(std::equal(unwrapped->begin(), unwrapped->end(),
                           cek.begin(), cek.end()));
    }

    SECTION("A256GCMKW") {
        auto kek = rand_bytes(32);
        auto cek = rand_bytes(32);

        auto result = aes_gcm_key_wrap(key_algorithm::A256GCMKW, to_span(kek),
                                       to_span(cek));
        REQUIRE(result.has_value());
        REQUIRE(result->iv.size() == 12);
        REQUIRE(result->tag.size() == 16);

        auto unwrapped = aes_gcm_key_unwrap(key_algorithm::A256GCMKW,
                                            to_span(kek),
                                            to_span(result->encrypted_key),
                                            to_span(result->iv),
                                            to_span(result->tag));
        REQUIRE(unwrapped.has_value());
        REQUIRE(std::equal(unwrapped->begin(), unwrapped->end(),
                           cek.begin(), cek.end()));
    }
}

TEST_CASE("AES-GCM Key Wrap wrong KEK", "[encryption][aes-gcm-kw]") {
    auto kek = rand_bytes(16);
    auto wrong_kek = rand_bytes(16);
    auto cek = rand_bytes(16);

    auto result = aes_gcm_key_wrap(key_algorithm::A128GCMKW, to_span(kek),
                                   to_span(cek));
    REQUIRE(result.has_value());

    auto unwrapped = aes_gcm_key_unwrap(key_algorithm::A128GCMKW,
                                        to_span(wrong_kek),
                                        to_span(result->encrypted_key),
                                        to_span(result->iv),
                                        to_span(result->tag));
    REQUIRE_FALSE(unwrapped.has_value());
}

// ---------------------------------------------------------------------------
// ECDH-ES
// ---------------------------------------------------------------------------

TEST_CASE("ECDH-ES P-256 key agreement", "[encryption][ecdh]") {
    auto recipient_key = generate_ec_key("P-256");
    REQUIRE(recipient_key.get() != nullptr);

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
    REQUIRE(std::equal(dec_result->begin(), dec_result->end(),
                       enc_result->derived_key.begin(),
                       enc_result->derived_key.end()));
}

TEST_CASE("ECDH-ES X25519 key agreement", "[encryption][ecdh]") {
    auto recipient_key = generate_x25519_key();
    REQUIRE(recipient_key.get() != nullptr);

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
    REQUIRE(std::equal(dec_result->begin(), dec_result->end(),
                       enc_result->derived_key.begin(),
                       enc_result->derived_key.end()));
}

TEST_CASE("ECDH-ES derived key length matches request", "[encryption][ecdh]") {
    auto key = generate_ec_key("P-256");

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
    auto cek = rand_bytes(16);
    std::string_view password = "correct-horse-battery-staple";

    auto wrap_result = pbes2_key_wrap(key_algorithm::PBES2_HS256_A128KW,
                                     password, to_span(cek), 1000);
    REQUIRE(wrap_result.has_value());
    REQUIRE(wrap_result->p2s.size() >= 8);
    REQUIRE(wrap_result->p2c == 1000);

    auto unwrapped = pbes2_key_unwrap(key_algorithm::PBES2_HS256_A128KW,
                                      password,
                                      to_span(wrap_result->encrypted_key),
                                      to_span(wrap_result->p2s),
                                      wrap_result->p2c);
    REQUIRE(unwrapped.has_value());
    REQUIRE(std::equal(unwrapped->begin(), unwrapped->end(),
                       cek.begin(), cek.end()));
}

TEST_CASE("PBES2 wrong password", "[encryption][pbes2]") {
    auto cek = rand_bytes(16);

    auto wrap_result = pbes2_key_wrap(key_algorithm::PBES2_HS256_A128KW,
                                     "right-password", to_span(cek), 1000);
    REQUIRE(wrap_result.has_value());

    auto unwrapped = pbes2_key_unwrap(key_algorithm::PBES2_HS256_A128KW,
                                      "wrong-password",
                                      to_span(wrap_result->encrypted_key),
                                      to_span(wrap_result->p2s),
                                      wrap_result->p2c);
    REQUIRE_FALSE(unwrapped.has_value());
}
