// Known-answer tests against published RFC test vectors.
//
// Vectors live in tests/vectors/*.json and are extracted directly from the
// RFC texts by tests/vectors/generator/gen_vectors.py; each case records its
// "source" section. Sources: RFC 3394, 7515, 7517, 7518, 7520, 8032, 8037.

#include <catch2/catch_test_macros.hpp>

#include "jose/jose.hpp"
#include "support/test_support.hpp"

#include <openssl/evp.h>

#include <array>
#include <string>
#include <vector>

using namespace jose;
using jose::test::b64;
using jose::test::b64_string;
using jose::test::key_from_jwk;
using jose::test::load_vectors;

namespace {

auto as_vec(const secure_bytes& s) -> std::vector<uint8_t> {
    return {s.begin(), s.end()};
}

auto is_hmac(signing_algorithm alg) -> bool {
    return alg == signing_algorithm::HS256 || alg == signing_algorithm::HS384 ||
           alg == signing_algorithm::HS512;
}

auto flip_last_bit(std::vector<uint8_t> v) -> std::vector<uint8_t> {
    v.back() ^= 0x01;
    return v;
}

// Independent single-round Concat KDF (keydatalen <= 256), used to check
// cases where the RFC publishes only the shared secret Z (RFC 8037 A.6/A.7).
auto reference_concat_kdf(const std::vector<uint8_t>& z, const std::string& alg,
                          const std::string& apu, const std::string& apv,
                          uint32_t keydatalen) -> std::vector<uint8_t> {
    REQUIRE(keydatalen <= 256);
    std::vector<uint8_t> in;
    auto be32 = [&](uint32_t v) {
        for (int shift = 24; shift >= 0; shift -= 8)
            in.push_back(static_cast<uint8_t>(v >> shift));
    };
    auto field = [&](const std::string& s) {
        be32(static_cast<uint32_t>(s.size()));
        in.insert(in.end(), s.begin(), s.end());
    };
    be32(1);
    in.insert(in.end(), z.begin(), z.end());
    field(alg);
    field(apu);
    field(apv);
    be32(keydatalen);

    std::array<uint8_t, 32> digest{};
    unsigned int len = 0;
    REQUIRE(EVP_Digest(in.data(), in.size(), digest.data(), &len, EVP_sha256(),
                       nullptr) == 1);
    return {digest.begin(), digest.begin() + keydatalen / 8};
}

} // namespace

// ---------------------------------------------------------------------------
// Signatures: RFC 7515 App. A, RFC 7520 §4, RFC 8037 App. A.4, RFC 8032 §7.4
// ---------------------------------------------------------------------------

TEST_CASE("RFC signature vectors", "[vectors][signing]") {
    for (const auto& c : load_vectors("signatures")) {
        DYNAMIC_SECTION(c["source"].get<std::string>() << " " << c["alg"].get<std::string>()) {
            auto alg = parse_signing_algorithm(c["alg"].get<std::string>());
            REQUIRE(alg.has_value());
            const auto message = b64(c["message"]);
            const auto expected_sig = b64(c["signature"]);
            const bool deterministic = c["deterministic"].get<bool>();

            if (is_hmac(*alg)) {
                const auto key = b64(c["key"]["k"]);
                CHECK(verify(*alg, key, message, expected_sig).has_value());
                CHECK_FALSE(verify(*alg, key, message, flip_last_bit(expected_sig)).has_value());
                auto sig = sign(*alg, key, message);
                REQUIRE(sig.has_value());
                CHECK(as_vec(*sig) == expected_sig);
                continue;
            }

            auto key = key_from_jwk(c["key"]);
            CHECK(verify(*alg, key.get(), message, expected_sig).has_value());
            CHECK_FALSE(verify(*alg, key.get(), message, flip_last_bit(expected_sig)).has_value());
            CHECK_FALSE(verify(*alg, key.get(), flip_last_bit(message.empty()
                                                                  ? std::vector<uint8_t>{0}
                                                                  : message),
                               expected_sig)
                            .has_value());

            auto sig = sign(*alg, key.get(), message);
            REQUIRE(sig.has_value());
            if (deterministic) {
                // RS*, EdDSA: the signature is a pure function of key + message.
                CHECK(as_vec(*sig) == expected_sig);
            } else {
                // PS*, ES*: randomized; our own signature must still verify.
                CHECK(sig->size() == expected_sig.size());
                CHECK(verify(*alg, key.get(), message, *sig).has_value());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Content encryption: RFC 7518 App. B, RFC 7520 §5
// ---------------------------------------------------------------------------

TEST_CASE("RFC content encryption vectors", "[vectors][encryption]") {
    for (const auto& c : load_vectors("content_encryption")) {
        DYNAMIC_SECTION(c["source"].get<std::string>() << " " << c["enc"].get<std::string>()) {
            auto enc = parse_content_encryption(c["enc"].get<std::string>());
            REQUIRE(enc.has_value());
            const auto cek = b64(c["cek"]);
            const auto iv = b64(c["iv"]);
            const auto plaintext = b64(c["plaintext"]);
            const auto aad = b64(c["aad"]);
            const auto ciphertext = b64(c["ciphertext"]);
            const auto tag = b64(c["tag"]);

            auto sealed = encrypt(*enc, cek, iv, plaintext, aad);
            REQUIRE(sealed.has_value());
            CHECK(as_vec(sealed->ciphertext) == ciphertext);
            CHECK(as_vec(sealed->tag) == tag);

            auto opened = decrypt(*enc, cek, iv, ciphertext, aad, tag);
            REQUIRE(opened.has_value());
            CHECK(as_vec(*opened) == plaintext);

            CHECK_FALSE(decrypt(*enc, cek, iv, ciphertext, aad, flip_last_bit(tag)).has_value());
        }
    }
}

// ---------------------------------------------------------------------------
// AES Key Wrap: RFC 3394 §4, RFC 7520 §5.8
// ---------------------------------------------------------------------------

TEST_CASE("RFC AES key wrap vectors", "[vectors][aes-kw]") {
    for (const auto& c : load_vectors("aes_kw")) {
        DYNAMIC_SECTION(c["source"].get<std::string>() << " " << c["alg"].get<std::string>()) {
            auto alg = parse_key_algorithm(c["alg"].get<std::string>());
            REQUIRE(alg.has_value());
            const auto kek = b64(c["kek"]);
            const auto cek = b64(c["cek"]);
            const auto wrapped = b64(c["wrapped"]);

            auto out = aes_key_wrap(*alg, kek, cek);
            REQUIRE(out.has_value());
            CHECK(as_vec(*out) == wrapped);

            auto back = aes_key_unwrap(*alg, kek, wrapped);
            REQUIRE(back.has_value());
            CHECK(as_vec(*back) == cek);

            CHECK_FALSE(aes_key_unwrap(*alg, kek, flip_last_bit(wrapped)).has_value());
        }
    }
}

// ---------------------------------------------------------------------------
// AES-GCM Key Wrap: RFC 7520 §5.7
// ---------------------------------------------------------------------------

TEST_CASE("RFC AES-GCM key wrap vectors", "[vectors][aes-gcm-kw]") {
    for (const auto& c : load_vectors("aes_gcm_kw")) {
        DYNAMIC_SECTION(c["source"].get<std::string>() << " " << c["alg"].get<std::string>()) {
            auto alg = parse_key_algorithm(c["alg"].get<std::string>());
            REQUIRE(alg.has_value());
            const auto kek = b64(c["kek"]);
            const auto iv = b64(c["iv"]);
            const auto tag = b64(c["tag"]);
            const auto encrypted_key = b64(c["encrypted_key"]);
            const auto cek = b64(c["cek"]);

            auto back = aes_gcm_key_unwrap(*alg, kek, encrypted_key, iv, tag);
            REQUIRE(back.has_value());
            CHECK(as_vec(*back) == cek);

            CHECK_FALSE(aes_gcm_key_unwrap(*alg, kek, encrypted_key, iv, flip_last_bit(tag))
                            .has_value());
        }
    }
}

// ---------------------------------------------------------------------------
// RSA key encryption: RFC 7520 §5.1 (RSA1_5), §5.2 (RSA-OAEP)
// ---------------------------------------------------------------------------

TEST_CASE("RFC RSA key encryption vectors", "[vectors][rsa-kek]") {
    for (const auto& c : load_vectors("rsa_key_encryption")) {
        DYNAMIC_SECTION(c["source"].get<std::string>() << " " << c["alg"].get<std::string>()) {
            auto alg = parse_key_algorithm(c["alg"].get<std::string>());
            REQUIRE(alg.has_value());
            auto key = key_from_jwk(c["key"]);
            const auto encrypted_key = b64(c["encrypted_key"]);
            const auto cek = b64(c["cek"]);
            const legacy_options legacy{.allow_rsa1_5 = true};

            auto back = rsa_decrypt_key(*alg, key.get(), encrypted_key, cek.size(), legacy);
            REQUIRE(back.has_value());
            CHECK(as_vec(*back) == cek);

            if (*alg == key_algorithm::RSA1_5) {
                auto refused = rsa_decrypt_key(*alg, key.get(), encrypted_key, cek.size());
                REQUIRE_FALSE(refused.has_value());
                CHECK(refused.error().code == errc::legacy_algorithm_disabled);
            }

            // RSA encryption is randomized: re-encrypt and round-trip.
            auto reencrypted = rsa_encrypt_key(*alg, key.get(), cek, legacy);
            REQUIRE(reencrypted.has_value());
            CHECK(reencrypted->size() == encrypted_key.size());
            auto again = rsa_decrypt_key(*alg, key.get(), *reencrypted, cek.size(), legacy);
            REQUIRE(again.has_value());
            CHECK(as_vec(*again) == cek);
        }
    }
}

// ---------------------------------------------------------------------------
// ECDH-ES + Concat KDF: RFC 7518 App. C, RFC 7520 §5.4/§5.5, RFC 8037 A.6/A.7
// ---------------------------------------------------------------------------

TEST_CASE("RFC ECDH-ES vectors", "[vectors][ecdh]") {
    for (const auto& c : load_vectors("ecdh_es")) {
        DYNAMIC_SECTION(c["source"].get<std::string>() << " " << c["alg_id"].get<std::string>()) {
            const auto alg_id = c["alg_id"].get<std::string>();
            const auto bits = c["keydatalen"].get<size_t>();
            const auto apu = b64_string(c["apu"]);
            const auto apv = b64_string(c["apv"]);
            auto recipient = key_from_jwk(c["recipient"]);
            auto ephemeral = key_from_jwk(c["ephemeral"]);

            if (c.contains("z")) {
                // Only Z is published, and only the ephemeral private key:
                // derive from the sender side (DH is symmetric) and compare
                // with an independent KDF computation over the published Z.
                auto derived = ecdh_derive_key_from_epk(ephemeral.get(), recipient.get(),
                                                        alg_id, apu, apv, bits);
                REQUIRE(derived.has_value());
                CHECK(as_vec(*derived) ==
                      reference_concat_kdf(b64(c["z"]), alg_id, apu, apv,
                                           static_cast<uint32_t>(bits)));
                continue;
            }

            // Recipient side: recipient private key + ephemeral public key.
            auto derived = ecdh_derive_key_from_epk(recipient.get(), ephemeral.get(),
                                                    alg_id, apu, apv, bits);
            REQUIRE(derived.has_value());
            REQUIRE(derived->size() == bits / 8);

            if (c.contains("derived_key")) {
                CHECK(as_vec(*derived) == b64(c["derived_key"]));
            } else {
                // ECDH-ES+A*KW: the derived key is the KEK for the CEK.
                auto kw = parse_key_algorithm(c["kw_alg"].get<std::string>());
                REQUIRE(kw.has_value());
                auto cek = aes_key_unwrap(*kw, *derived, b64(c["encrypted_key"]));
                REQUIRE(cek.has_value());
                CHECK(as_vec(*cek) == b64(c["cek"]));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PBES2: RFC 7517 App. C (HS256+A128KW), RFC 7520 §5.3 (HS512+A256KW)
// ---------------------------------------------------------------------------

TEST_CASE("RFC PBES2 vectors", "[vectors][pbes2]") {
    for (const auto& c : load_vectors("pbes2")) {
        DYNAMIC_SECTION(c["source"].get<std::string>() << " " << c["alg"].get<std::string>()) {
            auto alg = parse_key_algorithm(c["alg"].get<std::string>());
            REQUIRE(alg.has_value());
            const auto password = b64_string(c["password"]);

            auto cek = pbes2_key_unwrap(*alg, password, b64(c["encrypted_key"]),
                                        b64(c["p2s"]), c["p2c"].get<int>());
            REQUIRE(cek.has_value());
            CHECK(as_vec(*cek) == b64(c["cek"]));

            CHECK_FALSE(pbes2_key_unwrap(*alg, password + "x", b64(c["encrypted_key"]),
                                         b64(c["p2s"]), c["p2c"].get<int>())
                            .has_value());
        }
    }
}
