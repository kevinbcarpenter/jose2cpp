#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include "jose/jose.hpp"

#include <openssl/err.h>

#include <memory>
#include <string>
#include <vector>

using namespace jose;
using Catch::Matchers::ContainsSubstring;

namespace {

template <typename T>
auto must(expected<T> v) -> T {
    INFO((v ? std::string("ok") : v.error().message));
    REQUIRE(v.has_value());
    return std::move(*v);
}

auto with_kid(jwk key, std::string kid) -> jwk {
    key.set_key_id(std::move(kid));
    return key;
}

auto as_bytes(std::string_view s) -> std::vector<uint8_t> {
    return {s.begin(), s.end()};
}

// Software stand-ins for an HSM/KMS, holding a key the library never sees.

struct test_signer final : opaque_signer {
    enum class mode { normal, unavailable, der_sized, no_public_key };

    jwk key;
    std::vector<signing_algorithm> algs;
    mode behaviour = mode::normal;
    mutable int public_key_calls = 0;
    int sign_calls = 0;

    test_signer(jwk k, std::vector<signing_algorithm> a) : key(std::move(k)), algs(std::move(a)) {}

    auto public_key() const -> expected<jwk> override {
        ++public_key_calls;
        if (behaviour == mode::no_public_key) return make_error(errc::key_unavailable, "KMS GetPublicKey failed");
        return key.public_key();
    }
    auto algorithms() const -> std::vector<signing_algorithm> override { return algs; }
    auto sign(std::span<const uint8_t> input, signing_algorithm alg) -> expected<std::vector<uint8_t>> override {
        ++sign_calls;
        if (behaviour == mode::unavailable) return make_error(errc::key_unavailable, "HSM offline");
        if (behaviour == mode::der_sized) return std::vector<uint8_t>(70, 0x30);
        auto sig = jose::sign(alg, key.pkey(), input);
        if (!sig) return jose::unexpected(sig.error());
        return std::vector<uint8_t>(sig->begin(), sig->end());
    }
};

struct test_verifier final : opaque_verifier {
    enum class mode { normal, unavailable, other_error };

    jwk key;
    std::vector<signing_algorithm> algs;
    mode behaviour = mode::normal;
    int verify_calls = 0;

    test_verifier(jwk k, std::vector<signing_algorithm> a) : key(std::move(k)), algs(std::move(a)) {}

    auto algorithms() const -> std::vector<signing_algorithm> override { return algs; }
    auto verify(std::span<const uint8_t> input, std::span<const uint8_t> signature, signing_algorithm alg)
        -> expected<void> override {
        ++verify_calls;
        if (behaviour == mode::unavailable) return make_error(errc::key_unavailable, "KMS throttled");
        if (behaviour == mode::other_error) return make_error(errc::openssl_error, "backend said no");
        return key.key_type() == kty::oct ? jose::verify(alg, key.oct(), input, signature)
                                          : jose::verify(alg, key.pkey(), input, signature);
    }
};

struct test_decrypter final : opaque_key_decrypter {
    enum class mode { normal, unavailable, other_error, wrong_length };

    jwk key;
    std::vector<key_algorithm> algs;
    mode behaviour = mode::normal;
    int calls = 0;
    std::optional<header> last_header;

    test_decrypter(jwk k, std::vector<key_algorithm> a) : key(std::move(k)), algs(std::move(a)) {}

    auto algorithms() const -> std::vector<key_algorithm> override { return algs; }
    auto decrypt_key(std::span<const uint8_t> encrypted_key, key_algorithm alg, content_encryption enc,
                     const header& joined) -> expected<secure_bytes> override {
        ++calls;
        last_header = joined;
        if (behaviour == mode::unavailable) return make_error(errc::key_unavailable, "KMS unreachable");
        if (behaviour == mode::other_error) return make_error(errc::invalid_key, "KMS: InvalidCiphertextException");
        if (behaviour == mode::wrong_length) return secure_bytes(7, 0x41);

        const size_t cek_len = cek_byte_size(enc);
        switch (alg) {
        case key_algorithm::RSA_OAEP_256:
        case key_algorithm::RSA1_5:
            return rsa_decrypt_key(alg, key.pkey(), encrypted_key, cek_len, {.allow_rsa1_5 = true});
        case key_algorithm::A256KW:
            return aes_key_unwrap(alg, key.oct(), encrypted_key);
        case key_algorithm::ECDH_ES: {
            const auto& epk = joined.epk();
            if (!epk) return make_error(errc::invalid_header, "no epk");
            const auto apu = joined.apu().value_or(std::vector<uint8_t>{});
            const auto apv = joined.apv().value_or(std::vector<uint8_t>{});
            return ecdh_derive_key_from_epk(
                key.pkey(), epk->pkey(), to_string(enc),
                std::string_view(reinterpret_cast<const char*>(apu.data()), apu.size()),
                std::string_view(reinterpret_cast<const char*>(apv.data()), apv.size()), cek_len * 8);
        }
        default:
            return make_error(errc::unsupported_algorithm, "not in this test decrypter");
        }
    }
};

} // namespace

// ===========================================================================
// JWS
// ===========================================================================

TEST_CASE("an opaque signer produces ordinary JWS", "[opaque][jws]") {
    const auto key = with_kid(must(jwk::generate_ec(ec_curve::P256)), "hsm-1");
    const auto pub = must(key.public_key());
    auto hsm = std::make_shared<test_signer>(key, std::vector{signing_algorithm::ES256});

    auto signed_ = must(jws::sign("hello", {signing_algorithm::ES256, hsm}));
    CHECK(hsm->sign_calls == 1);
    const auto& sig = signed_.signatures().front();
    CHECK(sig.protected_header.kid() == "hsm-1");
    CHECK(sig.signature.size() == 64);

    // Verifiable with the plain public key, and after a round trip.
    CHECK(must(signed_.verify(pub)) == as_bytes("hello"));
    auto parsed = must(jws::parse(must(signed_.compact()), {signing_algorithm::ES256}));
    CHECK(must(parsed.verify(pub)) == as_bytes("hello"));

    SECTION("embed_jwk embeds the public key from the signer") {
        auto embedded = must(jws::sign("x", {signing_algorithm::ES256, hsm}, {.embed_jwk = true}));
        const auto& h = embedded.signatures().front().protected_header;
        REQUIRE(h.jwk());
        CHECK_FALSE(h.jwk()->is_private());
        CHECK(must(h.jwk()->thumbprint()) == must(pub.thumbprint()));
    }

    SECTION("public_key() is only asked for when needed") {
        hsm->behaviour = test_signer::mode::no_public_key;
        auto r = jws::sign("x", {signing_algorithm::ES256, hsm});
        REQUIRE_FALSE(r);
        CHECK(r.error().code == errc::key_unavailable);

        const int before = hsm->public_key_calls;
        hsm->behaviour = test_signer::mode::normal;
        auto plain = must(jws::sign("x", {signing_algorithm::ES256, hsm}, {.include_kid = false}));
        CHECK(hsm->public_key_calls == before);
        CHECK_FALSE(plain.signatures().front().protected_header.kid());
    }
}

TEST_CASE("opaque and local signers mix in one JWS", "[opaque][jws]") {
    const auto ec = with_kid(must(jwk::generate_ec(ec_curve::P384)), "kms");
    const auto rsa = with_kid(must(jwk::generate_rsa(2048)), "local");
    auto kms = std::make_shared<test_signer>(ec, std::vector{signing_algorithm::ES384, signing_algorithm::ES256});

    const std::vector<jws_signer> signers{
        {signing_algorithm::PS256, rsa},
        {signing_algorithm::ES384, kms},
    };
    const auto payload = as_bytes("two signatures");
    auto signed_ = must(jws::sign(payload, signers));
    auto parsed = must(jws::parse(must(signed_.to_json_string()),
                                  {signing_algorithm::PS256, signing_algorithm::ES384}));

    CHECK(must(parsed.verify_multi(must(rsa.public_key()))).index == 0);
    CHECK(must(parsed.verify_multi(must(ec.public_key()))).index == 1);

    test_verifier remote(must(ec.public_key()), {signing_algorithm::ES384});
    CHECK(must(parsed.verify_multi(remote)).index == 1);
    CHECK(remote.verify_calls == 1); // the PS256 signature was never offered
}

TEST_CASE("opaque signer misuse is caught", "[opaque][jws][validation]") {
    const auto key = must(jwk::generate_ec(ec_curve::P256));
    auto hsm = std::make_shared<test_signer>(key, std::vector{signing_algorithm::ES256});

    SECTION("an algorithm the signer doesn't support is refused before signing") {
        auto r = jws::sign("x", {signing_algorithm::ES384, hsm});
        REQUIRE_FALSE(r);
        CHECK(r.error().code == errc::algorithm_mismatch);
        CHECK(hsm->sign_calls == 0);
    }
    SECTION("a null signer") {
        auto r = jws::sign("x", {signing_algorithm::ES256, std::shared_ptr<opaque_signer>{}});
        REQUIRE_FALSE(r);
        CHECK(r.error().code == errc::invalid_argument);
    }
    SECTION("a DER-encoded ECDSA signature") {
        hsm->behaviour = test_signer::mode::der_sized;
        auto r = jws::sign("x", {signing_algorithm::ES256, hsm});
        REQUIRE_FALSE(r);
        CHECK(r.error().code == errc::invalid_signature);
        CHECK_THAT(r.error().message, ContainsSubstring("not DER"));
    }
    SECTION("backend errors pass through") {
        hsm->behaviour = test_signer::mode::unavailable;
        auto r = jws::sign("x", {signing_algorithm::ES256, hsm});
        REQUIRE_FALSE(r);
        CHECK(r.error().code == errc::key_unavailable);
        CHECK(r.error().message == "HSM offline");
    }
}

TEST_CASE("an opaque verifier checks JWS", "[opaque][jws]") {
    const auto secret = must(jwk::generate_oct(32));
    auto signed_ = must(jws::sign("payload", {signing_algorithm::HS256, secret}));
    auto parsed = must(jws::parse(must(signed_.compact()), {signing_algorithm::HS256}));
    test_verifier verifier(secret, {signing_algorithm::HS256});

    CHECK(must(parsed.verify(verifier)) == as_bytes("payload"));

    SECTION("a bad signature") {
        auto token = must(signed_.compact());
        {
            auto& c = token[token.size() - 5]; // inside the last part, clear of its padding bits
            c = c == 'A' ? 'B' : 'A';
        }
        auto tampered = must(jws::parse(token, {signing_algorithm::HS256}));
        auto r = tampered.verify(verifier);
        REQUIRE_FALSE(r);
        CHECK(r.error().code == errc::invalid_signature);
    }
    SECTION("an algorithm the verifier doesn't support is never offered") {
        test_verifier other(secret, {signing_algorithm::HS512});
        auto r = parsed.verify(other);
        REQUIRE_FALSE(r);
        CHECK(r.error().code == errc::algorithm_mismatch);
        CHECK(other.verify_calls == 0);
        auto m = parsed.verify_multi(other);
        REQUIRE_FALSE(m);
        CHECK(m.error().code == errc::algorithm_mismatch);
    }
    SECTION("verifier errors become invalid_signature, except key_unavailable") {
        verifier.behaviour = test_verifier::mode::other_error;
        auto r = parsed.verify(verifier);
        REQUIRE_FALSE(r);
        CHECK(r.error().code == errc::invalid_signature);

        verifier.behaviour = test_verifier::mode::unavailable;
        r = parsed.verify(verifier);
        REQUIRE_FALSE(r);
        CHECK(r.error().code == errc::key_unavailable);
        auto m = parsed.verify_multi(verifier);
        REQUIRE_FALSE(m);
        CHECK(m.error().code == errc::key_unavailable);
    }
    SECTION("verify() needs exactly one signature") {
        const std::vector<jws_signer> two{{signing_algorithm::HS256, secret}, {signing_algorithm::HS256, secret}};
        auto multi = must(jws::sign(as_bytes("p"), two));
        auto r = multi.verify(verifier);
        REQUIRE_FALSE(r);
        CHECK(r.error().code == errc::invalid_argument);
    }
}

// ===========================================================================
// JWE
// ===========================================================================

TEST_CASE("an opaque decrypter opens JWE", "[opaque][jwe]") {
    const auto plaintext = std::string_view("for the HSM's eyes only");

    SECTION("RSA-OAEP-256") {
        const auto key = must(jwk::generate_rsa(2048));
        auto sealed = must(jwe::encrypt(plaintext, content_encryption::A256GCM,
                                        {key_algorithm::RSA_OAEP_256, must(key.public_key())}));
        auto parsed = must(jwe::parse(must(sealed.compact()), {key_algorithm::RSA_OAEP_256},
                                      {content_encryption::A256GCM}));
        test_decrypter hsm(key, {key_algorithm::RSA_OAEP_256});
        auto out = must(parsed.decrypt(hsm));
        CHECK(std::string_view(reinterpret_cast<const char*>(out.data()), out.size()) == plaintext);
    }
    SECTION("ECDH-ES receives the complete header") {
        const auto key = must(jwk::generate_ec(ec_curve::P256));
        header params = must(header::from_json({{"apu", "QWxpY2U"}, {"apv", "Qm9i"}}));
        auto sealed = must(jwe::encrypt(plaintext, content_encryption::A128CBC_HS256,
                                        {key_algorithm::ECDH_ES, must(key.public_key()), params}));
        auto parsed = must(jwe::parse(must(sealed.to_json_string()), {key_algorithm::ECDH_ES},
                                      {content_encryption::A128CBC_HS256}));
        test_decrypter hsm(key, {key_algorithm::ECDH_ES});
        auto out = must(parsed.decrypt(hsm));
        CHECK(out.size() == plaintext.size());
        REQUIRE(hsm.last_header);
        CHECK(hsm.last_header->epk());
        CHECK(hsm.last_header->apu() == as_bytes("Alice"));
    }
    SECTION("multiple recipients") {
        const auto rsa = must(jwk::generate_rsa(2048));
        const auto kek = must(jwk::generate_oct(32));
        const std::vector<jwe_recipient> recipients{
            {key_algorithm::RSA_OAEP_256, must(rsa.public_key())},
            {key_algorithm::A256KW, kek},
        };
        auto sealed = must(jwe::encrypt(as_bytes(plaintext), content_encryption::A256GCM, recipients));
        auto parsed = must(jwe::parse(must(sealed.to_json_string()),
                                      {key_algorithm::RSA_OAEP_256, key_algorithm::A256KW},
                                      {content_encryption::A256GCM}));
        test_decrypter kms(kek, {key_algorithm::A256KW});
        auto r = must(parsed.decrypt_multi(kms));
        CHECK(r.index == 1);
        CHECK(kms.calls == 1); // the RSA recipient was never offered

        auto single = parsed.decrypt(kms);
        REQUIRE_FALSE(single);
        CHECK(single.error().code == errc::invalid_argument);
    }
}

TEST_CASE("opaque decrypter failures stay uniform", "[opaque][jwe][validation]") {
    const auto kek = must(jwk::generate_oct(32));
    auto sealed = must(jwe::encrypt("secret", content_encryption::A256GCM, {key_algorithm::A256KW, kek}));
    auto parsed = must(jwe::parse(must(sealed.compact()), {key_algorithm::A256KW}, {content_encryption::A256GCM}));
    test_decrypter kms(kek, {key_algorithm::A256KW});

    auto expect_failed = [](const expected<secure_bytes>& r) {
        REQUIRE_FALSE(r);
        CHECK(r.error().code == errc::decryption_failed);
        CHECK(r.error().message == "JWE decryption failed");
    };

    SECTION("a backend error becomes decryption_failed") {
        kms.behaviour = test_decrypter::mode::other_error;
        expect_failed(parsed.decrypt(kms));
        auto m = parsed.decrypt_multi(kms);
        REQUIRE_FALSE(m);
        CHECK(m.error().code == errc::decryption_failed);
    }
    SECTION("a CEK of the wrong length") {
        kms.behaviour = test_decrypter::mode::wrong_length;
        expect_failed(parsed.decrypt(kms));
    }
    SECTION("a wrong key") {
        test_decrypter other(must(jwk::generate_oct(32)), {key_algorithm::A256KW});
        expect_failed(parsed.decrypt(other));
    }
    SECTION("a tampered tag") {
        auto token = must(sealed.compact());
        {
            auto& c = token[token.size() - 5]; // inside the last part, clear of its padding bits
            c = c == 'A' ? 'B' : 'A';
        }
        auto tampered = must(jwe::parse(token, {key_algorithm::A256KW}, {content_encryption::A256GCM}));
        expect_failed(tampered.decrypt(kms));
    }
    SECTION("key_unavailable passes through") {
        kms.behaviour = test_decrypter::mode::unavailable;
        auto r = parsed.decrypt(kms);
        REQUIRE_FALSE(r);
        CHECK(r.error().code == errc::key_unavailable);
        auto m = parsed.decrypt_multi(kms);
        REQUIRE_FALSE(m);
        CHECK(m.error().code == errc::key_unavailable);
    }
    SECTION("an algorithm the decrypter doesn't support is never offered") {
        test_decrypter rsa_only(kek, {key_algorithm::RSA_OAEP_256});
        auto r = parsed.decrypt(rsa_only);
        REQUIRE_FALSE(r);
        CHECK(r.error().code == errc::algorithm_mismatch);
        auto m = parsed.decrypt_multi(rsa_only);
        REQUIRE_FALSE(m);
        CHECK(m.error().code == errc::algorithm_mismatch);
        CHECK(rsa_only.calls == 0);
    }
    CHECK(ERR_peek_error() == 0);
}

TEST_CASE("RSA1_5 through an opaque decrypter still needs the opt-in", "[opaque][jwe][legacy]") {
    const auto key = must(jwk::generate_rsa(2048));
    const jwe_encrypt_options legacy_enc{.legacy = {.allow_rsa1_5 = true}};
    auto sealed = must(jwe::encrypt("old", content_encryption::A128CBC_HS256,
                                    {key_algorithm::RSA1_5, must(key.public_key())}, legacy_enc));
    auto parsed = must(jwe::parse(must(sealed.compact()), {key_algorithm::RSA1_5},
                                  {content_encryption::A128CBC_HS256}));
    test_decrypter hsm(key, {key_algorithm::RSA1_5});

    auto refused = parsed.decrypt(hsm);
    REQUIRE_FALSE(refused);
    CHECK(refused.error().code == errc::legacy_algorithm_disabled);
    CHECK(hsm.calls == 0);

    auto out = must(parsed.decrypt(hsm, {.legacy = {.allow_rsa1_5 = true}}));
    CHECK(out.size() == 3);
}
