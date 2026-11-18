#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include "jose/jose.hpp"

#include <openssl/err.h>

#include <memory>
#include <mutex>
#include <string>
#include <thread>
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

// Stands in for a network round trip: `co_await net.hop()` resumes the
// coroutine on a new thread, so the async paths really suspend.
class network {
public:
    network() = default;
    network(const network&) = delete;
    network& operator=(const network&) = delete;
    ~network() {
        std::lock_guard lock(mutex_);
        for (auto& t : threads_) t.join();
    }

    struct hop_awaiter {
        network* net;
        [[nodiscard]] auto await_ready() const noexcept -> bool { return false; }
        auto await_suspend(std::coroutine_handle<> h) -> void {
            std::lock_guard lock(net->mutex_);
            net->threads_.emplace_back([h] { h.resume(); });
        }
        auto await_resume() const noexcept -> void {}
    };
    auto hop() -> hop_awaiter { return {this}; }

private:
    std::mutex mutex_;
    std::vector<std::thread> threads_;
};

struct kms_signer final : async_opaque_signer {
    enum class mode { normal, unavailable, der_sized };

    network& net;
    jwk key;
    std::vector<signing_algorithm> algs;
    mode behaviour = mode::normal;
    std::atomic<int> public_key_calls{0};
    std::atomic<int> sign_calls{0};

    kms_signer(network& n, jwk k, std::vector<signing_algorithm> a)
        : net(n), key(std::move(k)), algs(std::move(a)) {}

    auto public_key() -> task<expected<jwk>> override {
        ++public_key_calls;
        co_await net.hop();
        co_return key.public_key();
    }
    auto algorithms() const -> std::vector<signing_algorithm> override { return algs; }
    auto sign(std::span<const uint8_t> input, signing_algorithm alg) -> task<expected<std::vector<uint8_t>>> override {
        ++sign_calls;
        co_await net.hop();
        if (behaviour == mode::unavailable) co_return make_error(errc::key_unavailable, "KMS throttled");
        if (behaviour == mode::der_sized) co_return std::vector<uint8_t>(71, 0x30);
        // `input` is still valid: the library awaits this task before
        // releasing it.
        auto sig = jose::sign(alg, key.pkey(), input);
        if (!sig) co_return jose::unexpected(sig.error());
        co_return std::vector<uint8_t>(sig->begin(), sig->end());
    }
};

struct kms_verifier final : async_opaque_verifier {
    enum class mode { normal, unavailable, other_error };

    network& net;
    jwk key;
    std::vector<signing_algorithm> algs;
    mode behaviour = mode::normal;
    std::atomic<int> calls{0};

    kms_verifier(network& n, jwk k, std::vector<signing_algorithm> a)
        : net(n), key(std::move(k)), algs(std::move(a)) {}

    auto algorithms() const -> std::vector<signing_algorithm> override { return algs; }
    auto verify(std::span<const uint8_t> input, std::span<const uint8_t> signature, signing_algorithm alg)
        -> task<expected<void>> override {
        ++calls;
        co_await net.hop();
        if (behaviour == mode::unavailable) co_return make_error(errc::key_unavailable, "KMS throttled");
        if (behaviour == mode::other_error) co_return make_error(errc::openssl_error, "KMSInvalidSignature");
        co_return key.key_type() == kty::oct ? jose::verify(alg, key.oct(), input, signature)
                                             : jose::verify(alg, key.pkey(), input, signature);
    }
};

struct kms_decrypter final : async_opaque_key_decrypter {
    enum class mode { normal, unavailable, other_error, wrong_length };

    network& net;
    jwk key;
    std::vector<key_algorithm> algs;
    mode behaviour = mode::normal;
    std::atomic<int> calls{0};

    kms_decrypter(network& n, jwk k, std::vector<key_algorithm> a)
        : net(n), key(std::move(k)), algs(std::move(a)) {}

    auto algorithms() const -> std::vector<key_algorithm> override { return algs; }
    auto decrypt_key(std::span<const uint8_t> encrypted_key, key_algorithm alg, content_encryption enc,
                     const header& joined) -> task<expected<secure_bytes>> override {
        ++calls;
        co_await net.hop();
        if (behaviour == mode::unavailable) co_return make_error(errc::key_unavailable, "KMS unreachable");
        if (behaviour == mode::other_error) co_return make_error(errc::invalid_key, "InvalidCiphertextException");
        if (behaviour == mode::wrong_length) co_return secure_bytes(5, 0x41);
        const size_t cek_len = cek_byte_size(enc);
        switch (alg) {
        case key_algorithm::RSA_OAEP_256:
        case key_algorithm::RSA1_5:
            co_return rsa_decrypt_key(alg, key.pkey(), encrypted_key, cek_len, {.allow_rsa1_5 = true});
        case key_algorithm::A256KW:
            co_return aes_key_unwrap(alg, key.oct(), encrypted_key);
        case key_algorithm::ECDH_ES: {
            const auto& epk = joined.epk();
            if (!epk) co_return make_error(errc::invalid_header, "no epk");
            co_return ecdh_derive_key_from_epk(key.pkey(), epk->pkey(), to_string(enc), {}, {}, cek_len * 8);
        }
        default:
            co_return make_error(errc::unsupported_algorithm, "not in this test decrypter");
        }
    }
};

} // namespace

// ===========================================================================
// JWS
// ===========================================================================

TEST_CASE("sign_async with an async KMS signer", "[async][jws]") {
    network net;
    const auto key = with_kid(must(jwk::generate_ec(ec_curve::P256)), "arn:kms:1");
    const auto pub = must(key.public_key());
    auto kms = std::make_shared<kms_signer>(net, key, std::vector{signing_algorithm::ES256});

    auto signed_ = must(sync_wait(jws::sign_async("hello", {signing_algorithm::ES256, kms})));
    CHECK(kms->public_key_calls == 1);
    CHECK(kms->sign_calls == 1);
    CHECK(signed_.signatures().front().protected_header.kid() == "arn:kms:1");
    CHECK(must(signed_.verify(pub)) == as_bytes("hello"));

    SECTION("public_key() is only fetched when needed") {
        auto plain = must(sync_wait(jws::sign_async("x", {signing_algorithm::ES256, kms}, {.include_kid = false})));
        CHECK(kms->public_key_calls == 1);
        CHECK_FALSE(plain.signatures().front().protected_header.kid());
    }
    SECTION("embed_jwk") {
        auto embedded = must(sync_wait(jws::sign_async("x", {signing_algorithm::ES256, kms}, {.embed_jwk = true})));
        const auto& h = embedded.signatures().front().protected_header;
        REQUIRE(h.jwk());
        CHECK(must(h.jwk()->thumbprint()) == must(pub.thumbprint()));
    }
    SECTION("RFC 7797 unencoded payload") {
        auto unencoded = must(sync_wait(jws::sign_async("$.02", {signing_algorithm::ES256, kms}, {.b64 = false})));
        CHECK_FALSE(unencoded.b64());
        CHECK(must(unencoded.verify(pub)) == as_bytes("$.02"));
    }
}

TEST_CASE("sign_async mixes local, sync opaque and async signers", "[async][jws]") {
    network net;
    const auto local = with_kid(must(jwk::generate_okp(okp_curve::Ed25519)), "local");
    const auto remote = with_kid(must(jwk::generate_ec(ec_curve::P384)), "remote");
    const auto hmac = must(jwk::generate_oct(32));
    auto kms = std::make_shared<kms_signer>(net, remote, std::vector{signing_algorithm::ES384});

    std::vector<jws_signer> signers{
        {signing_algorithm::EdDSA, local},
        {signing_algorithm::ES384, kms},
        {signing_algorithm::HS256, hmac},
    };
    auto signed_ = must(sync_wait(jws::sign_async(as_bytes("three"), std::move(signers))));
    auto parsed = must(jws::parse(must(signed_.to_json_string()),
                                  {signing_algorithm::EdDSA, signing_algorithm::ES384, signing_algorithm::HS256}));
    CHECK(must(parsed.verify_multi(must(local.public_key()))).index == 0);
    CHECK(must(parsed.verify_multi(must(remote.public_key()))).index == 1);
    CHECK(must(parsed.verify_multi(hmac)).index == 2);
}

TEST_CASE("sign_async copies its arguments", "[async][jws]") {
    network net;
    const auto key = must(jwk::generate_ec(ec_curve::P256));
    task<expected<jws>> pending;
    {
        // Every argument is a temporary that dies before the task runs.
        auto payload = std::string("temporary payload");
        pending = jws::sign_async(payload, jws_signer{signing_algorithm::ES256,
                                                      std::make_shared<kms_signer>(
                                                          net, key, std::vector{signing_algorithm::ES256})});
        payload.assign(payload.size(), 'X');
    }
    auto signed_ = must(sync_wait(std::move(pending)));
    CHECK(must(signed_.verify(must(key.public_key()))) == as_bytes("temporary payload"));
}

TEST_CASE("async signer misuse is caught", "[async][jws][validation]") {
    network net;
    const auto key = must(jwk::generate_ec(ec_curve::P256));
    auto kms = std::make_shared<kms_signer>(net, key, std::vector{signing_algorithm::ES256});

    SECTION("the synchronous sign() refuses an async signer") {
        auto r = jws::sign("x", {signing_algorithm::ES256, kms});
        REQUIRE_FALSE(r);
        CHECK(r.error().code == errc::invalid_argument);
        CHECK_THAT(r.error().message, ContainsSubstring("sign_async"));
        CHECK(kms->sign_calls == 0);
    }
    SECTION("an unsupported algorithm is refused before any call") {
        auto r = sync_wait(jws::sign_async("x", {signing_algorithm::ES512, kms}));
        REQUIRE_FALSE(r);
        CHECK(r.error().code == errc::algorithm_mismatch);
        CHECK(kms->public_key_calls == 0);
        CHECK(kms->sign_calls == 0);
    }
    SECTION("a null async signer") {
        auto r = sync_wait(jws::sign_async("x", {signing_algorithm::ES256, std::shared_ptr<async_opaque_signer>{}}));
        REQUIRE_FALSE(r);
        CHECK(r.error().code == errc::invalid_argument);
    }
    SECTION("a DER-encoded signature") {
        kms->behaviour = kms_signer::mode::der_sized;
        auto r = sync_wait(jws::sign_async("x", {signing_algorithm::ES256, kms}));
        REQUIRE_FALSE(r);
        CHECK(r.error().code == errc::invalid_signature);
        CHECK_THAT(r.error().message, ContainsSubstring("not DER"));
    }
    SECTION("key_unavailable passes through") {
        kms->behaviour = kms_signer::mode::unavailable;
        auto r = sync_wait(jws::sign_async("x", {signing_algorithm::ES256, kms}));
        REQUIRE_FALSE(r);
        CHECK(r.error().code == errc::key_unavailable);
    }
    SECTION("no signers") {
        auto r = sync_wait(jws::sign_async(std::vector<uint8_t>{}, std::vector<jws_signer>{}));
        REQUIRE_FALSE(r);
        CHECK(r.error().code == errc::invalid_argument);
    }
}

TEST_CASE("verify_async with an async KMS verifier", "[async][jws]") {
    network net;
    const auto secret = must(jwk::generate_oct(32));
    auto signed_ = must(jws::sign("payload", {signing_algorithm::HS256, secret}));
    auto parsed = must(jws::parse(must(signed_.compact()), {signing_algorithm::HS256}));
    kms_verifier kms(net, secret, {signing_algorithm::HS256});

    CHECK(must(sync_wait(parsed.verify_async(kms))) == as_bytes("payload"));
    CHECK(must(sync_wait(parsed.verify_multi_async(kms))).index == 0);

    SECTION("a bad signature") {
        auto token = must(signed_.compact());
        auto& c = token[token.size() - 5];
        c = c == 'A' ? 'B' : 'A';
        auto tampered = must(jws::parse(token, {signing_algorithm::HS256}));
        auto r = sync_wait(tampered.verify_async(kms));
        REQUIRE_FALSE(r);
        CHECK(r.error().code == errc::invalid_signature);
    }
    SECTION("an unsupported algorithm is never offered") {
        kms_verifier other(net, secret, {signing_algorithm::HS384});
        auto r = sync_wait(parsed.verify_async(other));
        REQUIRE_FALSE(r);
        CHECK(r.error().code == errc::algorithm_mismatch);
        auto m = sync_wait(parsed.verify_multi_async(other));
        REQUIRE_FALSE(m);
        CHECK(m.error().code == errc::algorithm_mismatch);
        CHECK(other.calls == 0);
    }
    SECTION("verifier errors are normalized") {
        kms.behaviour = kms_verifier::mode::other_error;
        auto r = sync_wait(parsed.verify_async(kms));
        REQUIRE_FALSE(r);
        CHECK(r.error().code == errc::invalid_signature);

        kms.behaviour = kms_verifier::mode::unavailable;
        r = sync_wait(parsed.verify_async(kms));
        REQUIRE_FALSE(r);
        CHECK(r.error().code == errc::key_unavailable);
        auto m = sync_wait(parsed.verify_multi_async(kms));
        REQUIRE_FALSE(m);
        CHECK(m.error().code == errc::key_unavailable);
    }
}

TEST_CASE("async signing and verifying compose in one coroutine", "[async][jws]") {
    network net;
    const auto key = must(jwk::generate_ec(ec_curve::P256));
    auto signer = std::make_shared<kms_signer>(net, key, std::vector{signing_algorithm::ES256});
    kms_verifier verifier(net, must(key.public_key()), {signing_algorithm::ES256});

    auto round_trip = [&]() -> task<expected<std::vector<uint8_t>>> {
        auto signed_ = co_await jws::sign_async("composed", {signing_algorithm::ES256, signer});
        if (!signed_) co_return jose::unexpected(signed_.error());
        auto token = signed_->compact();
        if (!token) co_return jose::unexpected(token.error());
        auto parsed = jws::parse(*token, {signing_algorithm::ES256});
        if (!parsed) co_return jose::unexpected(parsed.error());
        co_return co_await parsed->verify_async(verifier);
    };
    CHECK(must(sync_wait(round_trip())) == as_bytes("composed"));
}

// ===========================================================================
// JWE
// ===========================================================================

TEST_CASE("decrypt_async with an async KMS decrypter", "[async][jwe]") {
    network net;
    const auto plaintext = std::string_view("sealed for the KMS");

    SECTION("RSA-OAEP-256") {
        const auto key = must(jwk::generate_rsa(2048));
        auto sealed = must(jwe::encrypt(plaintext, content_encryption::A256GCM,
                                        {key_algorithm::RSA_OAEP_256, must(key.public_key())}));
        auto parsed = must(jwe::parse(must(sealed.compact()), {key_algorithm::RSA_OAEP_256},
                                      {content_encryption::A256GCM}));
        kms_decrypter kms(net, key, {key_algorithm::RSA_OAEP_256});
        auto out = must(sync_wait(parsed.decrypt_async(kms)));
        CHECK(std::string_view(reinterpret_cast<const char*>(out.data()), out.size()) == plaintext);
    }
    SECTION("ECDH-ES, compressed") {
        const auto key = must(jwk::generate_okp(okp_curve::X25519));
        auto sealed = must(jwe::encrypt(plaintext, content_encryption::A128GCM,
                                        {key_algorithm::ECDH_ES, must(key.public_key())}, {.compress = true}));
        auto parsed = must(jwe::parse(must(sealed.compact()), {key_algorithm::ECDH_ES},
                                      {content_encryption::A128GCM}));
        kms_decrypter kms(net, key, {key_algorithm::ECDH_ES});
        CHECK(must(sync_wait(parsed.decrypt_async(kms))).size() == plaintext.size());
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
        kms_decrypter kms(net, kek, {key_algorithm::A256KW});
        CHECK(must(sync_wait(parsed.decrypt_multi_async(kms))).index == 1);
        CHECK(kms.calls == 1);
        auto single = sync_wait(parsed.decrypt_async(kms));
        REQUIRE_FALSE(single);
        CHECK(single.error().code == errc::invalid_argument);
    }
}

TEST_CASE("async decrypter failures stay uniform", "[async][jwe][validation]") {
    network net;
    const auto kek = must(jwk::generate_oct(32));
    auto sealed = must(jwe::encrypt("secret", content_encryption::A256GCM, {key_algorithm::A256KW, kek}));
    auto parsed = must(jwe::parse(must(sealed.compact()), {key_algorithm::A256KW}, {content_encryption::A256GCM}));
    kms_decrypter kms(net, kek, {key_algorithm::A256KW});

    auto expect_failed = [](const expected<secure_bytes>& r) {
        REQUIRE_FALSE(r);
        CHECK(r.error().code == errc::decryption_failed);
        CHECK(r.error().message == "JWE decryption failed");
    };

    SECTION("a backend error") {
        kms.behaviour = kms_decrypter::mode::other_error;
        expect_failed(sync_wait(parsed.decrypt_async(kms)));
        auto m = sync_wait(parsed.decrypt_multi_async(kms));
        REQUIRE_FALSE(m);
        CHECK(m.error().code == errc::decryption_failed);
    }
    SECTION("a CEK of the wrong length") {
        kms.behaviour = kms_decrypter::mode::wrong_length;
        expect_failed(sync_wait(parsed.decrypt_async(kms)));
    }
    SECTION("a wrong key") {
        kms_decrypter other(net, must(jwk::generate_oct(32)), {key_algorithm::A256KW});
        expect_failed(sync_wait(parsed.decrypt_async(other)));
    }
    SECTION("key_unavailable passes through") {
        kms.behaviour = kms_decrypter::mode::unavailable;
        auto r = sync_wait(parsed.decrypt_async(kms));
        REQUIRE_FALSE(r);
        CHECK(r.error().code == errc::key_unavailable);
        auto m = sync_wait(parsed.decrypt_multi_async(kms));
        REQUIRE_FALSE(m);
        CHECK(m.error().code == errc::key_unavailable);
    }
    SECTION("an unsupported algorithm is never offered") {
        kms_decrypter rsa_only(net, kek, {key_algorithm::RSA_OAEP_256});
        auto r = sync_wait(parsed.decrypt_async(rsa_only));
        REQUIRE_FALSE(r);
        CHECK(r.error().code == errc::algorithm_mismatch);
        auto m = sync_wait(parsed.decrypt_multi_async(rsa_only));
        REQUIRE_FALSE(m);
        CHECK(m.error().code == errc::algorithm_mismatch);
        CHECK(rsa_only.calls == 0);
    }
}

TEST_CASE("RSA1_5 through an async decrypter still needs the opt-in", "[async][jwe][legacy]") {
    network net;
    const auto key = must(jwk::generate_rsa(2048));
    auto sealed = must(jwe::encrypt("old", content_encryption::A128CBC_HS256,
                                    {key_algorithm::RSA1_5, must(key.public_key())},
                                    {.legacy = {.allow_rsa1_5 = true}}));
    auto parsed = must(jwe::parse(must(sealed.compact()), {key_algorithm::RSA1_5},
                                  {content_encryption::A128CBC_HS256}));
    kms_decrypter kms(net, key, {key_algorithm::RSA1_5});

    auto refused = sync_wait(parsed.decrypt_async(kms));
    REQUIRE_FALSE(refused);
    CHECK(refused.error().code == errc::legacy_algorithm_disabled);
    CHECK(kms.calls == 0);
    CHECK(must(sync_wait(parsed.decrypt_async(kms, {.legacy = {.allow_rsa1_5 = true}}))).size() == 3);
}
