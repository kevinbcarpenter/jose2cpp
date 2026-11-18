// Limits on the work an attacker-made token can ask for: the number of JWS
// signatures and JWE recipients (go-jose's MaxSignatures / MaxRecipients),
// and the PBKDF2 iterations one decrypt may spend.

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include "jose/jose.hpp"

#include <span>
#include <string>
#include <vector>

using namespace jose;
using Catch::Matchers::ContainsSubstring;
using json = nlohmann::json;

namespace {

auto bytes(std::string_view s) -> std::span<const uint8_t> {
    return {reinterpret_cast<const uint8_t*>(s.data()), s.size()};
}

const std::string plaintext = "the eagle flies at midnight";

auto password(std::string_view pw, const char* kid = nullptr) -> jwk {
    auto k = jwk::from_oct(bytes(pw));
    REQUIRE(k);
    if (kid) k->set_key_id(kid);
    return std::move(*k);
}

auto all_pbes2() -> std::vector<key_algorithm> {
    return {key_algorithm::PBES2_HS256_A128KW, key_algorithm::PBES2_HS384_A192KW, key_algorithm::PBES2_HS512_A256KW};
}

// A JSON JWE with one PBES2-HS256 recipient per password, at `count`.
auto pbes2_jwe(const std::vector<std::string>& passwords, int count) -> std::string {
    std::vector<jwe_recipient> recipients;
    for (const auto& pw : passwords)
        recipients.push_back({.alg = key_algorithm::PBES2_HS256_A128KW, .key = password(pw), .pbes2_count = count});
    auto sealed = jwe::encrypt(bytes(plaintext), content_encryption::A128GCM, std::span<const jwe_recipient>(recipients),
                               {.include_kid = false});
    REQUIRE(sealed);
    auto text = sealed->to_json_string();
    REQUIRE(text);
    return *text;
}

auto error_of(const auto& r) -> errc {
    REQUIRE_FALSE(r.has_value());
    return r.error().code;
}

} // namespace

TEST_CASE("limits: at most 32 JWE recipients", "[limits][jwe]") {
    STATIC_REQUIRE(jwe::max_recipients == 32);
    auto kek = jwk::generate_oct(16);
    REQUIRE(kek);
    std::vector<jwe_recipient> recipients(32, jwe_recipient{.alg = key_algorithm::A128KW, .key = *kek});
    auto sealed = jwe::encrypt(bytes(plaintext), content_encryption::A128GCM, std::span<const jwe_recipient>(recipients));
    REQUIRE(sealed);
    auto j = sealed->to_json();
    REQUIRE(j);
    auto parsed = jwe::parse(j->dump(), {key_algorithm::A128KW}, {content_encryption::A128GCM});
    REQUIRE(parsed);
    CHECK(parsed->recipients().size() == 32);

    // A 33rd: refused when parsing, before any key is touched.
    (*j)["recipients"].push_back((*j)["recipients"][0]);
    auto too_many = jwe::parse(j->dump(), {key_algorithm::A128KW}, {content_encryption::A128GCM});
    CHECK(error_of(too_many) == errc::invalid_token);
    CHECK_THAT(too_many.error().message, ContainsSubstring("33 recipients"));

    // And never produced.
    recipients.push_back(recipients.front());
    CHECK(error_of(jwe::encrypt(bytes(plaintext), content_encryption::A128GCM,
                                std::span<const jwe_recipient>(recipients))) == errc::invalid_argument);
}

TEST_CASE("limits: at most 32 JWS signatures", "[limits][jws]") {
    STATIC_REQUIRE(jws::max_signatures == 32);
    auto key = jwk::generate_oct(32);
    REQUIRE(key);
    std::vector<jws_signer> signers(32, jws_signer{.alg = signing_algorithm::HS256, .key = *key});
    auto token = jws::sign(bytes(plaintext), std::span<const jws_signer>(signers));
    REQUIRE(token);
    auto j = token->to_json();
    REQUIRE(j);
    auto parsed = jws::parse(j->dump(), {signing_algorithm::HS256});
    REQUIRE(parsed);
    CHECK(parsed->verify_multi(*key));

    (*j)["signatures"].push_back((*j)["signatures"][0]);
    auto too_many = jws::parse(j->dump(), {signing_algorithm::HS256});
    CHECK(error_of(too_many) == errc::invalid_token);
    CHECK_THAT(too_many.error().message, ContainsSubstring("33 signatures"));

    signers.push_back(signers.front());
    CHECK(error_of(jws::sign(bytes(plaintext), std::span<const jws_signer>(signers))) == errc::invalid_argument);
    CHECK(error_of(sync_wait(jws::sign_async(std::vector<uint8_t>(plaintext.begin(), plaintext.end()), signers))) ==
          errc::invalid_argument);
}

TEST_CASE("limits: PBKDF2 iterations per decrypt", "[limits][jwe][pbes2]") {
    const auto ours = password("ours");

    SECTION("the total spans the recipients tried") {
        // Ours is third; the first two are someone else's passwords.
        const auto token = pbes2_jwe({"theirs-1", "theirs-2", "ours"}, 1000);
        auto parsed = jwe::parse(token, all_pbes2(), {content_encryption::A128GCM});
        REQUIRE(parsed);

        auto r = parsed->decrypt_multi(ours, {.max_pbes2_iterations = 3000});
        REQUIRE(r);
        CHECK(r->index == 2);
        CHECK(std::string(r->plaintext.begin(), r->plaintext.end()) == plaintext);

        // One iteration short: the third attempt is refused, and nothing
        // after it is tried.
        auto short_of = parsed->decrypt_multi(ours, {.max_pbes2_iterations = 2999});
        CHECK(error_of(short_of) == errc::invalid_header);
        CHECK_THAT(short_of.error().message, ContainsSubstring("max_pbes2_iterations"));
    }
    SECTION("the default: one attempt at the largest p2c") {
        // At the largest p2c the second recipient is out of budget, so a
        // token can't make us run PBKDF2 at 1,000,000 more than once.
        const auto heavy = pbes2_jwe({"theirs", "ours"}, 1000000);
        auto parsed = jwe::parse(heavy, all_pbes2(), {content_encryption::A128GCM});
        REQUIRE(parsed);
        CHECK(error_of(parsed->decrypt_multi(ours)) == errc::invalid_header);

        // Three recipients at jose2cpp's own default count fit.
        const auto normal = pbes2_jwe({"theirs-1", "theirs-2", "ours"}, 310000);
        parsed = jwe::parse(normal, all_pbes2(), {content_encryption::A128GCM});
        REQUIRE(parsed);
        CHECK(parsed->decrypt_multi(ours));

        // go-jose's default count is 600,000, so only one such recipient fits
        // the default; a caller expecting several raises the budget.
        const auto go_jose = pbes2_jwe({"theirs", "ours"}, 600000);
        parsed = jwe::parse(go_jose, all_pbes2(), {content_encryption::A128GCM});
        REQUIRE(parsed);
        CHECK(error_of(parsed->decrypt_multi(ours)) == errc::invalid_header);
        CHECK(parsed->decrypt_multi(ours, {.max_pbes2_iterations = 1200000}));
    }
    SECTION("running out ends the call, even with a cheap recipient after") {
        // A 16-byte password also serves as an A128KW key; that recipient
        // comes last and would open the token.
        const auto both = password("sixteen-byte-key");
        std::vector<jwe_recipient> recipients{
            {.alg = key_algorithm::PBES2_HS256_A128KW, .key = password("theirs"), .pbes2_count = 1000},
            {.alg = key_algorithm::PBES2_HS256_A128KW, .key = password("theirs-2"), .pbes2_count = 2000},
            {.alg = key_algorithm::A128KW, .key = both},
        };
        auto sealed = jwe::encrypt(bytes(plaintext), content_encryption::A128GCM,
                                   std::span<const jwe_recipient>(recipients), {.include_kid = false});
        REQUIRE(sealed);
        auto parsed = jwe::parse(*sealed->to_json_string(), {key_algorithm::PBES2_HS256_A128KW, key_algorithm::A128KW},
                                 {content_encryption::A128GCM});
        REQUIRE(parsed);
        auto opened = parsed->decrypt_multi(both, {.max_pbes2_iterations = 3000});
        REQUIRE(opened);
        CHECK(opened->index == 2);
        // 1,000 spent on the first, the second needs 2,000 of the 500 left:
        // the call ends there and the A128KW recipient is never tried.
        CHECK(error_of(parsed->decrypt_multi(both, {.max_pbes2_iterations = 1500})) == errc::invalid_header);
    }
    SECTION("a single compact recipient at the largest p2c still decrypts") {
        auto sealed = jwe::encrypt(plaintext, content_encryption::A128GCM,
                                   {.alg = key_algorithm::PBES2_HS256_A128KW, .key = ours, .pbes2_count = 1000000});
        REQUIRE(sealed);
        auto compact = sealed->compact();
        REQUIRE(compact);
        auto parsed = jwe::parse(*compact, all_pbes2(), {content_encryption::A128GCM});
        REQUIRE(parsed);
        CHECK(parsed->decrypt(ours));
        // 0 refuses PBES2 altogether.
        CHECK(error_of(parsed->decrypt(ours, {.max_pbes2_iterations = 0})) == errc::invalid_header);
    }
    SECTION("a JWK Set: every key tried counts") {
        auto sealed = jwe::encrypt(plaintext, content_encryption::A128GCM,
                                   {.alg = key_algorithm::PBES2_HS256_A128KW, .key = password("ours", "pw"),
                                    .pbes2_count = 1000});
        REQUIRE(sealed);
        auto parsed = jwe::parse(*sealed->compact(), all_pbes2(), {content_encryption::A128GCM});
        REQUIRE(parsed);
        const jwk_set keys(std::vector<jwk>{password("wrong", "pw"), password("ours", "pw")});
        CHECK(parsed->decrypt(keys, {.max_pbes2_iterations = 2000}));
        auto r = parsed->decrypt(keys, {.max_pbes2_iterations = 1999});
        CHECK(error_of(r) == errc::invalid_header);
    }
}
