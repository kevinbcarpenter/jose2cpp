#include <catch2/catch_test_macros.hpp>

#include "jose/jose.hpp"
#include "support/test_support.hpp"

#include <openssl/err.h>

#include <string>
#include <vector>

using namespace jose;
using json = nlohmann::json;
using jose::test::b64;
using jose::test::load_vectors;

namespace {

const std::vector<signing_algorithm> k_all_algs{
    signing_algorithm::HS256, signing_algorithm::HS384, signing_algorithm::HS512,
    signing_algorithm::RS256, signing_algorithm::RS384, signing_algorithm::RS512,
    signing_algorithm::ES256, signing_algorithm::ES384, signing_algorithm::ES512,
    signing_algorithm::PS256, signing_algorithm::PS384, signing_algorithm::PS512,
    signing_algorithm::EdDSA,
};

template <typename T>
auto must(expected<T> v) -> T {
    INFO((v ? std::string("ok") : v.error().message));
    REQUIRE(v.has_value());
    return std::move(*v);
}

template <typename T>
auto error_of(const expected<T>& v) -> errc {
    REQUIRE_FALSE(v.has_value());
    INFO(v.error().message);
    CHECK(ERR_peek_error() == 0);
    return v.error().code;
}

auto bytes(std::string_view s) -> std::vector<uint8_t> { return {s.begin(), s.end()}; }

auto key_of(const json& j) -> jwk { return must(jwk::from_json(j)); }

// Strip "use"/"alg" so a key can be reused with any suitable algorithm.
auto bare(const jwk& k) -> jwk {
    jwk copy = k;
    REQUIRE(copy.set_algorithm(std::nullopt).has_value());
    REQUIRE(copy.set_use(std::nullopt).has_value());
    return copy;
}

auto key_for(signing_algorithm alg) -> jwk {
    switch (alg) {
    case signing_algorithm::HS256: return must(jwk::generate_oct(32));
    case signing_algorithm::HS384: return must(jwk::generate_oct(48));
    case signing_algorithm::HS512: return must(jwk::generate_oct(64));
    case signing_algorithm::ES256: return must(jwk::generate_ec(ec_curve::P256));
    case signing_algorithm::ES384: return must(jwk::generate_ec(ec_curve::P384));
    case signing_algorithm::ES512: return must(jwk::generate_ec(ec_curve::P521));
    case signing_algorithm::EdDSA: return must(jwk::generate_okp(okp_curve::Ed25519));
    default: {
        static const jwk rsa = must(jwk::generate_rsa(2048));
        return rsa;
    }
    }
}

auto verifier_for(const jwk& k) -> jwk { return k.key_type() == kty::oct ? k : must(k.public_key()); }

auto hs256_key() -> jwk { return must(jwk::generate_oct(32)); }

// The same JWS with its payload detached, in the given serialization.
auto detached_form(const jws& j, std::string_view form) -> std::string {
    if (form == "compact") return must(j.compact_detached());
    return must(j.to_json_string(form == "general" ? jws_json_format::general : jws_json_format::flattened,
                                 /*detached=*/true));
}

} // namespace

// ---------------------------------------------------------------------------
// RFC vectors: RFC 7515 App. A, RFC 7520 §4, RFC 7797 §4, RFC 8037 A.4
// ---------------------------------------------------------------------------

TEST_CASE("RFC JWS vectors parse, verify and re-serialize exactly", "[jws][vectors]") {
    const auto cases = load_vectors("jws");
    REQUIRE(cases.size() == 17);
    int serializations = 0;
    int reproduced = 0;

    for (const auto& c : cases) {
        const auto source = c["source"].get<std::string>();
        INFO(source);
        const auto payload = b64(c["payload"]);
        std::vector<jwk> keys;
        for (const auto& k : c["keys"]) keys.push_back(key_of(k));
        const auto detached_in = c["detached"].get<std::vector<std::string>>();

        for (const char* form : {"compact", "general", "flattened"}) {
            if (!c.contains(form)) continue;
            INFO(form);
            ++serializations;
            const bool detached = std::find(detached_in.begin(), detached_in.end(), form) != detached_in.end();
            const std::string text = c[form].is_string() ? c[form].get<std::string>() : c[form].dump();

            const auto parsed = detached ? must(jws::parse_detached(text, payload, k_all_algs))
                                         : must(jws::parse(text, k_all_algs));
            REQUIRE(parsed.signatures().size() == keys.size());
            CHECK(std::equal(payload.begin(), payload.end(), parsed.unsafe_payload().begin(),
                             parsed.unsafe_payload().end()));

            // Verify each signature with its own key.
            if (keys.size() == 1) {
                CHECK(must(parsed.verify(keys[0])) == payload);
            }
            for (size_t i = 0; i < keys.size(); ++i) {
                const auto v = must(parsed.verify_multi(keys[i]));
                CHECK(v.index == i);
                CHECK(v.payload == payload);
            }

            // Re-serializing a parsed JWS reproduces it exactly.
            if (std::string_view(form) == "compact") {
                CHECK((detached ? must(parsed.compact_detached()) : must(parsed.compact())) == text);
            } else {
                const auto fmt = std::string_view(form) == "general" ? jws_json_format::general
                                                                     : jws_json_format::flattened;
                CHECK(must(parsed.to_json(fmt, detached)) == c[form]);
            }

            // A different payload no longer verifies.
            auto other = payload;
            other.push_back('!');
            const auto tampered = must(jws::parse_detached(detached_form(parsed, form), other, k_all_algs));
            CHECK(error_of(tampered.verify_multi(keys[0])) == errc::invalid_signature);
        }

        // Deterministic algorithms: signing again with the same protected
        // header reproduces the signature, whenever our header encoding
        // matches the RFC's (key order and whitespace may differ).
        if (c["deterministic"].get<bool>() && c.contains("compact") && detached_in.empty()) {
            const auto parsed = must(jws::parse(c["compact"].get<std::string>(), k_all_algs));
            const auto& sig = parsed.signatures().front();
            jws_signer signer{sig.alg, bare(keys[0]), sig.protected_header};
            const auto resigned = must(jws::sign(payload, signer, {.include_kid = false}));
            if (resigned.signatures().front().encoded_protected == sig.encoded_protected) {
                CHECK(must(resigned.compact()) == c["compact"].get<std::string>());
                ++reproduced;
            }
        }
    }
    CHECK(serializations == 31);
    CHECK(reproduced >= 4);
}

// ---------------------------------------------------------------------------
// Round trips
// ---------------------------------------------------------------------------

TEST_CASE("every algorithm signs and verifies in every serialization", "[jws]") {
    const auto payload = bytes("{\"iss\":\"joe\"}");
    for (auto alg : k_all_algs) {
        INFO(to_string(alg));
        const auto key = key_for(alg);
        const auto pub = verifier_for(key);
        const auto signed_ = must(jws::sign(payload, {alg, key}));

        for (const auto& text : {must(signed_.compact()), must(signed_.to_json_string()),
                                 must(signed_.to_json_string(jws_json_format::flattened))}) {
            const auto parsed = must(jws::parse(text, {alg}));
            CHECK(must(parsed.verify(pub)) == payload);
            CHECK(parsed.signatures().front().alg == alg);
        }

        const auto parsed = must(jws::parse_detached(must(signed_.compact_detached()), payload, {alg}));
        CHECK(must(parsed.verify(pub)) == payload);
    }
}

TEST_CASE("empty and binary payloads", "[jws]") {
    const auto key = hs256_key();
    for (const auto& payload : {std::vector<uint8_t>{}, std::vector<uint8_t>{0, 0xff, '.', 0x80}}) {
        const auto s = must(jws::sign(payload, {signing_algorithm::HS256, key}));
        const auto parsed = must(jws::parse(must(s.compact()), {signing_algorithm::HS256}));
        CHECK(must(parsed.verify(key)) == payload);
    }
}

TEST_CASE("multiple signatures", "[jws][multi]") {
    const auto rsa = key_for(signing_algorithm::RS256);
    const auto ec = key_for(signing_algorithm::ES384);
    const auto ed = key_for(signing_algorithm::EdDSA);
    const std::vector<jws_signer> signers{
        {signing_algorithm::PS256, rsa},
        {signing_algorithm::ES384, ec, {}, must(header::from_json({{"kid", "ec-key"}}))},
        {signing_algorithm::EdDSA, ed},
    };
    const auto payload = bytes("multi");
    const auto s = must(jws::sign(payload, signers));

    CHECK(error_of(s.compact()) == errc::invalid_argument);
    CHECK(error_of(s.to_json(jws_json_format::flattened)) == errc::invalid_argument);

    const auto parsed = must(jws::parse(must(s.to_json_string()), k_all_algs));
    REQUIRE(parsed.signatures().size() == 3);
    CHECK(parsed.signatures()[1].unprotected_header.kid() == "ec-key");

    CHECK(must(parsed.verify_multi(verifier_for(rsa))).index == 0);
    CHECK(must(parsed.verify_multi(verifier_for(ec))).index == 1);
    CHECK(must(parsed.verify_multi(verifier_for(ed))).index == 2);
    CHECK(error_of(parsed.verify(verifier_for(rsa))) == errc::invalid_argument); // use verify_multi

    // A key that suits none of the signatures, or a wrong key that does.
    CHECK(error_of(parsed.verify_multi(hs256_key())) == errc::algorithm_mismatch);
    CHECK(error_of(parsed.verify_multi(verifier_for(key_for(signing_algorithm::ES384)))) ==
          errc::invalid_signature);

    // Every signature's alg must be allowed, not just the one being used.
    CHECK(error_of(jws::parse(must(s.to_json_string()), {signing_algorithm::PS256, signing_algorithm::ES384})) ==
          errc::algorithm_mismatch);
}

// ---------------------------------------------------------------------------
// Algorithm allowlist and key checks
// ---------------------------------------------------------------------------

TEST_CASE("the caller's algorithm list decides", "[jws][alg]") {
    const auto key = key_for(signing_algorithm::RS256);
    const auto token = must(must(jws::sign(bytes("x"), {signing_algorithm::RS256, key})).compact());

    CHECK(jws::parse(token, {signing_algorithm::RS256}).has_value());
    CHECK(error_of(jws::parse(token, {signing_algorithm::PS256, signing_algorithm::ES256})) ==
          errc::algorithm_mismatch);
    CHECK(error_of(jws::parse(token, {})) == errc::invalid_argument);

    // "none" and unknown algorithms never parse.
    for (const char* alg : {"none", "None", "HS1", ""}) {
        INFO(alg);
        const auto prot = base64url::encode(std::string_view(json{{"alg", alg}}.dump()));
        CHECK(error_of(jws::parse(prot + ".eA.", k_all_algs)) == errc::unsupported_algorithm);
    }
}

TEST_CASE("verification checks the key against the algorithm", "[jws][alg]") {
    const auto hs = hs256_key();
    const auto hs_token = must(jws::parse(must(must(jws::sign(bytes("x"), {signing_algorithm::HS256, hs})).compact()),
                                          k_all_algs));

    // Wrong key type, wrong curve, too-short HMAC key.
    CHECK(error_of(hs_token.verify(verifier_for(key_for(signing_algorithm::RS256)))) == errc::algorithm_mismatch);
    CHECK(error_of(hs_token.verify(must(jwk::generate_oct(16)))) == errc::key_too_short);

    const auto p256 = key_for(signing_algorithm::ES256);
    const auto es_token = must(jws::parse(
        must(must(jws::sign(bytes("x"), {signing_algorithm::ES256, p256})).compact()), k_all_algs));
    CHECK(error_of(es_token.verify(verifier_for(key_for(signing_algorithm::ES384)))) == errc::algorithm_mismatch);
    CHECK(error_of(es_token.verify(verifier_for(key_for(signing_algorithm::ES256)))) == errc::invalid_signature);

    // A key restricted to another "alg", or not for signatures.
    auto restricted = hs;
    REQUIRE(restricted.set_algorithm("HS384").has_value() == false); // 32 octets is too short for HS384
    auto hs64 = must(jwk::generate_oct(64));
    const auto hs512_token = must(jws::parse(
        must(must(jws::sign(bytes("x"), {signing_algorithm::HS512, hs64})).compact()), k_all_algs));
    REQUIRE(hs64.set_algorithm("HS384").has_value());
    CHECK(error_of(hs512_token.verify(hs64)) == errc::algorithm_mismatch);

    auto enc_only = hs;
    REQUIRE(enc_only.set_use("enc").has_value());
    CHECK(error_of(hs_token.verify(enc_only)) == errc::invalid_key);
    auto sign_only = hs;
    REQUIRE(sign_only.set_key_ops(std::vector<std::string>{"sign"}).has_value());
    CHECK(error_of(hs_token.verify(sign_only)) == errc::invalid_key);
    REQUIRE(sign_only.set_key_ops(std::vector<std::string>{"sign", "verify"}).has_value());
    CHECK(hs_token.verify(sign_only).has_value());
}

TEST_CASE("signing checks the key", "[jws][alg]") {
    const auto ec = key_for(signing_algorithm::ES256);
    CHECK(error_of(jws::sign(bytes("x"), {signing_algorithm::ES256, verifier_for(ec)})) == errc::invalid_key);
    CHECK(error_of(jws::sign(bytes("x"), {signing_algorithm::ES384, ec})) == errc::algorithm_mismatch);
    CHECK(error_of(jws::sign(bytes("x"), {signing_algorithm::HS256, must(jwk::generate_oct(31))})) ==
          errc::key_too_short);

    auto verify_only = hs256_key();
    REQUIRE(verify_only.set_key_ops(std::vector<std::string>{"verify"}).has_value());
    CHECK(error_of(jws::sign(bytes("x"), {signing_algorithm::HS256, verify_only})) == errc::invalid_key);

    CHECK(error_of(jws::sign(bytes("x"), std::span<const jws_signer>{})) == errc::invalid_argument);

    // A conflicting "alg", or "b64" set by hand.
    const auto wrong_alg = must(header::from_json({{"alg", "HS512"}}));
    CHECK(error_of(jws::sign(bytes("x"), {signing_algorithm::HS256, hs256_key(), wrong_alg})) ==
          errc::invalid_argument);
    const auto manual_b64 = must(header::from_json({{"b64", false}, {"crit", {"b64"}}}));
    CHECK(error_of(jws::sign(bytes("x"), {signing_algorithm::HS256, hs256_key(), manual_b64})) ==
          errc::invalid_argument);

    // Header parts must still be disjoint.
    const auto kid = must(header::from_json({{"kid", "a"}}));
    CHECK(error_of(jws::sign(bytes("x"), {signing_algorithm::HS256, hs256_key(), kid, kid})) ==
          errc::invalid_header);
}

// ---------------------------------------------------------------------------
// Header options
// ---------------------------------------------------------------------------

TEST_CASE("kid and embedded jwk", "[jws][header]") {
    auto key = key_for(signing_algorithm::ES256);
    key.set_key_id("signing-key-1");
    const auto pub = verifier_for(key);

    const auto s = must(jws::sign(bytes("x"), {signing_algorithm::ES256, key}, {.embed_jwk = true}));
    const auto& prot = s.signatures().front().protected_header;
    CHECK(prot.kid() == "signing-key-1");
    REQUIRE(prot.jwk().has_value());
    CHECK(prot.jwk()->is_public());
    CHECK(*prot.jwk()->thumbprint() == *key.thumbprint());

    // The embedded key is never used implicitly: verification needs a key.
    const auto parsed = must(jws::parse(must(s.compact()), {signing_algorithm::ES256}));
    const jwk_set set({verifier_for(key_for(signing_algorithm::ES256)), pub});
    CHECK(must(parsed.verify(set)) == bytes("x"));

    CHECK_FALSE(must(jws::sign(bytes("x"), {signing_algorithm::ES256, key}, {.include_kid = false}))
                    .signatures().front().joined.kid());
    const auto no_kid = must(jws::parse(
        must(must(jws::sign(bytes("x"), {signing_algorithm::ES256, key}, {.include_kid = false})).compact()),
        {signing_algorithm::ES256}));
    CHECK(error_of(no_kid.verify(set)) == errc::invalid_key);

    auto other = key_for(signing_algorithm::ES256);
    other.set_key_id("someone-else");
    CHECK(error_of(parsed.verify(jwk_set({verifier_for(other)}))) == errc::invalid_key);

    // Same kid, wrong key: tried and rejected.
    auto impostor = verifier_for(key_for(signing_algorithm::ES256));
    impostor.set_key_id("signing-key-1");
    CHECK(error_of(parsed.verify(jwk_set({impostor}))) == errc::invalid_signature);
    CHECK(must(parsed.verify(jwk_set({impostor, pub}))) == bytes("x"));
}

TEST_CASE("critical extensions", "[jws][crit]") {
    const auto key = hs256_key();
    const auto prot = must(header::from_json({{"crit", {"x-audit"}}, {"x-audit", "42"}, {"typ", "JOSE"}}));
    const auto token = must(must(jws::sign(bytes("x"), {signing_algorithm::HS256, key, prot})).compact());

    CHECK(error_of(jws::parse(token, {signing_algorithm::HS256})) == errc::unrecognized_critical_extension);
    const auto parsed = must(jws::parse(token, {signing_algorithm::HS256}, {"x-audit"}));
    CHECK(*parsed.signatures().front().joined.get("x-audit") == "42");
    CHECK(parsed.signatures().front().joined.typ() == "JOSE");
    CHECK(must(parsed.verify(key)) == bytes("x"));
}

TEST_CASE("unprotected headers need JSON", "[jws][header]") {
    const auto key = hs256_key();
    const auto unprot = must(header::from_json({{"kid", "k"}}));
    const auto s = must(jws::sign(bytes("x"), {signing_algorithm::HS256, key, {}, unprot}));
    CHECK(error_of(s.compact()) == errc::invalid_argument);
    CHECK(error_of(s.compact_detached()) == errc::invalid_argument);

    const auto parsed = must(jws::parse(must(s.to_json_string(jws_json_format::flattened)), {signing_algorithm::HS256}));
    CHECK(parsed.signatures().front().unprotected_header.kid() == "k");
    CHECK(must(parsed.verify(key)) == bytes("x"));

    // An unprotected "alg" works, with no protected header at all (RFC 7520 §4.7).
    const json flat = {{"payload", "eA"}, {"header", {{"alg", "HS256"}}},
                       {"signature", base64url::encode(must(jose::sign(signing_algorithm::HS256, key.oct(),
                                                                         bytes(".eA"))))}};
    CHECK(must(must(jws::parse(flat.dump(), {signing_algorithm::HS256})).verify(key)) == bytes("x"));
}

// ---------------------------------------------------------------------------
// RFC 7797 unencoded payloads
// ---------------------------------------------------------------------------

TEST_CASE("unencoded payload (b64=false)", "[jws][b64]") {
    const auto cases = load_vectors("jws");
    const auto it = std::find_if(cases.begin(), cases.end(),
                                 [](const json& c) { return c["source"] == "RFC 7797 §4.2"; });
    REQUIRE(it != cases.end());
    const auto key = bare(key_of((*it)["keys"][0]));

    const auto s = must(jws::sign(bytes("$.02"), {signing_algorithm::HS256, key}, {.b64 = false}));
    CHECK_FALSE(s.b64());
    CHECK(s.signatures().front().protected_header.crit() == std::vector<std::string>{"b64"});

    // Byte-identical to the RFC (HMAC is deterministic).
    CHECK(must(s.compact_detached()) == (*it)["compact"].get<std::string>());
    CHECK(must(s.to_json(jws_json_format::flattened)) == (*it)["flattened"]);
    // '.' in the payload rules out the attached compact form.
    CHECK(error_of(s.compact()) == errc::invalid_argument);

    // Without '.', compact works and the payload travels raw.
    const auto plain = must(jws::sign(bytes("hello"), {signing_algorithm::HS256, key}, {.b64 = false}));
    const auto token = must(plain.compact());
    CHECK(token.find(".hello.") != std::string::npos);
    CHECK(must(must(jws::parse(token, {signing_algorithm::HS256})).verify(key)) == bytes("hello"));

    // JSON needs UTF-8.
    const auto binary = must(jws::sign(std::vector<uint8_t>{0xff, 0xfe}, {signing_algorithm::HS256, key}, {.b64 = false}));
    CHECK(error_of(binary.to_json()) == errc::serialization_error);
    CHECK(binary.to_json(jws_json_format::general, true).has_value());

    // All signatures must agree on b64.
    const auto encoded = must(jws::sign(bytes("hello"), {signing_algorithm::HS256, key}));
    json mixed = must(plain.to_json());
    mixed["signatures"].push_back(must(encoded.to_json())["signatures"][0]);
    CHECK(error_of(jws::parse(mixed.dump(), {signing_algorithm::HS256})) == errc::invalid_header);
}

// ---------------------------------------------------------------------------
// Malformed input
// ---------------------------------------------------------------------------

TEST_CASE("malformed compact JWS", "[jws][validation]") {
    const auto key = hs256_key();
    const auto good = must(must(jws::sign(bytes("x"), {signing_algorithm::HS256, key})).compact());
    const auto parts_at = good.find('.');
    const auto prot = good.substr(0, parts_at);
    const std::vector<signing_algorithm> hs{signing_algorithm::HS256};

    CHECK(error_of(jws::parse("", hs)) == errc::invalid_token);
    CHECK(error_of(jws::parse(prot + ".eA", hs)) == errc::invalid_token);
    CHECK(error_of(jws::parse(good + ".", hs)) == errc::invalid_token);
    CHECK(error_of(jws::parse(".eA.AAAA", hs)) == errc::invalid_token);           // empty protected header
    CHECK(error_of(jws::parse(prot + ".e+A.AAAA", hs)) == errc::invalid_base64);  // payload
    CHECK(error_of(jws::parse(prot + ".eA.AA=A", hs)) == errc::invalid_base64);   // signature
    CHECK(error_of(jws::parse(base64url::encode(std::string_view("{x")) + ".eA.AAAA", hs)) ==
          errc::serialization_error); // header not JSON
    CHECK(error_of(jws::parse(base64url::encode(std::string_view("{\"kid\":\"k\"}")) + ".eA.AAAA", hs)) ==
          errc::invalid_header); // no alg

    // A detached JWS must go through parse_detached, and vice versa.
    const auto detached = good.substr(0, parts_at) + ".." + good.substr(good.rfind('.') + 1);
    CHECK(error_of(must(jws::parse(detached, hs)).verify(key)) == errc::invalid_signature);
    CHECK(error_of(jws::parse_detached(good, bytes("x"), hs)) == errc::invalid_token);
    CHECK(must(must(jws::parse_detached(detached, bytes("x"), hs)).verify(key)) == bytes("x"));
}

TEST_CASE("malformed JSON JWS", "[jws][validation]") {
    const auto key = hs256_key();
    const json good = must(must(jws::sign(bytes("x"), {signing_algorithm::HS256, key})).to_json(jws_json_format::flattened));
    const std::vector<signing_algorithm> hs{signing_algorithm::HS256};
    auto with = [&](const char* name, json value) {
        json j = good;
        j[name] = std::move(value);
        return j.dump();
    };
    auto without = [&](const char* name) {
        json j = good;
        j.erase(name);
        return j.dump();
    };

    CHECK(must(must(jws::parse(good.dump(), hs)).verify(key)) == bytes("x"));

    CHECK(error_of(jws::parse("[]", hs)) == errc::invalid_token);
    CHECK(error_of(jws::parse("{", hs)) == errc::serialization_error);
    CHECK(error_of(jws::parse(with("payload", 1), hs)) == errc::invalid_token);
    CHECK(error_of(jws::parse(with("protected", 1), hs)) == errc::invalid_token);
    CHECK(error_of(jws::parse(with("protected", ""), hs)) == errc::invalid_token);
    CHECK(error_of(jws::parse(with("header", "x"), hs)) == errc::invalid_token);
    CHECK(error_of(jws::parse(with("signature", 1), hs)) == errc::invalid_token);
    CHECK(error_of(jws::parse(without("signature"), hs)) == errc::invalid_token);
    CHECK(error_of(jws::parse(without("payload"), hs)) == errc::invalid_token);
    CHECK(error_of(jws::parse(with("signatures", json::array()), hs)) == errc::invalid_token); // mixed forms

    const json general = must(must(jws::sign(bytes("x"), {signing_algorithm::HS256, key})).to_json());
    json empty = general;
    empty["signatures"] = json::array();
    CHECK(error_of(jws::parse(empty.dump(), hs)) == errc::invalid_token);
    json not_objects = general;
    not_objects["signatures"] = {1};
    CHECK(error_of(jws::parse(not_objects.dump(), hs)) == errc::invalid_token);

    // Duplicate members anywhere are rejected.
    std::string dup = good.dump();
    dup.insert(1, "\"payload\":\"eA\",");
    CHECK(error_of(jws::parse(dup, hs)) == errc::serialization_error);

    // The same name in the protected and unprotected header.
    CHECK(error_of(jws::parse(with("header", {{"alg", "HS256"}}), hs)) == errc::invalid_header);

    // Detached JSON.
    CHECK(must(must(jws::parse_detached(without("payload"), bytes("x"), hs)).verify(key)) == bytes("x"));
    CHECK(error_of(jws::parse_detached(good.dump(), bytes("x"), hs)) == errc::invalid_token);
}

TEST_CASE("compact JWS: whitespace at the ends is ignored, inside it isn't", "[jws][whitespace]") {
    const auto key = must(jwk::generate_oct(32));
    const auto token = must(must(jws::sign(std::string_view("hello"), {signing_algorithm::HS256, key})).compact());
    const std::vector<signing_algorithm> algs{signing_algorithm::HS256};

    for (const auto& padded : {token + "\n", token + "\r\n", " \t" + token, "\n" + token + "  \n"}) {
        auto parsed = must(jws::parse_compact(padded, algs));
        CHECK(must(parsed.verify(key)) == std::vector<uint8_t>{'h', 'e', 'l', 'l', 'o'});
        CHECK(must(parsed.compact()) == token); // one spelling, whatever came in
        CHECK(must(jws::parse(padded, algs)).signatures().size() == 1);
    }
    const auto detached = must(must(jws::sign(std::string_view("hello"), {signing_algorithm::HS256, key})).compact_detached());
    const std::vector<uint8_t> hello{'h', 'e', 'l', 'l', 'o'};
    CHECK(must(jws::parse_detached(detached + "\n", hello, algs)).verify(key));

    const auto dot = token.find('.');
    for (const auto& inside : {token.substr(0, 5) + "\n" + token.substr(5), token.substr(0, dot) + " " + token.substr(dot),
                               token.substr(0, token.size() - 3) + "\r\n" + token.substr(token.size() - 3)}) {
        auto r = jws::parse_compact(inside, algs);
        CHECK(error_of(r) == errc::invalid_base64);
        CHECK(r.error().message.find("whitespace") != std::string::npos);
    }
    // An unencoded payload is taken as is (RFC 7797 §5.2); only '.' is refused.
    const auto unencoded = must(must(jws::sign(std::string_view("a b\n c"), {signing_algorithm::HS256, key},
                                               {.b64 = false}))
                                    .compact());
    CHECK(must(must(jws::parse_compact(unencoded + "\n", algs)).verify(key)) ==
          std::vector<uint8_t>{'a', ' ', 'b', '\n', ' ', 'c'});
    CHECK(error_of(jws::parse_compact("  \n", algs)) == errc::invalid_token);
    CHECK(ERR_peek_error() == 0);
}
