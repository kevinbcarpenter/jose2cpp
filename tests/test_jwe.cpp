#include <catch2/catch_test_macros.hpp>

#include "jose/jose.hpp"
#include "support/test_support.hpp"

#include <openssl/err.h>

#include <algorithm>
#include <string>
#include <vector>

using namespace jose;
using json = nlohmann::json;
using jose::test::b64;
using jose::test::load_vectors;

namespace {

const std::vector<key_algorithm> k_all_algs{
    key_algorithm::RSA1_5,         key_algorithm::RSA_OAEP,           key_algorithm::RSA_OAEP_256,
    key_algorithm::A128KW,         key_algorithm::A192KW,             key_algorithm::A256KW,
    key_algorithm::dir,            key_algorithm::ECDH_ES,            key_algorithm::ECDH_ES_A128KW,
    key_algorithm::ECDH_ES_A192KW, key_algorithm::ECDH_ES_A256KW,     key_algorithm::A128GCMKW,
    key_algorithm::A192GCMKW,      key_algorithm::A256GCMKW,          key_algorithm::PBES2_HS256_A128KW,
    key_algorithm::PBES2_HS384_A192KW, key_algorithm::PBES2_HS512_A256KW,
};

const std::vector<content_encryption> k_all_encs{
    content_encryption::A128CBC_HS256, content_encryption::A192CBC_HS384, content_encryption::A256CBC_HS512,
    content_encryption::A128GCM,       content_encryption::A192GCM,       content_encryption::A256GCM,
};

const jwe_decrypt_options k_legacy{.legacy = {.allow_rsa1_5 = true}};

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

auto same(std::span<const uint8_t> a, std::span<const uint8_t> b) -> bool {
    return std::equal(a.begin(), a.end(), b.begin(), b.end());
}

auto as_string(const secure_bytes& b) -> std::string { return {b.begin(), b.end()}; }

auto pub(const jwk& k) -> jwk { return must(k.public_key()); }

auto rsa_key() -> const jwk& {
    static const jwk key = must(jwk::generate_rsa(2048));
    return key;
}

// A (decryption key, encryption key) pair suited to `alg` and `enc`.
auto keys_for(key_algorithm alg, content_encryption enc) -> std::pair<jwk, jwk> {
    auto sym = [](size_t n) {
        auto k = must(jwk::generate_oct(n));
        return std::pair{k, k};
    };
    switch (alg) {
    case key_algorithm::RSA1_5:
    case key_algorithm::RSA_OAEP:
    case key_algorithm::RSA_OAEP_256: return {rsa_key(), pub(rsa_key())};
    case key_algorithm::A128KW:
    case key_algorithm::A128GCMKW: return sym(16);
    case key_algorithm::A192KW:
    case key_algorithm::A192GCMKW: return sym(24);
    case key_algorithm::A256KW:
    case key_algorithm::A256GCMKW: return sym(32);
    case key_algorithm::dir: return sym(cek_byte_size(enc));
    case key_algorithm::PBES2_HS256_A128KW:
    case key_algorithm::PBES2_HS384_A192KW:
    case key_algorithm::PBES2_HS512_A256KW: {
        auto k = must(jwk::from_oct(bytes("correct horse battery staple")));
        return {k, k};
    }
    default: {
        auto k = must(jwk::generate_ec(ec_curve::P256));
        return {k, pub(k)};
    }
    }
}

auto form_of(std::string_view form) -> jwe_json_format {
    return form == "general" ? jwe_json_format::general : jwe_json_format::flattened;
}

} // namespace

// ---------------------------------------------------------------------------
// RFC vectors: RFC 7520 §5, RFC 7516 Appendix A
// ---------------------------------------------------------------------------

TEST_CASE("RFC JWE vectors parse, decrypt and re-serialize exactly", "[jwe][vectors]") {
    const auto cases = load_vectors("jwe");
    REQUIRE(cases.size() == 18);
    int serializations = 0;

    for (const auto& c : cases) {
        INFO(c["source"].get<std::string>());
        const auto plaintext = b64(c["plaintext"]);
        std::vector<jwk> keys;
        for (const auto& k : c["keys"]) keys.push_back(must(jwk::from_json(k)));
        const auto options = c["legacy"].get<bool>() ? k_legacy : jwe_decrypt_options{};

        for (const char* form : {"compact", "general", "flattened"}) {
            if (!c.contains(form)) continue;
            INFO(form);
            ++serializations;
            const bool compact = std::string_view(form) == "compact";
            const std::string text = compact ? c[form].get<std::string>() : c[form].dump();

            const auto parsed = must(jwe::parse(text, k_all_algs, k_all_encs));
            REQUIRE(parsed.recipients().size() == keys.size());

            for (size_t i = 0; i < keys.size(); ++i) {
                const auto opened = must(parsed.decrypt_multi(keys[i], options));
                CHECK(opened.index == i);
                CHECK(same(opened.plaintext, plaintext));
            }
            if (keys.size() == 1) {
                CHECK(same(must(parsed.decrypt(keys[0], options)), plaintext));
            }

            // Re-serializing a parsed JWE reproduces it exactly.
            if (compact) {
                CHECK(must(parsed.compact()) == text);
            } else {
                // RFC 7520 §5.5/§5.6 label a JSON object with no "recipients"
                // as general; it is the flattened syntax.
                const auto fmt = c[form].contains("recipients") ? jwe_json_format::general
                                                                : jwe_json_format::flattened;
                CHECK(must(parsed.to_json(fmt)) == c[form]);
            }

            // Any change to the ciphertext is detected.
            json tampered = compact ? json() : c[form];
            std::string tampered_text = text;
            if (compact) {
                const auto pos = tampered_text.rfind('.') - 2; // inside the ciphertext
                tampered_text[pos] = tampered_text[pos] == 'A' ? 'B' : 'A';
            } else {
                auto ct = tampered["ciphertext"].get<std::string>();
                ct[0] = ct[0] == 'A' ? 'B' : 'A';
                tampered["ciphertext"] = ct;
                tampered_text = tampered.dump();
            }
            const auto bad = must(jwe::parse(tampered_text, k_all_algs, k_all_encs));
            CHECK(error_of(bad.decrypt_multi(keys[0], options)) == errc::decryption_failed);
        }
    }
    CHECK(serializations == 37);
}

TEST_CASE("RSA1_5 needs the legacy opt-in", "[jwe][legacy]") {
    const auto cases = load_vectors("jwe");
    const auto& c = cases[0];
    REQUIRE(c["source"] == "RFC 7520 §5.1");
    const auto key = must(jwk::from_json(c["keys"][0]));
    const auto parsed = must(jwe::parse(c["compact"].get<std::string>(), {key_algorithm::RSA1_5},
                                        {content_encryption::A128CBC_HS256}));
    CHECK(error_of(parsed.decrypt(key)) == errc::legacy_algorithm_disabled);
    CHECK(parsed.decrypt(key, k_legacy).has_value());

    CHECK(error_of(jwe::encrypt(bytes("x"), content_encryption::A128GCM, {key_algorithm::RSA1_5, pub(key)})) ==
          errc::legacy_algorithm_disabled);
    const auto sealed = must(jwe::encrypt(bytes("x"), content_encryption::A128GCM, {key_algorithm::RSA1_5, pub(key)},
                                          {.legacy = {.allow_rsa1_5 = true}}));
    CHECK(same(must(sealed.decrypt(key, k_legacy)), bytes("x")));
}

// ---------------------------------------------------------------------------
// Round trips
// ---------------------------------------------------------------------------

TEST_CASE("every algorithm and encryption round-trips", "[jwe]") {
    const auto plaintext = bytes("Live long and prosper.");
    for (auto alg : k_all_algs) {
        if (alg == key_algorithm::RSA1_5) continue; // covered above
        for (auto enc : k_all_encs) {
            INFO(to_string(alg) << " / " << to_string(enc));
            const auto [dkey, ekey] = keys_for(alg, enc);
            jwe_recipient recipient{alg, ekey};
            recipient.pbes2_count = 1000; // keep the test fast
            const auto sealed = must(jwe::encrypt(plaintext, enc, recipient));
            CHECK(sealed.recipients().front().joined.alg() == to_string(alg));

            for (const auto& text : {must(sealed.compact()), must(sealed.to_json_string()),
                                     must(sealed.to_json_string(jwe_json_format::flattened))}) {
                const auto parsed = must(jwe::parse(text, {alg}, {enc}));
                CHECK(same(must(parsed.decrypt(dkey)), plaintext));
            }
        }
    }
}

TEST_CASE("empty and large plaintexts, with and without compression", "[jwe][zip]") {
    const auto key = must(jwk::generate_oct(16));
    std::vector<uint8_t> large(100000);
    for (size_t i = 0; i < large.size(); ++i) large[i] = static_cast<uint8_t>("abcabcabd"[i % 9]);

    for (const auto& plaintext : {std::vector<uint8_t>{}, bytes("x"), large}) {
        for (bool compress : {false, true}) {
            INFO(plaintext.size() << " compress=" << compress);
            const auto sealed = must(jwe::encrypt(plaintext, content_encryption::A128GCM,
                                                  {key_algorithm::A128KW, key}, {.compress = compress}));
            CHECK(sealed.protected_header().zip().has_value() == compress);
            const auto parsed = must(jwe::parse(must(sealed.compact()), {key_algorithm::A128KW},
                                                {content_encryption::A128GCM}));
            CHECK(same(must(parsed.decrypt(key)), plaintext));
            if (compress && plaintext.size() == large.size()) {
                CHECK(sealed.to_json()->at("ciphertext").get<std::string>().size() < 2000);
            }
        }
    }
}

TEST_CASE("decompression is bounded", "[jwe][zip]") {
    const auto key = must(jwk::generate_oct(16));
    const std::vector<uint8_t> bomb(5 * 1024 * 1024, 0); // compresses ~1000:1
    const auto sealed = must(jwe::encrypt(bomb, content_encryption::A128GCM, {key_algorithm::A128KW, key},
                                          {.compress = true}));
    const auto parsed = must(jwe::parse(must(sealed.compact()), {key_algorithm::A128KW},
                                        {content_encryption::A128GCM}));

    // Default: max(250 KiB, 10x the ciphertext).
    CHECK(error_of(parsed.decrypt(key)) == errc::compression_error);
    CHECK(error_of(parsed.decrypt(key, {.max_decompressed_size = bomb.size() - 1})) == errc::compression_error);
    CHECK(must(parsed.decrypt(key, {.max_decompressed_size = bomb.size()})).size() == bomb.size());
}

TEST_CASE("multiple recipients", "[jwe][multi]") {
    const auto ec = must(jwk::generate_ec(ec_curve::P384));
    const auto x25519 = must(jwk::generate_okp(okp_curve::X25519));
    const auto kek = must(jwk::generate_oct(32));
    std::vector<jwe_recipient> recipients{
        {key_algorithm::RSA_OAEP_256, pub(rsa_key())},
        {key_algorithm::ECDH_ES_A256KW, pub(ec), must(header::from_json({{"apu", "QWxpY2U"}, {"kid", "ec"}}))},
        {key_algorithm::ECDH_ES_A128KW, pub(x25519)},
        {key_algorithm::A256GCMKW, kek},
    };
    const auto shared = must(header::from_json({{"jku", "https://example.com/keys"}}));
    const auto sealed = must(jwe::encrypt(bytes("to all"), content_encryption::A256CBC_HS512, recipients,
                                          {.shared_unprotected = shared, .aad = bytes("extra")}));

    CHECK(error_of(sealed.compact()) == errc::invalid_argument);
    CHECK(error_of(sealed.to_json(jwe_json_format::flattened)) == errc::invalid_argument);

    const auto parsed = must(jwe::parse(must(sealed.to_json_string()), k_all_algs, k_all_encs));
    REQUIRE(parsed.recipients().size() == 4);
    CHECK(parsed.recipients()[1].unprotected_header.kid() == "ec");
    CHECK(parsed.recipients()[1].joined.jku() == "https://example.com/keys");
    CHECK(same(parsed.aad(), bytes("extra")));

    const std::vector<jwk> keys{rsa_key(), ec, x25519, kek};
    for (size_t i = 0; i < keys.size(); ++i) {
        const auto opened = must(parsed.decrypt_multi(keys[i]));
        CHECK(opened.index == i);
        CHECK(same(opened.plaintext, bytes("to all")));
    }
    CHECK(error_of(parsed.decrypt(kek)) == errc::invalid_argument); // use decrypt_multi
    CHECK(error_of(parsed.decrypt_multi(must(jwk::generate_oct(16)))) == errc::algorithm_mismatch);
    CHECK(error_of(parsed.decrypt_multi(must(jwk::generate_oct(32)))) == errc::decryption_failed);

    // "dir" and "ECDH-ES" fix the CEK, so they can't be mixed.
    recipients.push_back({key_algorithm::dir, must(jwk::generate_oct(64))});
    CHECK(error_of(jwe::encrypt(bytes("x"), content_encryption::A256CBC_HS512, recipients)) ==
          errc::invalid_argument);

    // Every recipient's alg must be allowed, and the aad is authenticated.
    CHECK(error_of(jwe::parse(must(sealed.to_json_string()), {key_algorithm::A256GCMKW}, k_all_encs)) ==
          errc::algorithm_mismatch);
    json changed = must(sealed.to_json());
    changed["aad"] = base64url::encode(std::string_view("Extra"));
    CHECK(error_of(must(jwe::parse(changed.dump(), k_all_algs, k_all_encs)).decrypt_multi(kek)) ==
          errc::decryption_failed);
}

// ---------------------------------------------------------------------------
// Algorithm allowlists and key checks
// ---------------------------------------------------------------------------

TEST_CASE("the caller's algorithm lists decide", "[jwe][alg]") {
    const auto key = must(jwk::generate_oct(16));
    const auto token =
        must(must(jwe::encrypt(bytes("x"), content_encryption::A128GCM, {key_algorithm::A128KW, key})).compact());

    CHECK(jwe::parse(token, {key_algorithm::A128KW}, {content_encryption::A128GCM}).has_value());
    CHECK(error_of(jwe::parse(token, {key_algorithm::A256KW}, {content_encryption::A128GCM})) ==
          errc::algorithm_mismatch);
    CHECK(error_of(jwe::parse(token, {key_algorithm::A128KW}, {content_encryption::A256GCM})) ==
          errc::algorithm_mismatch);
    CHECK(error_of(jwe::parse(token, {}, k_all_encs)) == errc::invalid_argument);
    CHECK(error_of(jwe::parse(token, k_all_algs, {})) == errc::invalid_argument);

    auto with_header = [&](const json& h) {
        auto t = token;
        return base64url::encode(std::string_view(h.dump())) + t.substr(t.find('.'));
    };
    CHECK(error_of(jwe::parse(with_header({{"alg", "none"}, {"enc", "A128GCM"}}), k_all_algs, k_all_encs)) ==
          errc::unsupported_algorithm);
    CHECK(error_of(jwe::parse(with_header({{"alg", "A128KW"}, {"enc", "A128CTR"}}), k_all_algs, k_all_encs)) ==
          errc::unsupported_algorithm);
    CHECK(error_of(jwe::parse(with_header({{"alg", "A128KW"}, {"enc", "A128GCM"}, {"zip", "GZIP"}}), k_all_algs,
                              k_all_encs)) == errc::unsupported_algorithm);
    CHECK(error_of(jwe::parse(with_header({{"alg", "A128KW"}}), k_all_algs, k_all_encs)) == errc::invalid_header);
}

TEST_CASE("decryption checks the key", "[jwe][alg]") {
    const auto ec = must(jwk::generate_ec(ec_curve::P256));
    const auto sealed =
        must(jwe::encrypt(bytes("x"), content_encryption::A128GCM, {key_algorithm::ECDH_ES, pub(ec)}));
    const auto parsed = must(jwe::parse(must(sealed.compact()), k_all_algs, k_all_encs));

    CHECK(same(must(parsed.decrypt(ec)), bytes("x")));
    CHECK(error_of(parsed.decrypt(pub(ec))) == errc::invalid_key);                         // needs the private key
    CHECK(error_of(parsed.decrypt(rsa_key())) == errc::algorithm_mismatch);                // wrong type
    CHECK(error_of(parsed.decrypt(must(jwk::generate_ec(ec_curve::P384)))) == errc::invalid_header); // epk curve
    CHECK(error_of(parsed.decrypt(must(jwk::generate_ec(ec_curve::P256)))) == errc::decryption_failed);

    auto sig_only = ec;
    REQUIRE(sig_only.set_use("sig").has_value());
    CHECK(error_of(parsed.decrypt(sig_only)) == errc::invalid_key);
    auto wrap_only = ec;
    REQUIRE(wrap_only.set_key_ops(std::vector<std::string>{"unwrapKey"}).has_value());
    CHECK(error_of(parsed.decrypt(wrap_only)) == errc::invalid_key);

    // A key restricted to another alg.
    auto kek = must(jwk::generate_oct(16));
    const auto kw = must(jwe::parse(
        must(must(jwe::encrypt(bytes("x"), content_encryption::A128GCM, {key_algorithm::A128KW, kek})).compact()),
        k_all_algs, k_all_encs));
    REQUIRE(kek.set_algorithm("A128GCMKW").has_value());
    CHECK(error_of(kw.decrypt(kek)) == errc::algorithm_mismatch);

    // dir: the key size must match "enc"; "alg" may be "dir" or the enc.
    auto cek = must(jwk::generate_oct(16));
    const auto direct = must(jwe::parse(
        must(must(jwe::encrypt(bytes("x"), content_encryption::A128GCM, {key_algorithm::dir, cek})).compact()),
        k_all_algs, k_all_encs));
    CHECK(error_of(direct.decrypt(must(jwk::generate_oct(32)))) == errc::invalid_key);
    REQUIRE(cek.set_algorithm("dir").has_value());
    CHECK(direct.decrypt(cek).has_value());
    REQUIRE(cek.set_algorithm("A128GCM").has_value());
    CHECK(direct.decrypt(cek).has_value());
}

TEST_CASE("encryption checks the inputs", "[jwe][alg]") {
    const auto plaintext = bytes("x");
    const auto enc = content_encryption::A128GCM;
    CHECK(error_of(jwe::encrypt(plaintext, enc, std::span<const jwe_recipient>{})) == errc::invalid_argument);
    CHECK(error_of(jwe::encrypt(plaintext, enc, {key_algorithm::A128KW, must(jwk::generate_oct(32))})) ==
          errc::invalid_key);
    CHECK(error_of(jwe::encrypt(plaintext, enc, {key_algorithm::dir, must(jwk::generate_oct(32))})) ==
          errc::invalid_key);
    CHECK(error_of(jwe::encrypt(plaintext, enc, {key_algorithm::RSA_OAEP, must(jwk::generate_ec(ec_curve::P256))})) ==
          errc::algorithm_mismatch);
    CHECK(error_of(jwe::encrypt(plaintext, enc,
                                {key_algorithm::ECDH_ES, must(jwk::generate_okp(okp_curve::Ed25519))})) ==
          errc::algorithm_mismatch);

    jwe_recipient weak{key_algorithm::PBES2_HS256_A128KW, must(jwk::from_oct(bytes("pw")))};
    weak.pbes2_count = 10;
    CHECK_FALSE(jwe::encrypt(plaintext, enc, weak).has_value());

    // Library-owned parameters can't be supplied.
    const auto kek = must(jwk::generate_oct(16));
    const auto epk = must(pub(must(jwk::generate_ec(ec_curve::P256))).to_json());
    for (const char* name : {"alg", "enc", "zip", "epk", "iv", "tag", "p2s", "p2c"}) {
        INFO(name);
        const std::string_view n = name;
        const auto h = must(header::from_json({{name, n == "p2c" ? json(1000) : n == "epk" ? epk : json("AAAA")}}));
        CHECK(error_of(jwe::encrypt(plaintext, enc, {key_algorithm::A128KW, kek}, {.protected_header = h})) ==
              errc::invalid_argument);
        CHECK(error_of(jwe::encrypt(plaintext, enc, {key_algorithm::A128KW, kek, h})) == errc::invalid_argument);
    }
}

// ---------------------------------------------------------------------------
// Headers
// ---------------------------------------------------------------------------

TEST_CASE("kid, crit and unprotected headers", "[jwe][header]") {
    auto kek = must(jwk::generate_oct(32));
    kek.set_key_id("kek-1");
    const auto prot = must(header::from_json({{"crit", {"x-tenant"}}, {"x-tenant", "acme"}, {"typ", "JWE"}}));
    const auto sealed = must(jwe::encrypt(bytes("x"), content_encryption::A256GCM, {key_algorithm::A256KW, kek},
                                          {.protected_header = prot}));
    CHECK(sealed.protected_header().kid() == "kek-1");
    const auto token = must(sealed.compact());

    CHECK(error_of(jwe::parse(token, k_all_algs, k_all_encs)) == errc::unrecognized_critical_extension);
    const auto parsed = must(jwe::parse(token, k_all_algs, k_all_encs, {"x-tenant"}));
    CHECK(*parsed.recipients().front().joined.get("x-tenant") == "acme");

    auto other = must(jwk::generate_oct(32));
    other.set_key_id("kek-1");
    CHECK(same(must(parsed.decrypt(jwk_set({other, kek}))), bytes("x")));
    CHECK(error_of(parsed.decrypt(jwk_set({other}))) == errc::decryption_failed);
    kek.set_key_id("kek-2");
    CHECK(error_of(parsed.decrypt(jwk_set({kek}))) == errc::invalid_key);

    // Shared unprotected header: JSON only.
    const auto shared = must(header::from_json({{"cty", "text/plain"}}));
    const auto with_shared = must(jwe::encrypt(bytes("x"), content_encryption::A256GCM,
                                               {key_algorithm::A256KW, other}, {.shared_unprotected = shared}));
    CHECK(error_of(with_shared.compact()) == errc::invalid_argument);
    const auto p = must(jwe::parse(must(with_shared.to_json_string(jwe_json_format::flattened)), k_all_algs, k_all_encs));
    CHECK(p.recipients().front().joined.cty() == "text/plain");
    CHECK(same(must(p.decrypt(other)), bytes("x")));

    // ...and the protected header is authenticated: changing it fails.
    json changed = must(with_shared.to_json(jwe_json_format::flattened));
    changed["protected"] =
        base64url::encode(std::string_view(R"({"alg":"A256KW","enc":"A256GCM","kid":"kek-1","typ":"x"})"));
    CHECK(error_of(must(jwe::parse(changed.dump(), k_all_algs, k_all_encs)).decrypt(other)) ==
          errc::decryption_failed);
}

// ---------------------------------------------------------------------------
// Malformed input
// ---------------------------------------------------------------------------

TEST_CASE("malformed compact JWE", "[jwe][validation]") {
    const auto key = must(jwk::generate_oct(16));
    const auto token =
        must(must(jwe::encrypt(bytes("x"), content_encryption::A128GCM, {key_algorithm::A128KW, key})).compact());
    std::vector<std::string> parts;
    for (size_t start = 0;;) {
        const auto dot = token.find('.', start);
        parts.push_back(token.substr(start, dot - start));
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    REQUIRE(parts.size() == 5);
    auto join = [](const std::vector<std::string>& p) {
        std::string out;
        for (size_t i = 0; i < p.size(); ++i) out += (i ? "." : "") + p[i];
        return out;
    };
    auto replace = [&](size_t i, std::string v) {
        auto p = parts;
        p[i] = std::move(v);
        return join(p);
    };
    const std::vector<key_algorithm> kw{key_algorithm::A128KW, key_algorithm::dir};
    const std::vector<content_encryption> gcm{content_encryption::A128GCM};

    CHECK(error_of(jwe::parse("", kw, gcm)) == errc::invalid_token);
    CHECK(error_of(jwe::parse(token + ".", kw, gcm)) == errc::invalid_token);
    CHECK(error_of(jwe::parse(token.substr(0, token.rfind('.')), kw, gcm)) == errc::invalid_token);
    CHECK(error_of(jwe::parse(replace(0, ""), kw, gcm)) == errc::invalid_token);
    CHECK(error_of(jwe::parse(replace(1, "a+b"), kw, gcm)) == errc::invalid_base64);
    CHECK(error_of(jwe::parse(replace(2, base64url::encode(std::vector<uint8_t>(16))), kw, gcm)) == errc::invalid_iv);
    CHECK(error_of(jwe::parse(replace(4, base64url::encode(std::vector<uint8_t>(12))), kw, gcm)) ==
          errc::invalid_tag);

    // "dir" must have an empty encrypted key.
    const auto dir_header = base64url::encode(std::string_view(R"({"alg":"dir","enc":"A128GCM"})"));
    CHECK(error_of(jwe::parse(replace(0, dir_header), kw, gcm)) == errc::invalid_token);
}

TEST_CASE("malformed JSON JWE", "[jwe][validation]") {
    const auto key = must(jwk::generate_oct(16));
    const json good = must(must(jwe::encrypt(bytes("x"), content_encryption::A128GCM, {key_algorithm::A128KW, key}))
                               .to_json(jwe_json_format::flattened));
    const std::vector<key_algorithm> kw{key_algorithm::A128KW};
    const std::vector<content_encryption> gcm{content_encryption::A128GCM};
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

    CHECK(same(must(must(jwe::parse(good.dump(), kw, gcm)).decrypt(key)), bytes("x")));
    CHECK(error_of(jwe::parse("[]", kw, gcm)) == errc::invalid_token);
    CHECK(error_of(jwe::parse("{", kw, gcm)) == errc::serialization_error);
    for (const char* name : {"iv", "ciphertext", "tag"}) {
        INFO(name);
        CHECK(error_of(jwe::parse(without(name), kw, gcm)) == errc::invalid_token);
        CHECK(error_of(jwe::parse(with(name, 1), kw, gcm)) == errc::invalid_token);
    }
    CHECK(error_of(jwe::parse(with("protected", ""), kw, gcm)) == errc::invalid_token);
    CHECK(error_of(jwe::parse(with("protected", 1), kw, gcm)) == errc::invalid_token);
    CHECK(error_of(jwe::parse(with("unprotected", "x"), kw, gcm)) == errc::invalid_token);
    CHECK(error_of(jwe::parse(with("header", "x"), kw, gcm)) == errc::invalid_token);
    CHECK(error_of(jwe::parse(with("encrypted_key", 1), kw, gcm)) == errc::invalid_token);
    CHECK(error_of(jwe::parse(with("aad", 1), kw, gcm)) == errc::invalid_token);
    CHECK(error_of(jwe::parse(with("recipients", json::array()), kw, gcm)) == errc::invalid_token); // mixed

    // Parameter names must be disjoint across the header parts.
    CHECK(error_of(jwe::parse(with("unprotected", {{"enc", "A128GCM"}}), kw, gcm)) == errc::invalid_header);
    // "zip" must be protected.
    CHECK(error_of(jwe::parse(with("unprotected", {{"zip", "DEF"}}), kw, gcm)) == errc::invalid_header);

    const json general = must(must(jwe::encrypt(bytes("x"), content_encryption::A128GCM,
                                                {key_algorithm::A128KW, key})).to_json());
    json empty = general;
    empty["recipients"] = json::array();
    CHECK(error_of(jwe::parse(empty.dump(), kw, gcm)) == errc::invalid_token);

    std::string dup = good.dump();
    dup.insert(1, "\"iv\":\"AAAA\",");
    CHECK(error_of(jwe::parse(dup, kw, gcm)) == errc::serialization_error);
}

TEST_CASE("PBES2 and AES-GCM-KW header parameters are checked", "[jwe][validation]") {
    const auto pw = must(jwk::from_oct(bytes("password")));
    jwe_recipient r{key_algorithm::PBES2_HS256_A128KW, pw};
    r.pbes2_count = 1000;
    const json good = must(must(jwe::encrypt(bytes("x"), content_encryption::A128GCM, r)).to_json(jwe_json_format::flattened));
    auto with_protected = [&](const char* name, json value) {
        auto h = json::parse(as_string(must(base64url::decode(good["protected"].get<std::string>()))));
        if (value.is_null())
            h.erase(name);
        else
            h[name] = std::move(value);
        json j = good;
        j["protected"] = base64url::encode(std::string_view(h.dump()));
        return must(jwe::parse(j.dump(), {r.alg}, {content_encryption::A128GCM}));
    };

    CHECK(error_of(with_protected("p2c", 1000001).decrypt(pw)) == errc::invalid_header);
    CHECK(error_of(with_protected("p2c", 999).decrypt(pw)) == errc::invalid_header);
    CHECK(error_of(with_protected("p2c", nullptr).decrypt(pw)) == errc::invalid_header);
    CHECK(error_of(with_protected("p2s", "AAAA").decrypt(pw)) == errc::invalid_header); // 3 octets
    CHECK(error_of(with_protected("p2c", 1001).decrypt(pw)) == errc::decryption_failed);

    const auto kek = must(jwk::generate_oct(16));
    const json gcmkw = must(must(jwe::encrypt(bytes("x"), content_encryption::A128GCM,
                                              {key_algorithm::A128GCMKW, kek})).to_json(jwe_json_format::flattened));
    auto h = json::parse(as_string(must(base64url::decode(gcmkw["protected"].get<std::string>()))));
    h.erase("tag");
    json j = gcmkw;
    j["protected"] = base64url::encode(std::string_view(h.dump()));
    CHECK(error_of(must(jwe::parse(j.dump(), {key_algorithm::A128GCMKW}, {content_encryption::A128GCM})).decrypt(kek)) ==
          errc::invalid_header);
}
