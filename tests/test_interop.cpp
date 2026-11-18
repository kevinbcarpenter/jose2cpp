// Interoperability with go-jose v4 (PLAN.md Phase 2 item 11).
//
// tests/vectors/interop/gojose.json was produced by go-jose
// (tests/interop/go); every token is parsed, verified or decrypted with
// each listed key, and re-serialized. Set JOSE_INTEROP_GOJOSE to check a
// freshly generated file instead (the interop ctest fixtures do).
//
// tests/vectors/interop/jose2cpp.json is the other direction, produced by
// jose_interop_gen and verified by go-jose; it is also checked here so the
// checked-in file is known to be good.

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include "jose/jose.hpp"
#include "support/test_support.hpp"

#include <openssl/err.h>

#include <chrono>
#include <cstdlib>
#include <fstream>
#include <set>
#include <string>
#include <vector>

using namespace jose;
using json = nlohmann::json;
using jose::test::b64;
using Catch::Matchers::ContainsSubstring;

namespace {

template <typename T>
auto must(expected<T> v, const std::string& context) -> T {
    INFO(context << ": " << (v ? std::string("ok") : v.error().message));
    REQUIRE(v.has_value());
    return std::move(*v);
}

auto load(const std::string& path) -> json {
    std::ifstream in(path);
    INFO("interop vectors: " << path);
    REQUIRE(in.good());
    auto file = json::parse(in);
    REQUIRE(file.at("jws").is_array());
    REQUIRE(file.at("jwe").is_array());
    REQUIRE_FALSE(file.at("jws").empty());
    REQUIRE_FALSE(file.at("jwe").empty());
    return file;
}

auto vector_path(const char* env, const char* file) -> std::string {
    if (const char* p = std::getenv(env); p && *p) return p;
    return std::string(JOSE_TEST_VECTORS_DIR) + "/interop/" + file;
}

auto keys_of(const json& v, const std::string& context) -> std::vector<jwk> {
    std::vector<jwk> keys;
    for (const auto& k : v.at("keys")) keys.push_back(must(jwk::from_json(k), context + " key"));
    REQUIRE_FALSE(keys.empty());
    return keys;
}

// JSON forms are compared as values: member order differs between
// libraries, but nothing else may.
auto check_json_round_trip(const std::string& token, const json& reserialized, const std::string& context) {
    auto original = json::parse(token);
    // go-jose leaves a copy of the first recipient's "encrypted_key" at the
    // top level of general JWE JSON; jose2cpp ignores it and doesn't emit it.
    if (original.contains("recipients")) original.erase("encrypted_key");
    INFO(context << ": re-serialized JSON differs");
    CHECK(reserialized == original);
}

auto check_jws(const json& v) -> size_t {
    const auto name = "JWS " + v.at("name").get<std::string>();
    std::vector<signing_algorithm> algs;
    for (const auto& a : v.at("algorithms")) algs.push_back(must(parse_signing_algorithm(a.get<std::string>()), name));
    const auto keys = keys_of(v, name);
    const auto payload = b64(v.at("payload"));

    size_t checked = 0;
    for (const auto& [form, token_json] : v.at("serializations").items()) {
        const auto context = name + " (" + form + ")";
        const auto token = token_json.get<std::string>();
        auto parsed = must(form == "compact" ? jws::parse_compact(token, algs) : jws::parse_json(token, algs), context);
        CHECK(parsed.b64() == v.at("b64").get<bool>());

        for (size_t i = 0; i < keys.size(); ++i) {
            INFO(context << " key " << i);
            if (parsed.signatures().size() == 1) {
                CHECK(must(parsed.verify(keys[i]), context) == payload);
            } else {
                auto r = must(parsed.verify_multi(keys[i]), context);
                CHECK(r.index == i);
                CHECK(r.payload == payload);
            }
        }

        if (form == "compact") {
            CHECK(must(parsed.compact(), context) == token);
        } else {
            const auto format = json::parse(token).contains("signatures") ? jws_json_format::general
                                                                            : jws_json_format::flattened;
            check_json_round_trip(token, must(parsed.to_json(format), context), context);
        }
        ++checked;
    }
    return checked;
}

auto check_jwe(const json& v) -> size_t {
    const auto name = "JWE " + v.at("name").get<std::string>();
    std::vector<key_algorithm> algs;
    for (const auto& a : v.at("algorithms")) algs.push_back(must(parse_key_algorithm(a.get<std::string>()), name));
    const auto enc = must(parse_content_encryption(v.at("enc").get<std::string>()), name);
    const auto keys = keys_of(v, name);
    const auto plaintext = b64(v.at("plaintext"));
    const jwe_decrypt_options options{.legacy = {.allow_rsa1_5 = v.value("legacy", false)}};

    size_t checked = 0;
    for (const auto& [form, token_json] : v.at("serializations").items()) {
        const auto context = name + " (" + form + ")";
        const auto token = token_json.get<std::string>();
        auto parsed = must(form == "compact" ? jwe::parse_compact(token, algs, {enc})
                                             : jwe::parse_json(token, algs, {enc}),
                           context);

        for (size_t i = 0; i < keys.size(); ++i) {
            INFO(context << " key " << i);
            if (parsed.recipients().size() == 1) {
                auto out = must(parsed.decrypt(keys[i], options), context);
                CHECK(std::vector<uint8_t>(out.begin(), out.end()) == plaintext);
            } else {
                auto r = must(parsed.decrypt_multi(keys[i], options), context);
                CHECK(r.index == i);
                CHECK(std::vector<uint8_t>(r.plaintext.begin(), r.plaintext.end()) == plaintext);
            }
        }

        if (form == "compact") {
            CHECK(must(parsed.compact(), context) == token);
        } else {
            const auto format = json::parse(token).contains("recipients") ? jwe_json_format::general
                                                                             : jwe_json_format::flattened;
            check_json_round_trip(token, must(parsed.to_json(format), context), context);
        }
        ++checked;
    }
    return checked;
}

// A known incompatibility: jose2cpp must not accept any serialization of
// it. If it starts to, the difference is gone and the vector can move.
auto check_incompatible_jws(const json& v) -> void {
    const auto name = "JWS " + v.at("name").get<std::string>() + " [" + v.at("reason").get<std::string>() + "]";
    std::vector<signing_algorithm> algs;
    for (const auto& a : v.at("algorithms")) algs.push_back(must(parse_signing_algorithm(a.get<std::string>()), name));
    const auto keys = keys_of(v, name);
    for (const auto& [form, token_json] : v.at("serializations").items()) {
        INFO(name << " (" << form << ") must be rejected");
        const auto token = token_json.get<std::string>();
        auto parsed = form == "compact" ? jws::parse_compact(token, algs) : jws::parse_json(token, algs);
        if (!parsed) continue;
        for (const auto& key : keys) CHECK_FALSE(parsed->verify_multi(key));
    }
    ERR_clear_error();
}

// Parses and opens a JWT vector; the claims, or the first error.
auto jwt_claims(const json& v) -> expected<json> {
    const auto kind = v.at("kind").get<std::string>();
    std::vector<signing_algorithm> sig_algs;
    for (const auto& a : v.value("signature_algorithms", json::array()))
        sig_algs.push_back(must(parse_signing_algorithm(a.get<std::string>()), "alg"));
    std::vector<key_algorithm> key_algs;
    for (const auto& a : v.value("key_algorithms", json::array()))
        key_algs.push_back(must(parse_key_algorithm(a.get<std::string>()), "alg"));
    std::vector<content_encryption> encs;
    if (v.contains("enc")) encs.push_back(must(parse_content_encryption(v.at("enc").get<std::string>()), "enc"));
    const auto token = v.at("token").get<std::string>();

    if (kind == "signed") {
        auto parsed = jwt::parse_signed(token, sig_algs);
        if (!parsed) return jose::unexpected(parsed.error());
        return parsed->claims(must(jwk::from_json(v.at("verification_key")), "key"));
    }
    if (kind == "encrypted") {
        auto parsed = jwt::parse_encrypted(token, key_algs, encs);
        if (!parsed) return jose::unexpected(parsed.error());
        return parsed->claims(must(jwk::from_json(v.at("decryption_key")), "key"));
    }
    REQUIRE(kind == "nested");
    auto parsed = jwt::parse_signed_and_encrypted(token, key_algs, encs, sig_algs);
    if (!parsed) return jose::unexpected(parsed.error());
    auto inner = parsed->decrypt(must(jwk::from_json(v.at("decryption_key")), "key"));
    if (!inner) return jose::unexpected(inner.error());
    return inner->claims(must(jwk::from_json(v.at("verification_key")), "key"));
}

auto check_jwt(const json& v) -> void {
    INFO("JWT " << v.at("name").get<std::string>());
    const auto claims = must(jwt_claims(v), "claims");
    CHECK(claims == v.at("claims"));
    // The registered claims read back through jwt::registered_claims too.
    const auto registered = must(jwt::decode<jwt::registered_claims>(claims), "registered claims");
    CHECK(registered.subject == claims.at("sub").get<std::string>());
    CHECK(registered.expiry == jwt::numeric_date::from_seconds(claims.at("exp").get<std::int64_t>()));
    CHECK(json(registered.audience) == claims.at("aud"));
}

// go-jose's claims validation, case by case. The only difference is at the
// instant of expiry: RFC 7519 §4.1.4 says a token is expired "on or after"
// "exp", go-jose only after it.
auto check_validation(const json& cases) -> void {
    const std::set<std::string> expired_here{
        "at the instant of exp",
        "default leeway, at the instant of exp + 60s",
        "negative leeway, at the instant of exp - 10s",
    };
    std::set<std::string> differences_seen;
    for (const auto& v : cases) {
        const auto name = v.at("name").get<std::string>();
        INFO("validation case: " << name);
        const auto claims = must(jwt::decode<jwt::registered_claims>(v.at("claims")), "claims");
        const auto& e = v.at("expected");
        jwt::expected_claims want{
            .any_audience = e.value("aud", jwt::audience{}),
            .time = std::chrono::system_clock::time_point(
                std::chrono::seconds(v.at("time").get<std::int64_t>()) +
                std::chrono::duration_cast<std::chrono::system_clock::duration>(
                    std::chrono::nanoseconds(v.at("time_nanos").get<std::int64_t>()))),
        };
        if (e.contains("iss")) want.issuer = e.at("iss").get<std::string>();
        if (e.contains("sub")) want.subject = e.at("sub").get<std::string>();
        if (e.contains("jti")) want.id = e.at("jti").get<std::string>();
        const auto r = claims.validate(want, std::chrono::seconds(v.at("leeway").get<std::int64_t>()));

        auto go_jose = v.at("result").get<std::string>();
        if (expired_here.contains(name)) {
            CHECK(go_jose.empty()); // still a difference, or move the case out of the list
            differences_seen.insert(name);
            go_jose = "exp";
        }
        if (go_jose.empty()) {
            INFO((r ? std::string("ok") : r.error().message));
            CHECK(r.has_value());
        } else {
            REQUIRE_FALSE(r.has_value());
            CHECK_THAT(r.error().message, ContainsSubstring("\"" + go_jose + "\""));
        }
    }
    CHECK(differences_seen == expired_here);
}

auto check_file(const json& file) -> void {
    size_t jws_count = 0;
    size_t jwe_count = 0;
    for (const auto& v : file.at("jws")) jws_count += check_jws(v);
    for (const auto& v : file.at("jwe")) jwe_count += check_jwe(v);
    for (const auto& v : file.at("jwt")) check_jwt(v);
    CHECK_FALSE(file.at("jwt").empty());
    // The other library's incompatibilities must be rejected; jose2cpp's
    // own (RFC-conformant) ones must verify.
    const bool own = file.value("producer", "").starts_with("jose2cpp");
    for (const auto& v : file.value("jws_incompatible", json::array())) {
        if (own)
            jws_count += check_jws(v);
        else
            check_incompatible_jws(v);
    }
    // go-jose produces none of these yet; jose2cpp's own must work in jose2cpp.
    for (const auto& v : file.value("jwt_incompatible", json::array())) {
        if (own) {
            check_jwt(v);
        } else {
            INFO("JWT " << v.at("name").get<std::string>() << " must be rejected");
            CHECK_FALSE(jwt_claims(v));
            ERR_clear_error();
        }
    }
    if (!own) {
        REQUIRE(file.contains("jwt_validation"));
        CHECK(file.at("jwt_validation").size() >= 40);
        check_validation(file.at("jwt_validation"));
    }
    INFO("producer: " << file.value("producer", "?"));
    CHECK(jws_count > 0);
    CHECK(jwe_count > 0);
    CHECK(ERR_peek_error() == 0);
}

} // namespace

TEST_CASE("jose2cpp verifies and decrypts go-jose output", "[interop]") {
    const auto file = load(vector_path("JOSE_INTEROP_GOJOSE", "gojose.json"));
    REQUIRE(file.value("producer", "").starts_with("go-jose"));
    check_file(file);
}

TEST_CASE("jose2cpp's own interop vectors are valid", "[interop]") {
    const auto file = load(vector_path("JOSE_INTEROP_JOSE2CPP", "jose2cpp.json"));
    REQUIRE(file.value("producer", "").starts_with("jose2cpp"));
    check_file(file);
}
