#include <catch2/catch_test_macros.hpp>

#include "jose/jose.hpp"
#include "support/test_support.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>

#include <string>
#include <vector>

using namespace jose;
using json = nlohmann::json;
using jose::test::load_vectors;
using jose::test::self_signed_pem;

namespace {

auto must(expected<header> h) -> header {
    INFO((h ? std::string("ok") : h.error().message));
    REQUIRE(h.has_value());
    return std::move(*h);
}

auto hdr(const json& j) -> header { return must(header::from_json(j)); }

auto parse_error(const json& j) -> errc {
    auto h = header::from_json(j);
    INFO("header: " << j.dump());
    REQUIRE_FALSE(h.has_value());
    CHECK(ERR_peek_error() == 0);
    return h.error().code;
}

auto join_error(header_context ctx, const json& prot, const json& shared = json::object(),
                const json& recipient = json::object(), const extension_set& known = {}) -> errc {
    auto h = join_headers(ctx, hdr(prot), hdr(shared), hdr(recipient), known);
    INFO("protected: " << prot.dump() << " shared: " << shared.dump() << " recipient: " << recipient.dump());
    REQUIRE_FALSE(h.has_value());
    return h.error().code;
}

auto b64u(std::span<const uint8_t> v) -> std::string { return base64url::encode(v); }

auto sha256(std::span<const uint8_t> in) -> std::vector<uint8_t> {
    std::vector<uint8_t> out(32);
    unsigned int len = 0;
    REQUIRE(EVP_Digest(in.data(), in.size(), out.data(), &len, EVP_sha256(), nullptr) == 1);
    return out;
}

auto public_json(const jwk& k) -> json {
    auto pub = k.public_key();
    REQUIRE(pub.has_value());
    auto j = pub->to_json();
    REQUIRE(j.has_value());
    return *j;
}

} // namespace

// ---------------------------------------------------------------------------
// RFC vectors
// ---------------------------------------------------------------------------

TEST_CASE("RFC JWS protected headers parse and join", "[header][vectors]") {
    int checked = 0;
    for (const auto& c : load_vectors("signatures")) {
        INFO(c["source"].get<std::string>());
        // "message" is the base64url JWS Signing Input; the RFC 8032 cases
        // are raw EdDSA messages, not JWS.
        const auto message = jose::test::b64_string(c["message"]);
        const auto dot = message.find('.');
        if (dot == std::string::npos) continue;
        const auto encoded = message.substr(0, dot);
        ++checked;

        const auto h = must(header::from_base64url(encoded));
        REQUIRE(h.alg().has_value());
        CHECK(*h.alg() == c["alg"].get<std::string>());

        const auto joined = join_headers(header_context::jws, h);
        INFO((joined ? "" : joined.error().message));
        CHECK(joined.has_value());
    }
    CHECK(checked == 9);
}

TEST_CASE("RFC 7797 §4.2 unencoded-payload header", "[header][vectors][b64]") {
    // {"alg":"HS256","b64":false,"crit":["b64"]}
    const auto h = must(header::from_base64url("eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19"));
    CHECK(h.alg() == "HS256");
    CHECK(h.b64() == false);
    CHECK(h.crit() == std::vector<std::string>{"b64"});

    // The library itself understands "b64" for JWS...
    CHECK(join_headers(header_context::jws, h).has_value());
    // ...but it is not a JWE extension.
    auto as_jwe = hdr({{"alg", "dir"}, {"enc", "A128GCM"}, {"b64", false}, {"crit", {"b64"}}});
    auto r = join_headers(header_context::jwe, as_jwe);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().code == errc::unrecognized_critical_extension);
}

TEST_CASE("RFC 7515 §4.1.11 crit example", "[header][crit]") {
    const json prot = {{"alg", "ES256"}, {"crit", {"exp"}}, {"exp", 1363284000}};

    // Safe by default: an empty allowlist rejects every extension.
    CHECK(join_error(header_context::jws, prot) == errc::unrecognized_critical_extension);

    auto ok = join_headers(header_context::jws, hdr(prot), {}, {}, {"exp"});
    REQUIRE(ok.has_value());
    REQUIRE(ok->get("exp") != nullptr);
    CHECK(*ok->get("exp") == 1363284000);

    // Every listed name must be understood.
    const json two = {{"alg", "ES256"}, {"crit", {"exp", "x-unknown"}}, {"exp", 1}, {"x-unknown", 2}};
    CHECK(join_error(header_context::jws, two, json::object(), json::object(), {"exp"}) ==
          errc::unrecognized_critical_extension);
    CHECK(join_headers(header_context::jws, hdr(two), {}, {}, {"exp", "x-unknown"}).has_value());

    // A critical extension must actually be present, and protected.
    CHECK(join_error(header_context::jws, {{"alg", "ES256"}, {"crit", {"exp"}}}, json::object(),
                     json::object(), {"exp"}) == errc::invalid_header);
    CHECK(join_error(header_context::jws, {{"alg", "ES256"}, {"crit", {"exp"}}}, {{"exp", 1}},
                     json::object(), {"exp"}) == errc::invalid_header);
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

TEST_CASE("header JSON structure", "[header][validation]") {
    CHECK(header::parse(R"({"alg":"HS256"})").has_value());
    CHECK(header::parse("{}").has_value());

    for (const char* text : {"", "[]", "\"alg\"", "{\"alg\":", "{\"alg\":\"HS256\"} x"}) {
        INFO(text);
        auto h = header::parse(text);
        REQUIRE_FALSE(h.has_value());
        CHECK((h.error().code == errc::invalid_header || h.error().code == errc::serialization_error));
    }

    CHECK(header::from_base64url("not base64!").error().code == errc::invalid_base64);
    CHECK(header::from_base64url(base64url::encode(std::string_view("[1]"))).error().code ==
          errc::invalid_header);
}

TEST_CASE("duplicate member names are rejected", "[header][validation]") {
    auto h = header::parse(R"({"alg":"HS256","alg":"none"})");
    REQUIRE_FALSE(h.has_value());
    CHECK(h.error().code == errc::serialization_error);
    CHECK(h.error().message.find("\"alg\"") != std::string::npos);

    // In nested objects too (here, the "jwk" member).
    h = header::parse(R"({"alg":"ES256","jwk":{"kty":"EC","kty":"EC"}})");
    REQUIRE_FALSE(h.has_value());
    CHECK(h.error().code == errc::serialization_error);

    // The same name in sibling objects is not a duplicate.
    CHECK(header::parse(R"({"a":{"x":1},"b":{"x":2},"c":[{"x":1},{"x":2}]})").has_value());

    // jwk / jwk_set parsing uses the same strict parser.
    CHECK(jwk::from_json(std::string_view(R"({"kty":"oct","k":"AAAA","k":"BBBB"})")).error().code ==
          errc::serialization_error);
    CHECK(jwk_set::from_json(std::string_view(R"({"keys":[],"keys":[]})")).error().code ==
          errc::serialization_error);
}

TEST_CASE("registered parameter types", "[header][validation]") {
    const json base = {{"alg", "HS256"}};
    auto with = [&](const char* name, json value) {
        json j = base;
        j[name] = std::move(value);
        return j;
    };

    for (const char* name : {"alg", "enc", "zip", "kid", "typ", "cty", "jku", "x5u"}) {
        INFO(name);
        CHECK(parse_error(with(name, 1)) == errc::invalid_header);
        CHECK(parse_error(with(name, json::array())) == errc::invalid_header);
    }

    for (const char* name : {"apu", "apv", "iv", "tag", "p2s", "x5t", "x5t#S256"}) {
        INFO(name);
        CHECK(parse_error(with(name, 1)) == errc::invalid_header);
        CHECK(parse_error(with(name, "AA=")) == errc::invalid_base64);
    }
    CHECK(parse_error(with("x5t", b64u(std::vector<uint8_t>(32)))) == errc::invalid_header);
    CHECK(parse_error(with("x5t#S256", b64u(std::vector<uint8_t>(20)))) == errc::invalid_header);

    for (const json& bad : {json(0), json(-1), json(1.5), json("1000"), json(true)}) {
        INFO(bad.dump());
        CHECK(parse_error(with("p2c", bad)) == errc::invalid_header);
    }

    CHECK(parse_error(with("b64", "false")) == errc::invalid_header);
    CHECK(parse_error(with("b64", 0)) == errc::invalid_header);

    // Unknown parameters are kept, whatever their type.
    auto h = hdr(with("x-anything", {{"nested", {1, 2, 3}}}));
    REQUIRE(h.get("x-anything") != nullptr);
    CHECK((*h.get("x-anything"))["nested"].size() == 3);
}

TEST_CASE("crit structure", "[header][validation][crit]") {
    auto with_crit = [](json crit) { return json{{"alg", "HS256"}, {"crit", std::move(crit)}, {"x", 1}}; };

    CHECK(hdr(with_crit({"x"})).crit() == std::vector<std::string>{"x"});

    CHECK(parse_error(with_crit(json::array())) == errc::invalid_header); // empty list
    CHECK(parse_error(with_crit("x")) == errc::invalid_header);           // not an array
    CHECK(parse_error(with_crit({1})) == errc::invalid_header);
    CHECK(parse_error(with_crit({""})) == errc::invalid_header);
    CHECK(parse_error(with_crit({"x", "x"})) == errc::invalid_header);

    // Registered names may never be critical (RFC 7515 §4.1.11).
    for (const char* name : {"alg", "enc", "kid", "crit", "zip", "epk", "p2c", "x5t#S256"}) {
        INFO(name);
        CHECK(is_registered_header_parameter(name));
        CHECK(parse_error(with_crit({name})) == errc::invalid_header);
    }
    CHECK_FALSE(is_registered_header_parameter("b64"));
    CHECK_FALSE(is_registered_header_parameter("exp"));
}

TEST_CASE("jwk and epk must be public asymmetric keys", "[header][validation]") {
    const auto ec = jwk::generate_ec(ec_curve::P256);
    REQUIRE(ec.has_value());
    const json pub = public_json(*ec);
    auto priv = ec->to_json();
    REQUIRE(priv.has_value());

    for (const char* name : {"jwk", "epk"}) {
        INFO(name);
        const auto h = hdr({{"alg", "ES256"}, {name, pub}});
        const auto& key = std::string_view(name) == "jwk" ? h.jwk() : h.epk();
        REQUIRE(key.has_value());
        CHECK(key->ec_crv() == ec_curve::P256);
        CHECK(key->is_public());
        CHECK(*key->thumbprint() == *ec->thumbprint());

        CHECK(parse_error({{"alg", "ES256"}, {name, *priv}}) == errc::invalid_header);
        CHECK(parse_error({{"alg", "ES256"}, {name, {{"kty", "oct"}, {"k", "AAAAAAAAAAAAAAAAAAAAAA"}}}}) ==
              errc::invalid_header);
        CHECK(parse_error({{"alg", "ES256"}, {name, "not an object"}}) == errc::invalid_header);
        json broken = pub;
        broken["x"] = b64u(std::vector<uint8_t>(32, 0xff));
        CHECK(parse_error({{"alg", "ES256"}, {name, broken}}) == errc::invalid_header);
    }
}

TEST_CASE("x5c and its thumbprints", "[header][validation][x5c]") {
    const auto ec = jwk::generate_ec(ec_curve::P256);
    REQUIRE(ec.has_value());
    const auto cert = jwk::from_pem(self_signed_pem(ec->pkey(), "leaf"));
    REQUIRE(cert.has_value());
    const auto cert_json = cert->to_json();
    REQUIRE(cert_json.has_value());
    const json x5c = (*cert_json)["x5c"];
    const auto& der = cert->x5c().front();

    const auto h = hdr({{"alg", "ES256"}, {"x5c", x5c}, {"x5t#S256", b64u(sha256(der))}});
    REQUIRE(h.x5c().size() == 1);
    CHECK(h.x5c().front() == der);
    CHECK(h.x5t_s256() == sha256(der));

    CHECK(parse_error({{"alg", "ES256"}, {"x5c", x5c}, {"x5t#S256", b64u(std::vector<uint8_t>(32))}}) ==
          errc::invalid_header);
    CHECK(parse_error({{"alg", "ES256"}, {"x5c", x5c}, {"x5t", b64u(std::vector<uint8_t>(20))}}) ==
          errc::invalid_header);
    CHECK(parse_error({{"alg", "ES256"}, {"x5c", json::array()}}) == errc::invalid_header);
    CHECK(parse_error({{"alg", "ES256"}, {"x5c", {1}}}) == errc::invalid_header);
    CHECK(parse_error({{"alg", "ES256"}, {"x5c", {"not base64"}}}) == errc::invalid_header);
    CHECK(parse_error({{"alg", "ES256"}, {"x5c", {"AAAA"}}}) == errc::invalid_header); // not a certificate
}

TEST_CASE("typed accessors", "[header]") {
    const auto epk = jwk::generate_okp(okp_curve::X25519);
    REQUIRE(epk.has_value());
    const std::vector<uint8_t> apu{'A', 'l', 'i', 'c', 'e'};
    const std::vector<uint8_t> salt(16, 7);

    const auto h = hdr({
        {"alg", "PBES2-HS256+A128KW"},
        {"enc", "A128GCM"},
        {"zip", "DEF"},
        {"kid", "k1"},
        {"typ", "JWT"},
        {"cty", "JWT"},
        {"jku", "https://example.com/jwks"},
        {"x5u", "https://example.com/cert"},
        {"epk", public_json(*epk)},
        {"apu", b64u(apu)},
        {"apv", ""},
        {"iv", b64u(std::vector<uint8_t>(12, 1))},
        {"tag", b64u(std::vector<uint8_t>(16, 2))},
        {"p2s", b64u(salt)},
        {"p2c", 310000},
        {"x-custom", "value"},
    });

    CHECK(h.alg() == "PBES2-HS256+A128KW");
    CHECK(h.enc() == "A128GCM");
    CHECK(h.zip() == "DEF");
    CHECK(h.kid() == "k1");
    CHECK(h.typ() == "JWT");
    CHECK(h.cty() == "JWT");
    CHECK(h.jku() == "https://example.com/jwks");
    CHECK(h.x5u() == "https://example.com/cert");
    REQUIRE(h.epk().has_value());
    CHECK(h.epk()->okp_crv() == okp_curve::X25519);
    CHECK(h.apu() == apu);
    CHECK(h.apv() == std::vector<uint8_t>{});
    CHECK(h.iv() == std::vector<uint8_t>(12, 1));
    CHECK(h.tag() == std::vector<uint8_t>(16, 2));
    CHECK(h.p2s() == salt);
    CHECK(h.p2c() == 310000u);
    CHECK(h.get("x-custom") != nullptr);

    // Absent parameters.
    CHECK_FALSE(h.jwk().has_value());
    CHECK(h.x5c().empty());
    CHECK_FALSE(h.x5t().has_value());
    CHECK_FALSE(h.b64().has_value());
    CHECK(h.crit().empty());
    CHECK(h.get("missing") == nullptr);
    CHECK_FALSE(h.contains("missing"));
}

TEST_CASE("set and erase re-validate", "[header]") {
    auto h = hdr({{"alg", "HS256"}});

    REQUIRE(h.set("kid", "k1").has_value());
    CHECK(h.kid() == "k1");

    // A bad value leaves the header untouched.
    auto r = h.set("kid", 5);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().code == errc::invalid_header);
    CHECK(h.kid() == "k1");
    CHECK_FALSE(h.set("crit", {"alg"}).has_value());
    CHECK_FALSE(h.contains("crit"));

    const auto ec = jwk::generate_ec(ec_curve::P384);
    REQUIRE(ec.has_value());
    REQUIRE(h.set("jwk", public_json(*ec)).has_value());
    REQUIRE(h.jwk().has_value());
    CHECK(h.jwk()->ec_crv() == ec_curve::P384);

    CHECK(h.erase("jwk"));
    CHECK_FALSE(h.jwk().has_value());
    CHECK_FALSE(h.erase("jwk"));
    CHECK(h.to_json() == json{{"alg", "HS256"}, {"kid", "k1"}});
}

// ---------------------------------------------------------------------------
// join_headers
// ---------------------------------------------------------------------------

TEST_CASE("joining header parts", "[header][join]") {
    const auto ctx = header_context::jws;

    // Parameters may come from any part...
    auto joined = join_headers(ctx, hdr({{"alg", "ES256"}}), hdr({{"kid", "k1"}}), hdr({{"x-r", 1}}));
    REQUIRE(joined.has_value());
    CHECK(joined->to_json() == json{{"alg", "ES256"}, {"kid", "k1"}, {"x-r", 1}});

    // ...including "alg", with an empty protected header (JSON serialization).
    CHECK(join_headers(ctx, header{}, hdr({{"alg", "ES256"}})).has_value());

    // ...but only once.
    CHECK(join_error(ctx, {{"alg", "ES256"}}, {{"alg", "ES256"}}) == errc::invalid_header);
    CHECK(join_error(ctx, {{"alg", "ES256"}}, {{"kid", "a"}}, {{"kid", "a"}}) == errc::invalid_header);
    CHECK(join_error(ctx, {{"alg", "ES256"}, {"x", 1}}, json::object(), {{"x", 1}}) == errc::invalid_header);

    // "alg" is required; JWE also needs "enc".
    CHECK(join_error(ctx, {{"kid", "k1"}}) == errc::invalid_header);
    CHECK(join_error(header_context::jwe, {{"alg", "dir"}}) == errc::invalid_header);
    CHECK(join_headers(header_context::jwe, hdr({{"alg", "dir"}}), hdr({{"enc", "A128GCM"}})).has_value());
}

TEST_CASE("integrity-protected-only parameters", "[header][join]") {
    // "crit" anywhere but the protected header.
    CHECK(join_error(header_context::jws, {{"alg", "ES256"}, {"x", 1}}, {{"crit", {"x"}}},
                     json::object(), {"x"}) == errc::invalid_header);
    CHECK(join_error(header_context::jws, {{"alg", "ES256"}, {"x", 1}}, json::object(),
                     {{"crit", {"x"}}}, {"x"}) == errc::invalid_header);

    // "b64" (JWS) must be protected and listed in "crit".
    CHECK(join_error(header_context::jws, {{"alg", "HS256"}}, {{"b64", false}}) == errc::invalid_header);
    CHECK(join_error(header_context::jws, {{"alg", "HS256"}, {"b64", false}}) == errc::invalid_header);

    // "zip" (JWE) must be protected.
    CHECK(join_error(header_context::jwe, {{"alg", "dir"}, {"enc", "A128GCM"}}, {{"zip", "DEF"}}) ==
          errc::invalid_header);
    CHECK(join_headers(header_context::jwe, hdr({{"alg", "dir"}, {"enc", "A128GCM"}, {"zip", "DEF"}}))
              .has_value());
}
