#include <catch2/catch_test_macros.hpp>

#include "jose/jose.hpp"
#include "support/test_support.hpp"

#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/encoder.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <string>
#include <vector>

using namespace jose;
using json = nlohmann::json;
using jose::test::b64;
using jose::test::load_vectors;
using jose::test::self_signed_pem;

namespace {

auto must(expected<jwk> k) -> jwk {
    INFO((k ? std::string("ok") : k.error().message));
    REQUIRE(k.has_value());
    return std::move(*k);
}

auto json_of(const jwk& k) -> json {
    auto j = k.to_json();
    REQUIRE(j.has_value());
    return *j;
}

auto parse_error(const json& j) -> errc {
    auto k = jwk::from_json(j);
    INFO("JWK: " << j.dump());
    REQUIRE_FALSE(k.has_value());
    CHECK(ERR_peek_error() == 0);
    return k.error().code;
}

auto b64u(const std::vector<uint8_t>& v) -> std::string {
    return base64url::encode(std::span<const uint8_t>(v));
}

// Members that carry key material (as opposed to metadata).
const std::vector<std::string> k_private_members{"d", "p", "q", "dp", "dq", "qi", "k"};

auto rfc_key(std::string_view source_prefix, std::string_view kty) -> json {
    for (const auto& c : load_vectors("jwk"))
        if (c["source"].get<std::string>().starts_with(source_prefix) &&
            c["jwk"]["kty"] == kty)
            return c["jwk"];
    FAIL("no vector " << source_prefix << " / " << kty);
    return {};
}

auto to_pem(EVP_PKEY* key, bool priv) -> std::string {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio{BIO_new(BIO_s_mem()), BIO_free};
    REQUIRE((priv ? PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr)
                  : PEM_write_bio_PUBKEY(bio.get(), key)) == 1);
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio.get(), &data);
    return {data, static_cast<size_t>(len)};
}

} // namespace

// ---------------------------------------------------------------------------
// RFC vectors: RFC 7517 App. A/B, RFC 7638, RFC 8037, RFC 7520 §3/§5
// ---------------------------------------------------------------------------

TEST_CASE("RFC JWK vectors parse, round-trip and thumbprint", "[jwk][vectors]") {
    for (const auto& c : load_vectors("jwk")) {
        const auto& src = c["jwk"];
        DYNAMIC_SECTION(c["source"].get<std::string>() << " " << src["kty"].get<std::string>()) {
            ERR_clear_error();
            auto key = must(jwk::from_json(src));
            CHECK(key.is_private() == c["private"].get<bool>());
            CHECK(to_string(key.key_type()) == src["kty"].get<std::string>());

            // Every member of the vector serializes back byte-for-byte (the
            // RFCs use minimal RSA integers and full-size EC coordinates).
            auto out = json_of(key);
            for (const auto& [name, value] : src.items()) {
                INFO("member " << name);
                REQUIRE(out.contains(name));
                CHECK(out[name] == value);
            }

            // And re-parses to the same key.
            auto again = must(jwk::from_json(out));
            CHECK(json_of(again) == out);

            if (c.contains("thumbprint_sha256")) {
                auto tp = key.thumbprint();
                REQUIRE(tp.has_value());
                CHECK(b64u(*tp) == c["thumbprint_sha256"].get<std::string>());
            }

            if (key.key_type() != kty::oct) {
                auto pub = key.public_key();
                REQUIRE(pub.has_value());
                CHECK(pub->is_public());
                auto pub_json = json_of(*pub);
                for (const auto& m : k_private_members) CHECK_FALSE(pub_json.contains(m));
                CHECK(pub->thumbprint().value() == key.thumbprint().value());
                CHECK(pub->key_id() == key.key_id());
            }
            CHECK(ERR_peek_error() == 0);
        }
    }
}

TEST_CASE("RFC 7517 Appendix A JWK Sets", "[jwk][jwk_set][vectors]") {
    for (const auto& c : load_vectors("jwk_sets")) {
        DYNAMIC_SECTION(c["source"].get<std::string>()) {
            auto set = jwk_set::from_json(c["jwks"]);
            REQUIRE(set.has_value());
            CHECK(set->size() == 2);
            CHECK(set->skipped().empty());

            for (const auto& member : c["jwks"]["keys"]) {
                if (!member.contains("kid")) continue;
                auto found = set->find(member["kid"].get<std::string>());
                REQUIRE(found.has_value());
                CHECK(json_of(found->get())["kty"] == member["kty"]);
            }

            auto out = set->to_json();
            REQUIRE(out.has_value());
            auto again = jwk_set::from_json(*out);
            REQUIRE(again.has_value());
            CHECK(again->size() == 2);
        }
    }
}

TEST_CASE("jwk import agrees with the RFC signature vectors", "[jwk][vectors]") {
    // Cross-check against the Phase 1 known answers: keys imported through
    // jwk must verify the published signatures.
    for (const auto& c : load_vectors("signatures")) {
        if (c["key"]["kty"] == "oct") continue;
        DYNAMIC_SECTION(c["source"].get<std::string>()) {
            auto key = must(jwk::from_json(c["key"]));
            auto alg = parse_signing_algorithm(c["alg"].get<std::string>()).value();
            CHECK(verify(alg, key.pkey(), b64(c["message"]), b64(c["signature"])).has_value());
        }
    }
}

// ---------------------------------------------------------------------------
// Key validation (PLAN.md §Key Validation)
// ---------------------------------------------------------------------------

TEST_CASE("JWK structural errors", "[jwk][validation]") {
    ERR_clear_error();
    CHECK(jwk::from_json(std::string_view("{not json")).error().code == errc::serialization_error);
    CHECK(parse_error(json::array()) == errc::invalid_key);
    CHECK(parse_error(json{{"k", "AAAA"}}) == errc::invalid_key);                     // no kty
    CHECK(parse_error(json{{"kty", "DH"}}) == errc::unsupported_algorithm);           // unknown kty
    CHECK(parse_error(json{{"kty", "oct"}}) == errc::invalid_key);                    // no k
    CHECK(parse_error(json{{"kty", "oct"}, {"k", ""}}) == errc::invalid_key);         // empty k
    CHECK(parse_error(json{{"kty", "oct"}, {"k", "AAA="}}) == errc::invalid_base64);  // padded
    CHECK(parse_error(json{{"kty", "oct"}, {"k", 42}}) == errc::invalid_key);         // not a string
    CHECK(parse_error(json{{"kty", "oct"}, {"k", "AAAA"}, {"kid", 7}}) == errc::invalid_key);
}

TEST_CASE("RSA JWK validation", "[jwk][validation][rsa]") {
    ERR_clear_error();
    const auto good = rfc_key("RFC 7517 Appendix A.2", "RSA");
    REQUIRE(jwk::from_json(good).has_value());

    SECTION("CRT values are computed when absent") {
        auto j = good;
        j.erase("dp");
        j.erase("dq");
        j.erase("qi");
        auto key = must(jwk::from_json(j));
        auto out = json_of(key);
        CHECK(out["dp"] == good["dp"]);
        CHECK(out["dq"] == good["dq"]);
        CHECK(out["qi"] == good["qi"]);
    }

    SECTION("inconsistent CRT coefficient") {
        auto j = good;
        j["qi"] = good["dp"];
        CHECK(parse_error(j) == errc::invalid_key);
    }

    SECTION("private exponent from another key") {
        auto j = good;
        j["d"] = rfc_key("RFC 7520 Figure 4", "RSA")["d"];
        CHECK(parse_error(j) == errc::invalid_key);
    }

    SECTION("private key without prime factors") {
        auto j = good;
        j.erase("p");
        CHECK(parse_error(j) == errc::invalid_key);
    }

    SECTION("multi-prime keys are unsupported") {
        auto j = good;
        j["oth"] = json::array();
        CHECK(parse_error(j) == errc::unsupported_algorithm);
    }

    SECTION("keys under 2048 bits are rejected on every path") {
        auto ctx = make_evp_pkey_ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
        REQUIRE(EVP_PKEY_keygen_init(ctx.get()) == 1);
        REQUIRE(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 1024) == 1);
        EVP_PKEY* raw = nullptr;
        REQUIRE(EVP_PKEY_keygen(ctx.get(), &raw) == 1);
        auto weak = make_evp_pkey_ptr(raw);
        const auto pem = to_pem(weak.get(), true);

        CHECK(jwk::from_pkey(std::move(weak)).error().code == errc::key_size_too_small);
        CHECK(jwk::from_pem(pem).error().code == errc::key_size_too_small);
    }
}

TEST_CASE("EC JWK validation", "[jwk][validation][ec]") {
    ERR_clear_error();
    const auto p521 = rfc_key("RFC 7520 Figure 2", "EC");
    const auto p256 = rfc_key("RFC 7517 Appendix A.2", "EC");
    REQUIRE(jwk::from_json(p521).has_value());

    SECTION("coordinates must be full curve size") {
        // RFC 7520's P-521 x has a leading zero octet; dropping it must fail.
        auto x = b64(p521["x"]);
        REQUIRE(x.front() == 0);
        auto j = p521;
        j["x"] = b64u({x.begin() + 1, x.end()});
        CHECK(parse_error(j) == errc::invalid_curve_point);
    }

    SECTION("point not on the curve") {
        auto y = b64(p256["y"]);
        y.back() ^= 0x01;
        auto j = p256;
        j.erase("d");
        j["y"] = b64u(y);
        CHECK(parse_error(j) == errc::invalid_key);
    }

    SECTION("d does not match the public point") {
        auto j = p256;
        j["d"] = rfc_key("RFC 7520 Figure 120", "EC")["d"];
        CHECK(parse_error(j) == errc::invalid_key);
    }

    SECTION("d must be full curve size") {
        auto j = p256;
        j["d"] = "AQ";
        CHECK(parse_error(j) == errc::invalid_key);
    }

    SECTION("unsupported curves") {
        auto j = p256;
        j["crv"] = "secp256k1";
        CHECK(parse_error(j) == errc::unsupported_algorithm);

        auto ctx = make_evp_pkey_ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
        REQUIRE(EVP_PKEY_keygen_init(ctx.get()) == 1);
        REQUIRE(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_secp256k1) == 1);
        EVP_PKEY* raw = nullptr;
        REQUIRE(EVP_PKEY_keygen(ctx.get(), &raw) == 1);
        CHECK(jwk::from_pkey(make_evp_pkey_ptr(raw)).error().code == errc::unsupported_algorithm);
    }
}

TEST_CASE("OKP JWK validation", "[jwk][validation][okp]") {
    ERR_clear_error();
    const auto ed = rfc_key("RFC 8037 Appendix A.1", "OKP");

    SECTION("x must match d") {
        auto j = ed;
        auto x = b64(ed["x"]);
        x[0] ^= 0x01;
        j["x"] = b64u(x);
        CHECK(parse_error(j) == errc::invalid_key);
    }

    SECTION("sizes are checked per curve") {
        auto j = ed;
        j["crv"] = "Ed448"; // 32-byte values are wrong for Ed448
        CHECK(parse_error(j) == errc::invalid_key);
    }

    SECTION("unknown curve") {
        auto j = ed;
        j["crv"] = "Ed1174";
        CHECK(parse_error(j) == errc::unsupported_algorithm);
    }
}

TEST_CASE("JWK \"alg\" must suit the key", "[jwk][validation][alg]") {
    ERR_clear_error();
    auto with_alg = [](json j, const char* alg) {
        j["alg"] = alg;
        return j;
    };
    const auto p256 = rfc_key("RFC 7517 Appendix A.1", "EC");
    const auto rsa = rfc_key("RFC 7517 Appendix A.1", "RSA");
    const json oct16{{"kty", "oct"}, {"k", "GawgguFyGrWKav7AX4VKUg"}};

    CHECK(jwk::from_json(with_alg(p256, "ES256")).has_value());
    CHECK(jwk::from_json(with_alg(p256, "ECDH-ES+A128KW")).has_value());
    CHECK(parse_error(with_alg(p256, "ES384")) == errc::algorithm_mismatch);
    CHECK(parse_error(with_alg(p256, "RS256")) == errc::algorithm_mismatch);
    CHECK(parse_error(with_alg(rsa, "HS256")) == errc::algorithm_mismatch);
    CHECK(parse_error(with_alg(rsa, "EdDSA")) == errc::algorithm_mismatch);

    CHECK(jwk::from_json(with_alg(oct16, "A128KW")).has_value());
    CHECK(jwk::from_json(with_alg(oct16, "A128GCM")).has_value());
    CHECK(jwk::from_json(with_alg(oct16, "dir")).has_value());
    CHECK(parse_error(with_alg(oct16, "A256KW")) == errc::invalid_key);
    CHECK(parse_error(with_alg(oct16, "HS256")) == errc::key_too_short);
    CHECK(parse_error(with_alg(oct16, "ES256")) == errc::algorithm_mismatch);

    // Unregistered values are allowed (RFC 7517 §4.4).
    CHECK(jwk::from_json(with_alg(oct16, "x-custom")).has_value());

    auto okp = rfc_key("RFC 8037 Appendix A.6", "OKP"); // X25519
    CHECK(jwk::from_json(with_alg(okp, "ECDH-ES")).has_value());
    CHECK(parse_error(with_alg(okp, "EdDSA")) == errc::algorithm_mismatch);
}

TEST_CASE("JWK \"use\" and \"key_ops\"", "[jwk][validation]") {
    ERR_clear_error();
    json j{{"kty", "oct"}, {"k", "GawgguFyGrWKav7AX4VKUg"}};

    auto with = [&](json use, json ops) {
        auto x = j;
        if (!use.is_null()) x["use"] = use;
        if (!ops.is_null()) x["key_ops"] = ops;
        return x;
    };

    CHECK(jwk::from_json(with("enc", json{"wrapKey", "unwrapKey"})).has_value());
    CHECK(jwk::from_json(with("sig", json{"sign", "verify"})).has_value());
    CHECK(jwk::from_json(with("x-other", json{"anything"})).has_value());
    CHECK(parse_error(with("sig", json{"encrypt"})) == errc::invalid_key);
    CHECK(parse_error(with(nullptr, json{"sign", "sign"})) == errc::invalid_key);
    CHECK(parse_error(with(nullptr, "sign")) == errc::invalid_key);
    CHECK(parse_error(with(nullptr, json{"sign", 3})) == errc::invalid_key);
}

TEST_CASE("JWK x5c / x5t", "[jwk][validation][x5c]") {
    ERR_clear_error();
    json with_cert;
    for (const auto& c : load_vectors("jwk"))
        if (c["source"] == "RFC 7517 Appendix B") with_cert = c["jwk"];
    REQUIRE(with_cert.contains("x5c"));

    auto key = must(jwk::from_json(with_cert));
    REQUIRE(key.x5c().size() == 1);

    SECTION("x5t / x5t#S256 that match the leaf are accepted") {
        // Computed independently of the library.
        std::vector<uint8_t> sha1(20), sha256(32);
        const auto& der = key.x5c().front();
        REQUIRE(EVP_Digest(der.data(), der.size(), sha1.data(), nullptr, EVP_sha1(), nullptr) == 1);
        REQUIRE(EVP_Digest(der.data(), der.size(), sha256.data(), nullptr, EVP_sha256(), nullptr) == 1);
        auto j = with_cert;
        j["x5t"] = b64u(sha1);
        j["x5t#S256"] = b64u(sha256);
        auto k = must(jwk::from_json(j));
        CHECK(json_of(k)["x5t#S256"] == j["x5t#S256"]);

        sha1[0] ^= 1;
        j["x5t"] = b64u(sha1);
        CHECK(parse_error(j) == errc::invalid_key);
    }

    SECTION("leaf certificate must match the key") {
        auto j = with_cert;
        j["n"] = rfc_key("RFC 7517 Appendix A.1", "RSA")["n"];
        CHECK(parse_error(j) == errc::invalid_key);
    }

    SECTION("malformed x5c") {
        auto j = with_cert;
        j["x5c"] = json{"not base64!"};
        CHECK(parse_error(j) == errc::invalid_base64);
        j["x5c"] = json{"AAAA"};
        CHECK(parse_error(j) == errc::invalid_key);
        j["x5c"] = json::array();
        CHECK(parse_error(j) == errc::invalid_key);
    }

    SECTION("x5c is not allowed on oct keys") {
        json j{{"kty", "oct"}, {"k", "GawgguFyGrWKav7AX4VKUg"}, {"x5c", with_cert["x5c"]}};
        CHECK(parse_error(j) == errc::invalid_key);
    }
}

TEST_CASE("JWK setters re-validate", "[jwk]") {
    auto key = must(jwk::generate_ec(ec_curve::P256));
    REQUIRE(key.set_algorithm("ES256").has_value());
    auto bad = key.set_algorithm("ES512");
    REQUIRE_FALSE(bad.has_value());
    CHECK(bad.error().code == errc::algorithm_mismatch);
    CHECK(key.algorithm() == "ES256"); // unchanged on failure

    REQUIRE(key.set_use("sig").has_value());
    CHECK_FALSE(key.set_key_ops(std::vector<std::string>{"encrypt"}).has_value());
    CHECK_FALSE(key.key_ops().has_value());
}

// ---------------------------------------------------------------------------
// Generation, PEM, public_key, sets
// ---------------------------------------------------------------------------

TEST_CASE("generated keys are usable", "[jwk]") {
    const std::vector<uint8_t> msg{1, 2, 3};

    auto ec = must(jwk::generate_ec(ec_curve::P384));
    CHECK(ec.is_private());
    CHECK(ec.ec_crv() == ec_curve::P384);
    auto sig = sign(signing_algorithm::ES384, ec.pkey(), msg);
    REQUIRE(sig.has_value());
    auto pub = ec.public_key().value();
    CHECK(verify(signing_algorithm::ES384, pub.pkey(), msg, *sig).has_value());
    CHECK_FALSE(sign(signing_algorithm::ES384, pub.pkey(), msg).has_value()); // no private part
    ERR_clear_error();

    for (auto crv : {okp_curve::Ed25519, okp_curve::Ed448, okp_curve::X25519, okp_curve::X448}) {
        auto k = must(jwk::generate_okp(crv));
        CHECK(k.okp_crv() == crv);
        CHECK(must(jwk::from_json(json_of(k))).thumbprint().value() == k.thumbprint().value());
    }

    auto rsa = must(jwk::generate_rsa(2048));
    CHECK(json_of(rsa).contains("qi"));
    CHECK(jwk::generate_rsa(1024).error().code == errc::key_size_too_small);

    auto oct = must(jwk::generate_oct(32));
    CHECK(oct.oct().size() == 32);
    CHECK(oct.pkey() == nullptr);
    CHECK_FALSE(oct.public_key().has_value());
    CHECK(jwk::generate_oct(0).error().code == errc::invalid_key);
}

TEST_CASE("PEM import", "[jwk][pem]") {
    ERR_clear_error();
    auto ec = must(jwk::generate_ec(ec_curve::P256));
    const auto tp = ec.thumbprint().value();

    SECTION("private and public keys") {
        auto priv = must(jwk::from_pem(to_pem(ec.pkey(), true)));
        CHECK(priv.is_private());
        CHECK(priv.thumbprint().value() == tp);

        auto pub = must(jwk::from_pem(to_pem(ec.pkey(), false)));
        CHECK(pub.is_public());
        CHECK(pub.thumbprint().value() == tp);
    }

    SECTION("PKCS#1 RSA public key") {
        auto rsa = must(jwk::generate_rsa(2048));
        std::unique_ptr<BIO, decltype(&BIO_free)> bio{BIO_new(BIO_s_mem()), BIO_free};
        auto pub = rsa.public_key().value();
        // "RSA PUBLIC KEY" (PKCS#1) rather than SubjectPublicKeyInfo.
        auto ectx = OSSL_ENCODER_CTX_new_for_pkey(pub.pkey(), EVP_PKEY_PUBLIC_KEY, "PEM",
                                                  "type-specific", nullptr);
        REQUIRE(ectx != nullptr);
        REQUIRE(OSSL_ENCODER_to_bio(ectx, bio.get()) == 1);
        OSSL_ENCODER_CTX_free(ectx);
        char* data = nullptr;
        const long len = BIO_get_mem_data(bio.get(), &data);
        std::string pem(data, static_cast<size_t>(len));
        REQUIRE(pem.find("RSA PUBLIC KEY") != std::string::npos);
        CHECK(must(jwk::from_pem(pem)).thumbprint().value() == rsa.thumbprint().value());
    }

    SECTION("certificate chain becomes x5c") {
        auto other = must(jwk::generate_ec(ec_curve::P256));
        const auto chain = self_signed_pem(ec.pkey(), "leaf") + self_signed_pem(other.pkey(), "ca");
        auto key = must(jwk::from_pem(chain));
        CHECK(key.is_public());
        CHECK(key.thumbprint().value() == tp);
        CHECK(key.x5c().size() == 2);
        // x5c survives a JSON round-trip and still matches.
        CHECK(must(jwk::from_json(json_of(key))).x5c() == key.x5c());
    }

    SECTION("encrypted keys fail instead of prompting") {
        std::unique_ptr<BIO, decltype(&BIO_free)> bio{BIO_new(BIO_s_mem()), BIO_free};
        const char pass[] = "secret";
        REQUIRE(PEM_write_bio_PKCS8PrivateKey(bio.get(), ec.pkey(), EVP_aes_256_cbc(), pass,
                                              sizeof(pass) - 1, nullptr, nullptr) == 1);
        char* data = nullptr;
        const long len = BIO_get_mem_data(bio.get(), &data);
        auto r = jwk::from_pem(std::string(data, static_cast<size_t>(len)));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().code == errc::invalid_key);
        CHECK(ERR_peek_error() == 0);
    }

    SECTION("garbage") {
        CHECK_FALSE(jwk::from_pem("hello").has_value());
        CHECK_FALSE(jwk::from_pem("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
                        .has_value());
        CHECK(ERR_peek_error() == 0);
    }
}

TEST_CASE("jwk is a shared, copyable value", "[jwk]") {
    auto a = must(jwk::generate_ec(ec_curve::P256));
    a.set_key_id("a");
    auto b = a;
    b.set_key_id("b");
    CHECK(a.pkey() == b.pkey()); // shared, immutable key material
    CHECK(a.key_id() == "a");
    CHECK(b.key_id() == "b");
}

TEST_CASE("JWK Set skips unusable members", "[jwk][jwk_set]") {
    ERR_clear_error();
    json set{{"keys", json::array({
                          rfc_key("RFC 7517 Appendix A.1", "EC"),
                          json{{"kty", "DH"}, {"kid", "unknown-kty"}},
                          json{{"kty", "EC"}, {"crv", "P-256"}, {"x", "AA"}, {"y", "AA"}},
                          "not an object",
                          rfc_key("RFC 7517 Appendix A.1", "RSA"),
                      })}};
    auto parsed = jwk_set::from_json(set);
    REQUIRE(parsed.has_value());
    CHECK(parsed->size() == 2);
    CHECK(parsed->skipped().size() == 3);
    CHECK(parsed->find("2011-04-29").has_value());
    CHECK_FALSE(parsed->find("unknown-kty").has_value());
    CHECK(ERR_peek_error() == 0);

    CHECK_FALSE(jwk_set::from_json(json{{"key", json::array()}}).has_value());
    CHECK_FALSE(jwk_set::from_json(json{{"keys", "nope"}}).has_value());

    jwk_set dup;
    auto k = must(jwk::generate_oct(32));
    k.set_key_id("same");
    dup.add(k);
    dup.add(k);
    CHECK(dup.find_all("same").size() == 2);
}

TEST_CASE("EC keys serialize the same whatever their point conversion form", "[jwk][ec]") {
    // to_json reads x and y from the encoded point when it is uncompressed
    // and falls back to the coordinate parameters otherwise. OpenSSL 3.0
    // and 3.6 encode uncompressed whatever the form is set to, so this
    // checks that changing the form changes nothing; it doesn't reach the
    // fallback (the add_bn path every EC key used before). The fixed
    // vectors in "RFC JWK vectors parse, round-trip and thumbprint" check
    // the encoded-point x and y byte for byte on P-256, P-384 and P-521.
    for (auto crv : {ec_curve::P256, ec_curve::P384, ec_curve::P521}) {
        auto key = jwk::generate_ec(crv);
        REQUIRE(key.has_value());
        auto want = key->public_key()->to_json();
        REQUIRE(want.has_value());

        auto der = std::vector<unsigned char>();
        {
            unsigned char* buf = nullptr;
            int len = i2d_PUBKEY(key->pkey(), &buf);
            REQUIRE(len > 0);
            der.assign(buf, buf + len);
            OPENSSL_free(buf);
        }
        const unsigned char* p = der.data();
        EVP_PKEY* raw = d2i_PUBKEY(nullptr, &p, static_cast<long>(der.size()));
        REQUIRE(raw != nullptr);
        REQUIRE(EVP_PKEY_set_utf8_string_param(raw, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, "compressed") == 1);
        auto compressed = jwk::from_pkey(make_evp_pkey_ptr(raw));
        REQUIRE(compressed.has_value());
        auto got = compressed->to_json();
        REQUIRE(got.has_value());
        CHECK(*got == *want);
    }
}
