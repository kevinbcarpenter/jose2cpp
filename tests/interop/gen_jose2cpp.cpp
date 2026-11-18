// Writes jose2cpp-produced JWS and JWE in the interop vector format, for
// go-jose to verify (tests/interop/go: `go run . verify <file>`).
//
//   jose_interop_gen <out.json>
//
// Only algorithms go-jose v4 supports are included: no Ed448, and no
// X25519/X448 key agreement (go-jose's ECDH-ES is NIST curves only).

#include "jose/jose.hpp"

#include <nlohmann/json.hpp>

#include <cstdio>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

using namespace jose;
using json = nlohmann::json;

namespace {

template <typename T>
auto must(expected<T> v, const std::string& what) -> T {
    if (!v) throw std::runtime_error(what + ": " + v.error().message);
    return std::move(*v);
}

auto bytes(std::string_view s) -> std::vector<uint8_t> {
    return {s.begin(), s.end()};
}

class key_source {
public:
    key_source()
        : rsa_(must(jwk::generate_rsa(2048), "RSA key")),
          ed_(must(jwk::generate_okp(okp_curve::Ed25519), "Ed25519 key")) {
        for (auto crv : {ec_curve::P256, ec_curve::P384, ec_curve::P521})
            ec_.emplace(crv, must(jwk::generate_ec(crv), "EC key"));
    }

    // Each use gets its own "kid", so headers carry one as in real use.
    auto labelled(jwk key) -> jwk {
        key.set_key_id("cpp-" + std::to_string(++kids_));
        return key;
    }
    auto rsa() -> jwk { return labelled(rsa_); }
    auto ec(ec_curve crv) -> jwk { return labelled(ec_.at(crv)); }
    auto ed25519() -> jwk { return labelled(ed_); }
    auto oct(size_t n) -> jwk { return labelled(must(jwk::generate_oct(n), "oct key")); }
    auto password() -> jwk { return labelled(must(jwk::from_oct(bytes("correct horse battery staple")), "password")); }

private:
    jwk rsa_;
    jwk ed_;
    std::map<ec_curve, jwk> ec_;
    int kids_ = 0;
};

auto key_json(const jwk& key) -> json {
    return must(key.to_json(), "key JSON");
}

auto public_json(const jwk& key) -> json {
    return key.key_type() == kty::oct ? key_json(key) : key_json(must(key.public_key(), "public key"));
}

auto signing_key_for(key_source& keys, signing_algorithm alg) -> jwk {
    switch (alg) {
    case signing_algorithm::HS256: return keys.oct(32);
    case signing_algorithm::HS384: return keys.oct(48);
    case signing_algorithm::HS512: return keys.oct(64);
    case signing_algorithm::ES256: return keys.ec(ec_curve::P256);
    case signing_algorithm::ES384: return keys.ec(ec_curve::P384);
    case signing_algorithm::ES512: return keys.ec(ec_curve::P521);
    case signing_algorithm::EdDSA: return keys.ed25519();
    default: return keys.rsa();
    }
}

auto jws_vector(const std::string& name, const std::vector<jws_signer>& signers, std::span<const uint8_t> payload,
                bool b64) -> json {
    auto signed_ = must(jws::sign(payload, signers, {.b64 = b64}), name);
    json v{{"name", name}, {"payload", base64url::encode(payload)}, {"b64", b64}};
    for (const auto& s : signers) {
        v["algorithms"].push_back(to_string(s.alg));
        v["keys"].push_back(public_json(std::get<jwk>(s.key)));
    }
    if (signers.size() == 1) {
        v["serializations"]["compact"] = must(signed_.compact(), name);
        v["serializations"]["json"] = must(signed_.to_json_string(jws_json_format::flattened), name);
    } else {
        v["serializations"]["json"] = must(signed_.to_json_string(jws_json_format::general), name);
    }
    return v;
}

auto generate_jws(key_source& keys) -> json {
    const auto payload = bytes(R"({"iss":"jose2cpp","msg":"interop ✓","n":42})");
    json out = json::array();
    for (auto alg : {signing_algorithm::HS256, signing_algorithm::HS384, signing_algorithm::HS512,
                     signing_algorithm::RS256, signing_algorithm::RS384, signing_algorithm::RS512,
                     signing_algorithm::PS256, signing_algorithm::PS384, signing_algorithm::PS512,
                     signing_algorithm::ES256, signing_algorithm::ES384, signing_algorithm::ES512,
                     signing_algorithm::EdDSA}) {
        out.push_back(jws_vector(std::string(to_string(alg)), {{alg, signing_key_for(keys, alg)}}, payload, true));
    }
    out.push_back(jws_vector("multi-signature",
                             {{signing_algorithm::RS256, keys.rsa()},
                              {signing_algorithm::ES384, keys.ec(ec_curve::P384)},
                              {signing_algorithm::EdDSA, keys.ed25519()}},
                             payload, true));
    return out;
}

// RFC 7797 tokens, which go-jose can't read (it expects a base64url
// payload even when "b64" is false).
auto generate_incompatible_jws(key_source& keys) -> json {
    auto v = jws_vector("b64=false", {{signing_algorithm::HS256, keys.oct(32)}},
                        bytes("unencoded payload, no dots"), false);
    v["reason"] = "go-jose base64url-encodes the payload of b64=false tokens (RFC 7797 §3, §5)";
    return json::array({v});
}

struct recipient_and_key {
    jwe_recipient recipient;
    jwk key; // what decrypts it
};

auto recipient_for(key_source& keys, key_algorithm alg, content_encryption enc, ec_curve crv = ec_curve::P256)
    -> recipient_and_key {
    switch (alg) {
    case key_algorithm::RSA1_5:
    case key_algorithm::RSA_OAEP:
    case key_algorithm::RSA_OAEP_256: {
        auto key = keys.rsa();
        return {{alg, must(key.public_key(), "public key")}, key};
    }
    case key_algorithm::ECDH_ES:
    case key_algorithm::ECDH_ES_A128KW:
    case key_algorithm::ECDH_ES_A192KW:
    case key_algorithm::ECDH_ES_A256KW: {
        auto key = keys.ec(crv);
        return {{alg, must(key.public_key(), "public key")}, key};
    }
    case key_algorithm::dir: {
        auto key = keys.oct(cek_byte_size(enc));
        return {{alg, key}, key};
    }
    case key_algorithm::PBES2_HS256_A128KW:
    case key_algorithm::PBES2_HS384_A192KW:
    case key_algorithm::PBES2_HS512_A256KW: {
        auto key = keys.password();
        return {{.alg = alg, .key = key, .pbes2_count = 1000}, key}; // fast; one vector uses the default
    }
    case key_algorithm::A128KW:
    case key_algorithm::A128GCMKW: {
        auto key = keys.oct(16);
        return {{alg, key}, key};
    }
    case key_algorithm::A192KW:
    case key_algorithm::A192GCMKW: {
        auto key = keys.oct(24);
        return {{alg, key}, key};
    }
    default: {
        auto key = keys.oct(32);
        return {{alg, key}, key};
    }
    }
}

auto jwe_vector(const std::string& name, content_encryption enc, const std::vector<recipient_and_key>& rs,
                std::span<const uint8_t> plaintext, const jwe_encrypt_options& options) -> json {
    std::vector<jwe_recipient> recipients;
    for (const auto& r : rs) recipients.push_back(r.recipient);
    auto sealed = must(jwe::encrypt(plaintext, enc, recipients, options), name);

    json v{{"name", name}, {"enc", to_string(enc)}, {"plaintext", base64url::encode(plaintext)}};
    for (const auto& r : rs) {
        v["algorithms"].push_back(to_string(r.recipient.alg));
        v["keys"].push_back(key_json(r.key));
        if (r.recipient.alg == key_algorithm::RSA1_5) v["legacy"] = true;
    }
    if (auto compact = sealed.compact()) v["serializations"]["compact"] = *compact;
    v["serializations"]["json"] =
        must(sealed.to_json_string(rs.size() == 1 ? jwe_json_format::flattened : jwe_json_format::general), name);
    return v;
}

auto generate_jwe(key_source& keys) -> json {
    const auto plaintext = bytes("jose2cpp → go-jose: The true sign of intelligence is not knowledge but imagination.");
    const jwe_encrypt_options defaults{.legacy = {.allow_rsa1_5 = true}};
    json out = json::array();

    for (auto alg : {key_algorithm::RSA1_5, key_algorithm::RSA_OAEP, key_algorithm::RSA_OAEP_256,
                     key_algorithm::A128KW, key_algorithm::A192KW, key_algorithm::A256KW, key_algorithm::dir,
                     key_algorithm::ECDH_ES, key_algorithm::ECDH_ES_A128KW, key_algorithm::ECDH_ES_A192KW,
                     key_algorithm::ECDH_ES_A256KW, key_algorithm::A128GCMKW, key_algorithm::A192GCMKW,
                     key_algorithm::A256GCMKW, key_algorithm::PBES2_HS256_A128KW,
                     key_algorithm::PBES2_HS384_A192KW, key_algorithm::PBES2_HS512_A256KW}) {
        for (auto enc : {content_encryption::A128CBC_HS256, content_encryption::A192CBC_HS384,
                         content_encryption::A256CBC_HS512, content_encryption::A128GCM,
                         content_encryption::A192GCM, content_encryption::A256GCM}) {
            out.push_back(jwe_vector(std::string(to_string(alg)) + " " + std::string(to_string(enc)), enc,
                                     {recipient_for(keys, alg, enc)}, plaintext, defaults));
        }
    }

    for (auto crv : {ec_curve::P384, ec_curve::P521}) {
        for (auto alg : {key_algorithm::ECDH_ES, key_algorithm::ECDH_ES_A256KW}) {
            out.push_back(jwe_vector(std::string(to_string(alg)) + " " + std::string(to_string(crv)),
                                     content_encryption::A256GCM,
                                     {recipient_for(keys, alg, content_encryption::A256GCM, crv)}, plaintext,
                                     defaults));
        }
    }

    std::vector<uint8_t> long_text;
    for (int i = 0; i < 200; ++i) {
        const auto chunk = bytes("compressible ");
        long_text.insert(long_text.end(), chunk.begin(), chunk.end());
    }
    for (auto alg : {key_algorithm::RSA_OAEP_256, key_algorithm::A256KW, key_algorithm::ECDH_ES}) {
        out.push_back(jwe_vector(std::string(to_string(alg)) + " zip=DEF", content_encryption::A128GCM,
                                 {recipient_for(keys, alg, content_encryption::A128GCM)}, long_text,
                                 {.compress = true}));
    }

    {
        auto pw = keys.password();
        out.push_back(jwe_vector("PBES2 default p2c", content_encryption::A256GCM,
                                 {{{key_algorithm::PBES2_HS512_A256KW, pw}, pw}}, plaintext, {}));
    }
    out.push_back(jwe_vector("aad", content_encryption::A128CBC_HS256,
                             {recipient_for(keys, key_algorithm::A128KW, content_encryption::A128CBC_HS256)},
                             plaintext, {.aad = bytes("extra ✓")}));
    {
        std::vector<recipient_and_key> rs;
        for (auto alg : {key_algorithm::RSA_OAEP, key_algorithm::A192KW, key_algorithm::ECDH_ES_A128KW,
                         key_algorithm::A256GCMKW, key_algorithm::PBES2_HS256_A128KW})
            rs.push_back(recipient_for(keys, alg, content_encryption::A256CBC_HS512, ec_curve::P384));
        out.push_back(
            jwe_vector("multi-recipient", content_encryption::A256CBC_HS512, rs, plaintext, {.compress = true}));
    }
    return out;
}

const json k_jwt_claims{
    {"iss", "https://issuer.example"},
    {"sub", "kevin"},
    {"aud", json::array({"api", "web"})},
    {"exp", 1900000000},
    {"nbf", 1700000000},
    {"name", "Kevin ✓"},
    {"ctx", {{"role", "admin"}, {"levels", json::array({1, 2, 3})}}},
};

auto jwt_vector(const std::string& name, const std::string& kind) -> json {
    return json{{"name", name}, {"kind", kind}, {"claims", k_jwt_claims}};
}

auto signed_jwt_vector(key_source& keys, signing_algorithm alg) -> json {
    const auto key = signing_key_for(keys, alg);
    auto v = jwt_vector("signed " + std::string(to_string(alg)), "signed");
    v["signature_algorithms"] = json::array({to_string(alg)});
    v["verification_key"] = public_json(key);
    v["token"] = must(jwt::signed_token({alg, key}).claims(k_jwt_claims).serialize(), v["name"]);
    return v;
}

auto encrypted_jwt_vector(key_source& keys, key_algorithm alg, content_encryption enc) -> json {
    const auto r = recipient_for(keys, alg, enc);
    auto v = jwt_vector("encrypted " + std::string(to_string(alg)) + " " + std::string(to_string(enc)), "encrypted");
    v["key_algorithms"] = json::array({to_string(alg)});
    v["enc"] = to_string(enc);
    v["decryption_key"] = key_json(r.key);
    v["token"] = must(jwt::encrypted_token(enc, r.recipient).claims(k_jwt_claims).serialize(), v["name"]);
    return v;
}

auto nested_jwt_vector(key_source& keys, key_algorithm alg, content_encryption enc, signing_algorithm sig,
                       bool compress = false) -> json {
    const auto signing_key = signing_key_for(keys, sig);
    const auto r = recipient_for(keys, alg, enc);
    auto v = jwt_vector("nested " + std::string(to_string(alg)) + " " + std::string(to_string(enc)) + " " +
                            std::string(to_string(sig)) + (compress ? " DEFLATE" : ""),
                        "nested");
    v["signature_algorithms"] = json::array({to_string(sig)});
    v["key_algorithms"] = json::array({to_string(alg)});
    v["enc"] = to_string(enc);
    v["verification_key"] = public_json(signing_key);
    v["decryption_key"] = key_json(r.key);
    v["token"] =
        must(jwt::signed_and_encrypted({sig, signing_key}, enc, r.recipient, {}, {.compress = compress})
                 .claims(k_jwt_claims)
                 .serialize(),
             v["name"]);
    return v;
}

// Built from jwt::registered_claims with a single audience, which is
// written as a plain string.
auto registered_claims_vector(key_source& keys) -> json {
    const jwt::registered_claims standard{
        .issuer = "https://issuer.example",
        .subject = "kevin",
        .audience = {"api"},
        .expiry = jwt::numeric_date::from_seconds(1900000000),
        .not_before = jwt::numeric_date::from_seconds(1700000000),
        .issued_at = jwt::numeric_date::from_seconds(1700000000),
        .id = "cpp-claims-1",
    };
    const auto key = signing_key_for(keys, signing_algorithm::ES256);
    json v{{"name", "signed ES256 registered_claims"}, {"kind", "signed"}, {"claims", json(standard)}};
    v["signature_algorithms"] = json::array({"ES256"});
    v["verification_key"] = public_json(key);
    v["token"] = must(jwt::signed_token({signing_algorithm::ES256, key}).claims(standard).serialize(), v["name"]);
    return v;
}

auto generate_jwt(key_source& keys) -> json {
    json out = json::array();
    out.push_back(registered_claims_vector(keys));
    for (auto alg : {signing_algorithm::HS256, signing_algorithm::RS256, signing_algorithm::PS384,
                     signing_algorithm::ES256, signing_algorithm::ES512, signing_algorithm::EdDSA})
        out.push_back(signed_jwt_vector(keys, alg));
    out.push_back(encrypted_jwt_vector(keys, key_algorithm::dir, content_encryption::A128GCM));
    out.push_back(encrypted_jwt_vector(keys, key_algorithm::A256KW, content_encryption::A256GCM));
    out.push_back(encrypted_jwt_vector(keys, key_algorithm::A192GCMKW, content_encryption::A192CBC_HS384));
    out.push_back(nested_jwt_vector(keys, key_algorithm::A128KW, content_encryption::A128GCM, signing_algorithm::RS256));
    out.push_back(nested_jwt_vector(keys, key_algorithm::dir, content_encryption::A256GCM, signing_algorithm::ES256));
    out.push_back(nested_jwt_vector(keys, key_algorithm::A256GCMKW, content_encryption::A256CBC_HS512,
                                    signing_algorithm::EdDSA));
    out.push_back(nested_jwt_vector(keys, key_algorithm::A128KW, content_encryption::A128GCM, signing_algorithm::HS256,
                                    true));
    return out;
}

// Nested JWTs whose JWE uses a public-key algorithm: allowed by jose2cpp's
// split rule (the inner signature authenticates them), refused by go-jose.
auto generate_incompatible_jwt(key_source& keys) -> json {
    json out = json::array();
    for (auto alg : {key_algorithm::RSA_OAEP_256, key_algorithm::ECDH_ES_A256KW, key_algorithm::ECDH_ES}) {
        auto v = nested_jwt_vector(keys, alg, content_encryption::A256GCM, signing_algorithm::ES256);
        v["reason"] = "go-jose refuses RSA, ECDH-ES and PBES2 key algorithms for nested JWTs too";
        v["rejected_with"] = "asymmetric encryption algorithms not supported for JWT";
        out.push_back(std::move(v));
    }
    return out;
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: jose_interop_gen <out.json>\n";
        return 2;
    }
    try {
        key_source keys;
        const json file{
            {"producer", std::string("jose2cpp ") + JOSE_VERSION},
            {"jws", generate_jws(keys)},
            {"jwe", generate_jwe(keys)},
            {"jwt", generate_jwt(keys)},
            {"jws_incompatible", generate_incompatible_jws(keys)},
            {"jwt_incompatible", generate_incompatible_jwt(keys)},
        };
        std::ofstream out(argv[1]);
        out << file.dump(2) << '\n';
        if (!out) throw std::runtime_error(std::string("cannot write ") + argv[1]);
    } catch (const std::exception& e) {
        std::cerr << "jose_interop_gen: " << e.what() << '\n';
        return 1;
    }
    return 0;
}
