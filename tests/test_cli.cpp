#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include "cli.hpp"
#include "jose/jose.hpp"

#include <openssl/encoder.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>
#include <string>
#include <vector>

using namespace jose;
using Catch::Matchers::ContainsSubstring;
using Catch::Matchers::StartsWith;
using json = nlohmann::json;
namespace fs = std::filesystem;

namespace {

struct cli_result {
    int status;
    std::string out;
    std::string err;
};

auto run_cli(std::vector<std::string> args, const std::string& input = "") -> cli_result {
    std::istringstream in(input);
    std::ostringstream out, err;
    const int status = cli::run(args, {in, out, err});
    return {status, out.str(), err.str()};
}

auto ok(const cli_result& r) -> bool {
    if (r.status != cli::exit_ok) UNSCOPED_INFO("stderr: " << r.err);
    return r.status == cli::exit_ok;
}

struct temp_dir {
    fs::path path;
    temp_dir() {
        std::random_device rd;
        path = fs::temp_directory_path() / ("jose-cli-test-" + std::to_string(rd()) + std::to_string(rd()));
        fs::create_directories(path);
    }
    ~temp_dir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
    temp_dir(const temp_dir&) = delete;
    temp_dir& operator=(const temp_dir&) = delete;

    auto write(const std::string& name, const std::string& content) const -> std::string {
        const auto p = path / name;
        std::ofstream f(p, std::ios::binary);
        f << content;
        return p.string();
    }
    auto read(const std::string& name) const -> std::string {
        std::ifstream f(path / name, std::ios::binary);
        return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
    }
};

// Encodes a key with OpenSSL: format "PEM" or "DER", structure e.g.
// "PrivateKeyInfo", "type-specific" (PKCS#1, SEC 1), "SubjectPublicKeyInfo".
auto encode(const jwk& key, const char* format, const char* structure, bool private_part) -> std::string {
    const int selection = private_part ? OSSL_KEYMGMT_SELECT_ALL : OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
    OSSL_ENCODER_CTX* ctx = OSSL_ENCODER_CTX_new_for_pkey(key.pkey(), selection, format, structure, nullptr);
    REQUIRE(ctx);
    unsigned char* data = nullptr;
    std::size_t len = 0;
    const bool ok = OSSL_ENCODER_to_data(ctx, &data, &len) == 1;
    OSSL_ENCODER_CTX_free(ctx);
    REQUIRE(ok);
    std::string out(reinterpret_cast<char*>(data), len);
    OPENSSL_free(data);
    return out;
}

// A self-signed certificate for `key`, as PEM or DER.
auto certificate(const jwk& key, bool pem) -> std::string {
    X509* x = X509_new();
    REQUIRE(x);
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600);
    X509_set_pubkey(x, key.pkey());
    X509_NAME* name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("test"), -1, -1, 0);
    X509_set_issuer_name(x, name);
    REQUIRE(X509_sign(x, key.pkey(), EVP_sha256()) > 0);
    std::string out;
    if (pem) {
        BIO* bio = BIO_new(BIO_s_mem());
        PEM_write_bio_X509(bio, x);
        char* data = nullptr;
        const long len = BIO_get_mem_data(bio, &data);
        out.assign(data, static_cast<std::size_t>(len));
        BIO_free(bio);
    } else {
        unsigned char* der = nullptr;
        const int len = i2d_X509(x, &der);
        REQUIRE(len > 0);
        out.assign(reinterpret_cast<char*>(der), static_cast<std::size_t>(len));
        OPENSSL_free(der);
    }
    X509_free(x);
    return out;
}

auto json_of(const jwk& key) -> std::string {
    auto s = key.to_json_string();
    REQUIRE(s);
    return *s;
}

auto with_kid(expected<jwk> key, const char* kid) -> jwk {
    REQUIRE(key);
    key->set_key_id(kid);
    return std::move(*key);
}

const std::string message = "Lorem ipsum dolor sit amet\n";

} // namespace

TEST_CASE("cli: usage", "[cli]") {
    auto r = run_cli({});
    CHECK(r.status == cli::exit_usage);
    CHECK_THAT(r.err, ContainsSubstring("Commands:"));

    r = run_cli({"--help"});
    CHECK(ok(r));
    for (const char* name : {"sign", "verify", "encrypt", "decrypt", "expand", "generate-key"})
        CHECK_THAT(r.out, ContainsSubstring(name));

    r = run_cli({"version"});
    CHECK(ok(r));
    CHECK_THAT(r.out, StartsWith("jose-cli " JOSE_VERSION));

    r = run_cli({"frobnicate"});
    CHECK(r.status == cli::exit_usage);
    CHECK_THAT(r.err, ContainsSubstring("unknown command 'frobnicate'"));

    r = run_cli({"sign", "--help"});
    CHECK(ok(r));
    CHECK_THAT(r.out, StartsWith("Usage: jose-cli sign"));

    for (const auto& bad : std::vector<std::vector<std::string>>{
             {"sign", "--frob"},
             {"sign", "stray"},
             {"sign", "--key"},
             {"sign", "--full=maybe"},
             {"sign", "--key", "a", "--key", "b"},
             {"sign", "--alg", "ES256"},
             {"verify"},
             {"encrypt", "--key", "x"},
             {"generate-key", "--alg", "ES256"},
         }) {
        r = run_cli(bad);
        std::string line;
        for (const auto& a : bad) line += a + " ";
        INFO(line);
        CHECK(r.status == cli::exit_usage);
        CHECK_THAT(r.err, ContainsSubstring("--help"));
    }
}

TEST_CASE("cli: sign and verify", "[cli]") {
    temp_dir dir;
    auto rsa = jwk::generate_rsa(2048);
    auto ec = jwk::generate_ec(ec_curve::P384);
    auto ed = jwk::generate_okp(okp_curve::Ed25519);
    REQUIRE(rsa);
    REQUIRE(ec);
    REQUIRE(ed);

    SECTION("PEM and DER keys in every encoding OpenSSL writes, like jose-util's") {
        struct form {
            const jwk* key;
            const char* alg;
            const char* format;
            const char* priv_structure;
        };
        for (const auto& f : {form{&*rsa, "PS256", "PEM", "type-specific"}, form{&*rsa, "RS256", "PEM", "PrivateKeyInfo"},
                              form{&*rsa, "RS512", "DER", "type-specific"}, form{&*ec, "ES384", "PEM", "type-specific"},
                              form{&*ec, "ES384", "DER", "PrivateKeyInfo"}, form{&*ed, "EdDSA", "PEM", "PrivateKeyInfo"},
                              form{&*ed, "EdDSA", "DER", "PrivateKeyInfo"}}) {
            INFO(f.alg << " " << f.format << " " << f.priv_structure);
            const auto priv = dir.write("priv", encode(*f.key, f.format, f.priv_structure, true));
            const auto pub = dir.write("pub", encode(*f.key, f.format, "SubjectPublicKeyInfo", false));
            auto signed_ = run_cli({"sign", "--alg", f.alg, "--key", priv}, message);
            REQUIRE(ok(signed_));
            CHECK(signed_.out.ends_with("\n"));
            CHECK(std::count(signed_.out.begin(), signed_.out.end(), '.') == 2);
            auto verified = run_cli({"verify", "--key", pub}, signed_.out);
            REQUIRE(ok(verified));
            CHECK(verified.out == message);
        }
    }
    SECTION("JWK keys; --alg defaults to the key's alg") {
        auto key = with_kid(jwk::generate_ec(ec_curve::P256), "k1");
        REQUIRE(key.set_algorithm("ES256"));
        const auto priv = dir.write("k1.json", json_of(key));
        const auto pub = dir.write("k1-pub.json", json_of(*key.public_key()));
        auto signed_ = run_cli({"sign", "--key", priv}, message);
        REQUIRE(ok(signed_));
        auto parsed = jws::parse(signed_.out, {signing_algorithm::ES256});
        REQUIRE(parsed);
        CHECK(parsed->signatures()[0].joined.kid() == "k1");
        CHECK(run_cli({"verify", "--key", pub}, signed_.out).out == message);
        // A private key verifies too.
        CHECK(run_cli({"verify", "--key", priv}, signed_.out).out == message);

        auto no_alg = with_kid(jwk::generate_ec(ec_curve::P256), "k2");
        auto r = run_cli({"sign", "--key", dir.write("k2.json", json_of(no_alg))}, message);
        CHECK(r.status == cli::exit_usage);
        CHECK_THAT(r.err, ContainsSubstring("--alg is required"));
    }
    SECTION("a JWK Set picks the key by kid") {
        auto k1 = with_kid(jwk::generate_ec(ec_curve::P256), "k1");
        auto k2 = with_kid(jwk::generate_ec(ec_curve::P256), "k2");
        const auto set = dir.write("jwks.json", R"({"keys":[)" + json_of(*k1.public_key()) + "," +
                                                    json_of(*k2.public_key()) + "]}");
        auto signed_ = run_cli({"sign", "--alg", "ES256", "--key", dir.write("k2.json", json_of(k2))}, message);
        REQUIRE(ok(signed_));
        CHECK(run_cli({"verify", "--key", set}, signed_.out).out == message);
        // Signing needs one key.
        auto r = run_cli({"sign", "--alg", "ES256", "--key", set}, message);
        CHECK(r.status == cli::exit_failed);
        CHECK_THAT(r.err, ContainsSubstring("JWK Set can't be used here"));
    }
    SECTION("HMAC, --full and the allowlist") {
        auto key = jwk::generate_oct(32);
        REQUIRE(key);
        const auto file = dir.write("hs.json", json_of(*key));
        auto signed_ = run_cli({"sign", "--alg", "HS256", "--full", "--key", file}, message);
        REQUIRE(ok(signed_));
        const auto j = json::parse(signed_.out);
        CHECK(j.contains("protected"));
        CHECK(j.contains("signature"));
        CHECK(run_cli({"verify", "--key", file}, signed_.out).out == message);
        CHECK(ok(run_cli({"verify", "--key", file, "--alg", "HS384,HS256"}, signed_.out)));
        auto r = run_cli({"verify", "--key", file, "--alg", "HS384"}, signed_.out);
        CHECK(r.status == cli::exit_failed);
        CHECK(r.out.empty());
        r = run_cli({"verify", "--key", file, "--alg", "none"}, signed_.out);
        CHECK(r.status == cli::exit_usage);
    }
    SECTION("a JSON JWS with several signatures verifies with any of its keys") {
        auto k1 = jwk::generate_ec(ec_curve::P256);
        REQUIRE(k1);
        const std::vector<jws_signer> signers{{signing_algorithm::ES256, *k1}, {signing_algorithm::EdDSA, *ed}};
        auto token = jws::sign(std::span(reinterpret_cast<const uint8_t*>(message.data()), message.size()),
                               std::span<const jws_signer>(signers));
        REQUIRE(token);
        auto text = token->to_json_string();
        REQUIRE(text);
        const auto pub = dir.write("ed.pem", encode(*ed, "PEM", "SubjectPublicKeyInfo", false));
        auto r = run_cli({"verify", "--key", pub}, *text);
        REQUIRE(ok(r));
        CHECK(r.out == message);
    }
    SECTION("more encodings of public keys") {
        const auto priv = dir.write("rsa.pem", encode(*rsa, "PEM", "PrivateKeyInfo", true));
        auto signed_ = run_cli({"sign", "--alg", "RS256", "--key", priv}, message);
        REQUIRE(ok(signed_));
        for (const auto& [what, key] : {std::pair{"PKCS#1 PEM", encode(*rsa, "PEM", "type-specific", false)},
                                        std::pair{"PKCS#1 DER", encode(*rsa, "DER", "type-specific", false)},
                                        std::pair{"X.509 PEM", certificate(*rsa, true)},
                                        std::pair{"X.509 DER", certificate(*rsa, false)}}) {
            INFO(what);
            auto r = run_cli({"verify", "--key", dir.write("pub", key)}, signed_.out);
            REQUIRE(ok(r));
            CHECK(r.out == message);
        }
        const auto ec_priv = dir.write("ec.der", encode(*ec, "DER", "type-specific", true)); // SEC 1
        signed_ = run_cli({"sign", "--alg", "ES384", "--key", ec_priv}, message);
        REQUIRE(ok(signed_));
        CHECK(run_cli({"verify", "--key", dir.write("ec-cert.der", certificate(*ec, false))}, signed_.out).out == message);
        // Trailing bytes after DER are refused.
        for (const auto& der : {encode(*rsa, "DER", "SubjectPublicKeyInfo", false), certificate(*rsa, false)}) {
            auto r = run_cli({"verify", "--key", dir.write("trailing", der + "x")}, signed_.out);
            CHECK(r.status == cli::exit_failed);
            CHECK_THAT(r.err, ContainsSubstring("trailing bytes"));
        }
        CHECK(ERR_peek_error() == 0);
    }
    SECTION("an RSA public key used as an HMAC secret is refused") {
        const std::string pem = encode(*rsa, "PEM", "SubjectPublicKeyInfo", false);
        const auto pub = dir.write("rsa.pem", pem);
        auto secret = jwk::from_oct(std::span(reinterpret_cast<const uint8_t*>(pem.data()), pem.size()));
        REQUIRE(secret);
        auto forged = jws::sign(message, {signing_algorithm::HS256, *secret});
        REQUIRE(forged);
        for (const auto& token : {*forged->compact(), *forged->to_json_string()}) {
            auto r = run_cli({"verify", "--key", pub}, token);
            CHECK(r.status == cli::exit_failed);
            CHECK(r.out.empty());
        }
    }
    SECTION("a JWK Set and a JSON JWS with several signatures") {
        auto ka = with_kid(jwk::generate_ec(ec_curve::P256), "a");
        auto kb = with_kid(jwk::generate_okp(okp_curve::Ed25519), "b");
        const std::vector<jws_signer> signers{{signing_algorithm::ES256, ka}, {signing_algorithm::EdDSA, kb}};
        auto token = jws::sign(std::span(reinterpret_cast<const uint8_t*>(message.data()), message.size()),
                               std::span<const jws_signer>(signers));
        REQUIRE(token);
        auto other = with_kid(jwk::generate_ec(ec_curve::P256), "c");
        const auto set = dir.write("set.json", R"({"keys":[)" + json_of(*other.public_key()) + "," +
                                                   json_of(*kb.public_key()) + "]}");
        auto r = run_cli({"verify", "--key", set}, *token->to_json_string());
        REQUIRE(ok(r));
        CHECK(r.out == message);
    }
    SECTION("Go's boolean spellings and --") {
        auto key = jwk::generate_oct(32);
        REQUIRE(key);
        const auto file = dir.write("hs.json", json_of(*key));
        for (const char* yes : {"--full=1", "--full=t", "--full=TRUE", "-full=True"}) {
            auto r = run_cli({"sign", "--alg", "HS256", "--key", file, yes}, message);
            REQUIRE(ok(r));
            CHECK(r.out.starts_with("{"));
        }
        for (const char* no : {"--full=0", "--full=f", "--full=FALSE"}) {
            auto r = run_cli({"sign", "--alg", "HS256", "--key", file, no}, message);
            REQUIRE(ok(r));
            CHECK_FALSE(r.out.starts_with("{"));
        }
        CHECK(ok(run_cli({"sign", "--alg", "HS256", "--key", file, "--"}, message)));
        CHECK(run_cli({"sign", "--alg", "HS256", "--key", file, "--", "x"}, message).status == cli::exit_usage);
        CHECK(run_cli({"sign", "--alg", "HS256", "--key", file, "--full=yes"}, message).status == cli::exit_usage);
    }
    SECTION("a bad signature fails and writes nothing") {
        const auto priv = dir.write("priv.pem", encode(*ec, "PEM", "PrivateKeyInfo", true));
        auto other = jwk::generate_ec(ec_curve::P384);
        REQUIRE(other);
        const auto wrong = dir.write("wrong.pem", encode(*other, "PEM", "SubjectPublicKeyInfo", false));
        auto signed_ = run_cli({"sign", "--alg", "ES384", "--key", priv}, message);
        REQUIRE(ok(signed_));
        auto r = run_cli({"verify", "--key", wrong}, signed_.out);
        CHECK(r.status == cli::exit_failed);
        CHECK(r.out.empty());
        CHECK_THAT(r.err, StartsWith("jose-cli verify: "));
        // An RSA key accepts no ES* token: the allowlist comes from the key.
        const auto rsa_pub = dir.write("rsa.pem", encode(*rsa, "PEM", "SubjectPublicKeyInfo", false));
        r = run_cli({"verify", "--key", rsa_pub}, signed_.out);
        CHECK(r.status == cli::exit_failed);
    }
    SECTION("files with --in and --out, and -flag=value") {
        const auto priv = dir.write("priv.pem", encode(*ed, "PEM", "PrivateKeyInfo", true));
        const auto pub = dir.write("pub.pem", encode(*ed, "PEM", "SubjectPublicKeyInfo", false));
        dir.write("msg", message);
        REQUIRE(ok(run_cli({"sign", "-alg=EdDSA", "-key=" + priv, "-in", (dir.path / "msg").string(), "--out",
                            (dir.path / "token").string()})));
        REQUIRE(ok(run_cli({"verify", "--key", pub, "--in", (dir.path / "token").string(), "--out=" +
                                                                                            (dir.path / "out").string()})));
        CHECK(dir.read("out") == message);
        auto r = run_cli({"verify", "--key", pub, "--in", (dir.path / "missing").string()});
        CHECK(r.status == cli::exit_failed);
        CHECK_THAT(r.err, ContainsSubstring("can't open input file"));
        r = run_cli({"verify", "--key", (dir.path / "missing").string()}, "x");
        CHECK_THAT(r.err, ContainsSubstring("can't open key file"));
        r = run_cli({"verify", "--key", dir.write("junk", "not a key")}, "x");
        CHECK(r.status == cli::exit_failed);
        CHECK_THAT(r.err, ContainsSubstring("not a key"));
        // Failed decoding attempts don't leave errors on OpenSSL's queue.
        CHECK(ERR_peek_error() == 0);
        // A directory as input is an error, not an empty payload.
        r = run_cli({"sign", "--alg", "EdDSA", "--key", priv, "--in", dir.path.string()});
        CHECK(r.status == cli::exit_failed);
        CHECK(r.out.empty());
        CHECK_THAT(r.err, ContainsSubstring("is a directory"));
        r = run_cli({"verify", "--key", dir.path.string()}, "x");
        CHECK(r.status == cli::exit_failed);
    }
}

TEST_CASE("cli: encrypt and decrypt", "[cli]") {
    temp_dir dir;
    auto rsa = jwk::generate_rsa(2048);
    auto ec = jwk::generate_ec(ec_curve::P256);
    REQUIRE(rsa);
    REQUIRE(ec);
    const auto rsa_priv = dir.write("rsa.pem", encode(*rsa, "PEM", "type-specific", true));
    const auto rsa_pub = dir.write("rsa-pub.pem", encode(*rsa, "PEM", "SubjectPublicKeyInfo", false));
    const auto ec_priv = dir.write("ec.pem", encode(*ec, "PEM", "type-specific", true));
    const auto ec_pub = dir.write("ec-pub.pem", encode(*ec, "PEM", "SubjectPublicKeyInfo", false));

    SECTION("asymmetric, as in jose-util's examples") {
        for (const auto& [alg, pub, priv] : {std::tuple{"RSA-OAEP", rsa_pub, rsa_priv},
                                             std::tuple{"RSA-OAEP-256", rsa_pub, rsa_priv},
                                             std::tuple{"ECDH-ES", ec_pub, ec_priv},
                                             std::tuple{"ECDH-ES+A128KW", ec_pub, ec_priv}}) {
            INFO(alg);
            auto sealed = run_cli({"encrypt", "--alg", alg, "--enc", "A128GCM", "--key", pub}, message);
            REQUIRE(ok(sealed));
            CHECK(std::count(sealed.out.begin(), sealed.out.end(), '.') == 4);
            auto opened = run_cli({"decrypt", "--key", priv}, sealed.out);
            REQUIRE(ok(opened));
            CHECK(opened.out == message);
        }
    }
    SECTION("symmetric keys, --zip and --full") {
        auto kw = jwk::generate_oct(32);
        REQUIRE(kw);
        const auto file = dir.write("kw.json", json_of(*kw));
        auto sealed = run_cli({"encrypt", "--alg", "A256KW", "--enc", "A256CBC-HS512", "--zip", "--full", "--key", file},
                              message);
        REQUIRE(ok(sealed));
        const auto j = json::parse(sealed.out);
        auto parsed = jwe::parse(sealed.out, {key_algorithm::A256KW}, {content_encryption::A256CBC_HS512});
        REQUIRE(parsed);
        CHECK(parsed->protected_header().get("zip"));
        CHECK(j.contains("ciphertext"));
        CHECK(run_cli({"decrypt", "--key", file}, sealed.out).out == message);
        // --enc narrows the content encryptions accepted.
        auto r = run_cli({"decrypt", "--key", file, "--enc", "A128GCM"}, sealed.out);
        CHECK(r.status == cli::exit_failed);

        auto cek = jwk::generate_oct(16);
        REQUIRE(cek);
        const auto dir_key = dir.write("dir.json", json_of(*cek));
        sealed = run_cli({"encrypt", "--alg", "dir", "--enc", "A128GCM", "--key", dir_key}, message);
        REQUIRE(ok(sealed));
        CHECK(run_cli({"decrypt", "--key", dir_key}, sealed.out).out == message);
    }
    SECTION("PBES2: the password as an oct JWK") {
        auto pw = jwk::from_oct(std::span(reinterpret_cast<const uint8_t*>("correct horse battery staple"), 28));
        REQUIRE(pw);
        const auto file = dir.write("pw.json", json_of(*pw));
        auto sealed = run_cli({"encrypt", "--alg", "PBES2-HS256+A128KW", "--enc", "A128GCM", "--key", file}, message);
        REQUIRE(ok(sealed));
        CHECK(run_cli({"decrypt", "--key", file}, sealed.out).out == message);
    }
    SECTION("a JWK Set picks the key by kid") {
        auto k1 = with_kid(jwk::generate_ec(ec_curve::P256), "k1");
        auto k2 = with_kid(jwk::generate_ec(ec_curve::P256), "k2");
        const auto set = dir.write("jwks.json", R"({"keys":[)" + json_of(k1) + "," + json_of(k2) + "]}");
        auto sealed = run_cli({"encrypt", "--alg", "ECDH-ES+A256KW", "--enc", "A256GCM", "--key",
                               dir.write("k2.json", json_of(*k2.public_key()))},
                              message);
        REQUIRE(ok(sealed));
        CHECK(run_cli({"decrypt", "--key", set}, sealed.out).out == message);
    }
    SECTION("RSA1_5 needs --allow-legacy both ways") {
        auto r = run_cli({"encrypt", "--alg", "RSA1_5", "--enc", "A128GCM", "--key", rsa_pub}, message);
        CHECK(r.status == cli::exit_failed);
        auto sealed = run_cli({"encrypt", "--alg", "RSA1_5", "--enc", "A128GCM", "--allow-legacy", "--key", rsa_pub},
                              message);
        REQUIRE(ok(sealed));
        r = run_cli({"decrypt", "--key", rsa_priv}, sealed.out);
        CHECK(r.status == cli::exit_failed);
        CHECK(r.out.empty());
        CHECK(run_cli({"decrypt", "--allow-legacy", "--key", rsa_priv}, sealed.out).out == message);
    }
    SECTION("a JWK Set and a JSON JWE with several recipients; --out is private") {
        auto ka = with_kid(jwk::generate_ec(ec_curve::P256), "a");
        auto kb = with_kid(jwk::generate_ec(ec_curve::P384), "b");
        const std::vector<jwe_recipient> recipients{{key_algorithm::ECDH_ES_A128KW, *ka.public_key()},
                                                    {key_algorithm::ECDH_ES_A256KW, *kb.public_key()}};
        auto token = jwe::encrypt(std::span(reinterpret_cast<const uint8_t*>(message.data()), message.size()),
                                  content_encryption::A256GCM, std::span<const jwe_recipient>(recipients));
        REQUIRE(token);
        auto other = with_kid(jwk::generate_ec(ec_curve::P256), "c");
        const auto set = dir.write("set.json", R"({"keys":[)" + json_of(other) + "," + json_of(kb) + "]}");
        const auto out = (dir.path / "plain.txt").string();
        auto r = run_cli({"decrypt", "--key", set, "--out", out}, *token->to_json_string());
        REQUIRE(ok(r));
        CHECK(r.out.empty());
        CHECK(dir.read("plain.txt") == message);
#ifndef _WIN32
        using p = fs::perms;
        CHECK((fs::status(out).permissions() & (p::group_all | p::others_all)) == p::none);
#endif
    }
    SECTION("failures") {
        auto sealed = run_cli({"encrypt", "--alg", "RSA-OAEP", "--enc", "A128GCM", "--key", rsa_pub}, message);
        REQUIRE(ok(sealed));
        auto other = jwk::generate_rsa(2048);
        REQUIRE(other);
        auto r = run_cli({"decrypt", "--key", dir.write("other.pem", encode(*other, "PEM", "PrivateKeyInfo", true))},
                         sealed.out);
        CHECK(r.status == cli::exit_failed);
        CHECK(r.out.empty());
        // A public key can't decrypt.
        r = run_cli({"decrypt", "--key", rsa_pub}, sealed.out);
        CHECK(r.status == cli::exit_failed);
        r = run_cli({"encrypt", "--alg", "RSA-OAEP", "--key", rsa_pub}, message);
        CHECK(r.status == cli::exit_usage);
        CHECK_THAT(r.err, ContainsSubstring("--enc is required"));
        r = run_cli({"encrypt", "--alg", "RSA-OAEP", "--enc", "A1GCM", "--key", rsa_pub}, message);
        CHECK(r.status == cli::exit_usage);
    }
}

TEST_CASE("cli: expand", "[cli]") {
    // The JWS from jose-util's own tests (jose-util.t), and its expected output.
    const std::string token =
        "eyJhbGciOiJFUzM4NCJ9.TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQK.QPU35XY913Im7ZEaN2yHykfbtPqjHZvYp-lV8OcTAJZs67bJF"
        "SdTSkQhQWE9ch6tvYrj_7py6HKaWVFLll_s_Rm6bmwq3JszsHrIvFFm1NydruYHhvAnx7rjYiqwOu0W";
    const std::string expanded =
        R"({"payload":"TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQK","protected":"eyJhbGciOiJFUzM4NCJ9","signature":"QPU35XY913Im7ZEaN2yHykfbtPqjHZvYp-lV8OcTAJZs67bJFSdTSkQhQWE9ch6tvYrj_7py6HKaWVFLll_s_Rm6bmwq3JszsHrIvFFm1NydruYHhvAnx7rjYiqwOu0W"})"
        "\n";
    auto r = run_cli({"expand", "--format", "JWS"}, token + "\n");
    REQUIRE(ok(r));
    CHECK(r.out == expanded);
    CHECK(run_cli({"expand"}, token).out == expanded);

    temp_dir dir;
    auto key = jwk::generate_oct(16);
    REQUIRE(key);
    auto sealed = run_cli({"encrypt", "--alg", "A128KW", "--enc", "A128GCM", "--key", dir.write("k", json_of(*key))},
                          message);
    REQUIRE(ok(sealed));
    r = run_cli({"expand"}, sealed.out);
    REQUIRE(ok(r));
    const auto j = json::parse(r.out);
    CHECK(j.contains("encrypted_key"));
    CHECK(run_cli({"decrypt", "--key", dir.write("k", json_of(*key))}, r.out).out == message);

    CHECK(run_cli({"expand"}, "a.b").status == cli::exit_failed);
    CHECK(run_cli({"expand", "--format", "JWE"}, token).status == cli::exit_failed);
    CHECK(run_cli({"expand", "--format", "XML"}, token).status == cli::exit_usage);
    // JSON in: written back out (as jose-util does).
    r = run_cli({"expand"}, expanded);
    REQUIRE(ok(r));
    CHECK(r.out == expanded);
    r = run_cli({"expand"}, run_cli({"expand"}, sealed.out).out);
    REQUIRE(ok(r));
    CHECK(json::parse(r.out).contains("ciphertext"));
}

TEST_CASE("cli: generate-key", "[cli]") {
    temp_dir dir;
    const auto d = dir.path.string();
    const auto gen = [&](std::vector<std::string> extra) {
        std::vector<std::string> args{"generate-key", "--dir", d};
        args.insert(args.end(), extra.begin(), extra.end());
        return run_cli(args);
    };
    const auto load = [&](const std::string& name) {
        auto k = jwk::from_json(std::string_view(dir.read(name)));
        REQUIRE(k);
        return std::move(*k);
    };

    SECTION("asymmetric keys: a pair, with alg, use and kid") {
        auto r = gen({"--use", "sig", "--alg", "ES256", "--kid", "test"});
        REQUIRE(ok(r));
        CHECK_THAT(r.out, ContainsSubstring("jwk-sig-test-pub.json"));
        CHECK_THAT(r.out, ContainsSubstring("jwk-sig-test-priv.json"));
        const auto priv = load("jwk-sig-test-priv.json");
        const auto pub = load("jwk-sig-test-pub.json");
        CHECK(priv.is_private());
        CHECK(pub.is_public());
        CHECK(pub.algorithm() == "ES256");
        CHECK(pub.use() == "sig");
        CHECK(pub.key_id() == "test");
#ifndef _WIN32
        // Whatever the umask: the private file is owner-read only, and
        // neither file is writable.
        using p = fs::perms;
        CHECK((fs::status(dir.path / "jwk-sig-test-priv.json").permissions() & p::all) == p::owner_read);
        const auto pub_perms = fs::status(dir.path / "jwk-sig-test-pub.json").permissions();
        CHECK((pub_perms & p::owner_read) == p::owner_read);
        CHECK((pub_perms & (p::owner_write | p::group_write | p::others_write | p::owner_exec)) == p::none);
#endif
        // Usable straight away.
        auto signed_ = run_cli({"sign", "--key", (dir.path / "jwk-sig-test-priv.json").string()}, message);
        REQUIRE(ok(signed_));
        CHECK(run_cli({"verify", "--key", (dir.path / "jwk-sig-test-pub.json").string()}, signed_.out).out == message);

        // Never overwrites.
        r = gen({"--use", "sig", "--alg", "ES256", "--kid", "test"});
        CHECK(r.status == cli::exit_failed);
        CHECK_THAT(r.err, ContainsSubstring("exists already"));
    }
    SECTION("without --kid, the kid is the RFC 7638 thumbprint") {
        auto r = gen({"--use", "enc", "--alg", "RSA-OAEP"});
        REQUIRE(ok(r));
        for (const auto& entry : fs::directory_iterator(dir.path)) {
            const auto name = entry.path().filename().string();
            if (!name.ends_with("-pub.json")) continue;
            const auto key = load(name);
            auto thumb = key.thumbprint();
            REQUIRE(thumb);
            CHECK(key.key_id() == base64url::encode(*thumb));
            CHECK(name == "jwk-enc-" + base64url::encode(*thumb) + "-pub.json");
        }
    }
    SECTION("what each algorithm makes") {
        struct want {
            std::vector<std::string> args;
            kty type;
            std::size_t files;
        };
        int n = 0;
        for (const auto& w : std::vector<want>{
                 {{"--use", "sig", "--alg", "RS256", "--size", "3072"}, kty::RSA, 2},
                 {{"--use", "sig", "--alg", "PS384"}, kty::RSA, 2},
                 {{"--use", "sig", "--alg", "ES512"}, kty::EC, 2},
                 {{"--use", "sig", "--alg", "EdDSA"}, kty::OKP, 2},
                 {{"--use", "sig", "--alg", "EdDSA", "--crv", "Ed448"}, kty::OKP, 2},
                 {{"--use", "sig", "--alg", "HS512"}, kty::oct, 1},
                 {{"--use", "enc", "--alg", "ECDH-ES+A128KW", "--size", "384"}, kty::EC, 2},
                 {{"--use", "enc", "--alg", "ECDH-ES", "--crv", "X25519"}, kty::OKP, 2},
                 {{"--use", "enc", "--alg", "A192KW"}, kty::oct, 1},
                 {{"--use", "enc", "--alg", "A256GCMKW"}, kty::oct, 1},
                 {{"--use", "enc", "--alg", "dir", "--enc", "A256CBC-HS512"}, kty::oct, 1},
                 {{"--use", "sig", "--alg", "RS512"}, kty::RSA, 2},
                 {{"--use", "sig", "--alg", "HS256"}, kty::oct, 1},
                 {{"--use", "enc", "--alg", "A128KW"}, kty::oct, 1},
                 {{"--use", "enc", "--alg", "A128GCMKW"}, kty::oct, 1},
                 {{"--use", "enc", "--alg", "RSA1_5"}, kty::RSA, 2},
                 {{"--use", "enc", "--alg", "ECDH-ES+A256KW", "--crv", "X448"}, kty::OKP, 2},
                 {{"--use", "enc", "--alg", "ECDH-ES+A192KW", "--crv", "P-521"}, kty::EC, 2},
             }) {
            const auto kid = "k" + std::to_string(n++);
            auto args = w.args;
            args.insert(args.end(), {"--kid", kid});
            INFO(args[3]);
            auto r = gen(args);
            REQUIRE(ok(r));
            const auto use = args[1];
            const auto key = load("jwk-" + use + "-" + kid + "-priv.json");
            CHECK(key.key_type() == w.type);
            CHECK(fs::exists(dir.path / ("jwk-" + use + "-" + kid + "-pub.json")) == (w.files == 2));
            if (args[3] == "RS256") CHECK(EVP_PKEY_get_bits(key.pkey()) == 3072);
            if (args[3] == "HS512") CHECK(key.oct().size() == 64);
            if (args[3] == "A192KW") CHECK(key.oct().size() == 24);
            if (args[3] == "dir") CHECK(key.oct().size() == 64);
            if (args[3] == "ECDH-ES+A128KW") CHECK(key.ec_crv() == ec_curve::P384);
            if (args[3] == "EdDSA" && args.size() > 6 && args[5] == "Ed448") CHECK(key.okp_crv() == okp_curve::Ed448);
        }
    }
    SECTION("refusals") {
        for (const auto& bad : std::vector<std::vector<std::string>>{
                 {"--use", "sig", "--alg", "ES256", "--size", "384"},
                 {"--use", "sig", "--alg", "RS256", "--size", "1024"},
                 {"--use", "sig", "--alg", "HS256", "--size", "128"},
                 {"--use", "sig", "--alg", "HS256", "--size", "260"},
                 {"--use", "enc", "--alg", "A128KW", "--size", "256"},
                 {"--use", "enc", "--alg", "dir"},
                 {"--use", "enc", "--alg", "PBES2-HS256+A128KW"},
                 {"--use", "enc", "--alg", "ES256"},
                 {"--use", "sig", "--alg", "RSA-OAEP"},
                 {"--use", "both", "--alg", "ES256"},
                 {"--use", "sig", "--alg", "ES256", "--crv", "P-256"},
                 {"--use", "sig", "--alg", "ES256", "--size", "x"},
             }) {
            INFO(bad[3] << " " << (bad.size() > 5 ? bad[5] : ""));
            auto r = gen(bad);
            CHECK(r.status != cli::exit_ok);
        }
        CHECK(fs::is_empty(dir.path));
    }
    SECTION("an empty --kid means the thumbprint, as in jose-util") {
        auto r = gen({"--use", "sig", "--alg", "ES256", "--kid="});
        REQUIRE(ok(r));
        CHECK_THAT(r.out, !ContainsSubstring("jwk-sig--"));
    }
#ifndef _WIN32
    SECTION("a dangling symlink in the way: nothing is written") {
        fs::create_symlink(dir.path / "nowhere", dir.path / "jwk-sig-x-priv.json");
        auto r = gen({"--use", "sig", "--alg", "ES256", "--kid", "x"});
        CHECK(r.status == cli::exit_failed);
        CHECK(r.out.empty());
        CHECK_FALSE(fs::exists(dir.path / "jwk-sig-x-pub.json"));
        CHECK_FALSE(fs::exists(dir.path / "nowhere"));
    }
#endif
    SECTION("a kid can't escape the directory") {
        auto r = gen({"--use", "sig", "--alg", "ES256", "--kid", "../../evil"});
        REQUIRE(ok(r));
        CHECK(fs::exists(dir.path / "jwk-sig-_.._.._evil-priv.json"));
        CHECK(load("jwk-sig-_.._.._evil-pub.json").key_id() == "../../evil");
    }
}
