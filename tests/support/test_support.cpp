#include "test_support.hpp"

#include "jose/base64url.hpp"

#include <catch2/catch_test_macros.hpp>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <fstream>
#include <memory>
#include <sstream>

#ifndef JOSE_TEST_VECTORS_DIR
#error "JOSE_TEST_VECTORS_DIR must be defined by the build"
#endif

namespace jose::test {

namespace {

using bn_ptr = std::unique_ptr<BIGNUM, decltype(&BN_clear_free)>;
using param_bld_ptr = std::unique_ptr<OSSL_PARAM_BLD, decltype(&OSSL_PARAM_BLD_free)>;
using params_ptr = std::unique_ptr<OSSL_PARAM, decltype(&OSSL_PARAM_free)>;

auto to_bn(const std::vector<uint8_t>& bytes) -> bn_ptr {
    bn_ptr bn{BN_bin2bn(bytes.data(), static_cast<int>(bytes.size()), nullptr),
              BN_clear_free};
    REQUIRE(bn != nullptr);
    return bn;
}

auto from_params(const char* type, OSSL_PARAM_BLD* bld, bool has_private)
    -> evp_pkey_ptr {
    params_ptr params{OSSL_PARAM_BLD_to_param(bld), OSSL_PARAM_free};
    REQUIRE(params != nullptr);

    auto ctx = make_evp_pkey_ctx(EVP_PKEY_CTX_new_from_name(nullptr, type, nullptr));
    REQUIRE(ctx != nullptr);
    REQUIRE(EVP_PKEY_fromdata_init(ctx.get()) == 1);

    EVP_PKEY* raw = nullptr;
    const int selection = has_private ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY;
    REQUIRE(EVP_PKEY_fromdata(ctx.get(), &raw, selection, params.get()) == 1);
    return make_evp_pkey_ptr(raw);
}

auto rsa_from_jwk(const nlohmann::json& jwk) -> evp_pkey_ptr {
    param_bld_ptr bld{OSSL_PARAM_BLD_new(), OSSL_PARAM_BLD_free};
    REQUIRE(bld != nullptr);

    // BIGNUMs must outlive OSSL_PARAM_BLD_to_param.
    std::vector<bn_ptr> keep;
    auto push = [&](const char* jwk_name, const char* param_name) {
        keep.push_back(to_bn(b64(jwk.at(jwk_name))));
        REQUIRE(OSSL_PARAM_BLD_push_BN(bld.get(), param_name, keep.back().get()) == 1);
    };

    push("n", OSSL_PKEY_PARAM_RSA_N);
    push("e", OSSL_PKEY_PARAM_RSA_E);
    const bool priv = jwk.contains("d");
    if (priv) {
        push("d", OSSL_PKEY_PARAM_RSA_D);
        push("p", OSSL_PKEY_PARAM_RSA_FACTOR1);
        push("q", OSSL_PKEY_PARAM_RSA_FACTOR2);
        push("dp", OSSL_PKEY_PARAM_RSA_EXPONENT1);
        push("dq", OSSL_PKEY_PARAM_RSA_EXPONENT2);
        push("qi", OSSL_PKEY_PARAM_RSA_COEFFICIENT1);
    }
    return from_params("RSA", bld.get(), priv);
}

auto ec_from_jwk(const nlohmann::json& jwk) -> evp_pkey_ptr {
    const auto crv = jwk.at("crv").get<std::string>();
    const char* group = crv == "P-256"   ? "prime256v1"
                        : crv == "P-384" ? "secp384r1"
                        : crv == "P-521" ? "secp521r1"
                                         : nullptr;
    REQUIRE(group != nullptr);

    // Uncompressed point: 0x04 || X || Y
    std::vector<uint8_t> point{0x04};
    auto x = b64(jwk.at("x"));
    auto y = b64(jwk.at("y"));
    point.insert(point.end(), x.begin(), x.end());
    point.insert(point.end(), y.begin(), y.end());

    param_bld_ptr bld{OSSL_PARAM_BLD_new(), OSSL_PARAM_BLD_free};
    REQUIRE(bld != nullptr);
    REQUIRE(OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_GROUP_NAME,
                                            group, 0) == 1);
    REQUIRE(OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY,
                                             point.data(), point.size()) == 1);
    bn_ptr d{nullptr, BN_clear_free};
    const bool priv = jwk.contains("d");
    if (priv) {
        d = to_bn(b64(jwk.at("d")));
        REQUIRE(OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_PRIV_KEY, d.get()) == 1);
    }
    return from_params("EC", bld.get(), priv);
}

auto okp_from_jwk(const nlohmann::json& jwk) -> evp_pkey_ptr {
    const auto crv = jwk.at("crv").get<std::string>();
    const int id = crv == "Ed25519" ? EVP_PKEY_ED25519
                   : crv == "Ed448" ? EVP_PKEY_ED448
                   : crv == "X25519" ? EVP_PKEY_X25519
                   : crv == "X448"  ? EVP_PKEY_X448
                                    : 0;
    REQUIRE(id != 0);

    const auto x = b64(jwk.at("x"));
    if (!jwk.contains("d")) {
        auto key = make_evp_pkey_ptr(
            EVP_PKEY_new_raw_public_key(id, nullptr, x.data(), x.size()));
        REQUIRE(key != nullptr);
        return key;
    }

    const auto d = b64(jwk.at("d"));
    auto key = make_evp_pkey_ptr(
        EVP_PKEY_new_raw_private_key(id, nullptr, d.data(), d.size()));
    REQUIRE(key != nullptr);

    // The vector's public key must match the one derived from "d".
    std::vector<uint8_t> derived(x.size());
    size_t len = derived.size();
    REQUIRE(EVP_PKEY_get_raw_public_key(key.get(), derived.data(), &len) == 1);
    REQUIRE(derived == x);
    return key;
}

} // namespace

auto load_vectors(std::string_view name) -> nlohmann::json {
    const std::string path =
        std::string(JOSE_TEST_VECTORS_DIR) + "/" + std::string(name) + ".json";
    std::ifstream in(path);
    INFO("vector file: " << path);
    REQUIRE(in.good());
    auto cases = nlohmann::json::parse(in);
    REQUIRE(cases.is_array());
    REQUIRE_FALSE(cases.empty());
    return cases;
}

auto b64(const nlohmann::json& value) -> std::vector<uint8_t> {
    auto decoded = base64url::decode(value.get<std::string>());
    REQUIRE(decoded.has_value());
    return {decoded->begin(), decoded->end()};
}

auto b64_string(const nlohmann::json& value) -> std::string {
    auto bytes = b64(value);
    return {bytes.begin(), bytes.end()};
}

auto key_from_jwk(const nlohmann::json& jwk) -> evp_pkey_ptr {
    const auto kty = jwk.at("kty").get<std::string>();
    if (kty == "RSA") return rsa_from_jwk(jwk);
    if (kty == "EC") return ec_from_jwk(jwk);
    if (kty == "OKP") return okp_from_jwk(jwk);
    FAIL("unsupported kty in test vector: " << kty);
    return make_evp_pkey_ptr();
}

auto self_signed_pem(EVP_PKEY* key, const char* cn) -> std::string {
    std::unique_ptr<X509, decltype(&X509_free)> cert{X509_new(), X509_free};
    REQUIRE(cert);
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 3600);
    REQUIRE(X509_set_pubkey(cert.get(), key) == 1);
    X509_NAME* name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(cn), -1, -1, 0);
    X509_set_issuer_name(cert.get(), name);
    REQUIRE(X509_sign(cert.get(), key, EVP_sha256()) > 0);

    std::unique_ptr<BIO, decltype(&BIO_free)> bio{BIO_new(BIO_s_mem()), BIO_free};
    REQUIRE(PEM_write_bio_X509(bio.get(), cert.get()) == 1);
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio.get(), &data);
    return {data, static_cast<size_t>(len)};
}

} // namespace jose::test
