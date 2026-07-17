#include "jose/crypto/rsa.hpp"

#include <openssl/evp.h>
#include <openssl/rsa.h>

namespace jose {

namespace {

struct rsa_alg_params {
    const EVP_MD* md;
    int padding;
    int salt_len; // only meaningful for PSS
};

auto get_rsa_params(signing_algorithm alg) -> expected<rsa_alg_params> {
    switch (alg) {
    case signing_algorithm::RS256:
        return rsa_alg_params{EVP_sha256(), RSA_PKCS1_PADDING, 0};
    case signing_algorithm::RS384:
        return rsa_alg_params{EVP_sha384(), RSA_PKCS1_PADDING, 0};
    case signing_algorithm::RS512:
        return rsa_alg_params{EVP_sha512(), RSA_PKCS1_PADDING, 0};
    case signing_algorithm::PS256:
        return rsa_alg_params{EVP_sha256(), RSA_PKCS1_PSS_PADDING, RSA_PSS_SALTLEN_DIGEST};
    case signing_algorithm::PS384:
        return rsa_alg_params{EVP_sha384(), RSA_PKCS1_PSS_PADDING, RSA_PSS_SALTLEN_DIGEST};
    case signing_algorithm::PS512:
        return rsa_alg_params{EVP_sha512(), RSA_PKCS1_PSS_PADDING, RSA_PSS_SALTLEN_DIGEST};
    default:
        return make_error(errc::unsupported_algorithm,
                          "not an RSA signing algorithm");
    }
}

auto configure_pkey_ctx(EVP_PKEY_CTX* pctx, const rsa_alg_params& params)
    -> expected<void> {
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, params.padding) <= 0)
        return make_openssl_error("EVP_PKEY_CTX_set_rsa_padding");

    if (params.padding == RSA_PKCS1_PSS_PADDING) {
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, params.salt_len) <= 0)
            return make_openssl_error("EVP_PKEY_CTX_set_rsa_pss_saltlen");
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, params.md) <= 0)
            return make_openssl_error("EVP_PKEY_CTX_set_rsa_mgf1_md");
    }
    return {};
}

} // namespace

auto rsa_sign(signing_algorithm alg, EVP_PKEY* key,
              std::span<const uint8_t> data) -> expected<secure_bytes> {
    auto params = get_rsa_params(alg);
    if (!params) return jose::unexpected(params.error());

    auto ctx = make_evp_md_ctx();
    if (!ctx) return make_openssl_error("EVP_MD_CTX_new");

    EVP_PKEY_CTX* pctx = nullptr; // owned by ctx
    if (EVP_DigestSignInit(ctx.get(), &pctx, params->md, nullptr, key) != 1)
        return make_openssl_error("EVP_DigestSignInit");

    auto cfg = configure_pkey_ctx(pctx, *params);
    if (!cfg) return jose::unexpected(cfg.error());

    if (EVP_DigestSignUpdate(ctx.get(), data.data(), data.size()) != 1)
        return make_openssl_error("EVP_DigestSignUpdate");

    size_t sig_len = 0;
    if (EVP_DigestSignFinal(ctx.get(), nullptr, &sig_len) != 1)
        return make_openssl_error("EVP_DigestSignFinal (length query)");

    secure_bytes sig(sig_len);
    if (EVP_DigestSignFinal(ctx.get(), sig.data(), &sig_len) != 1)
        return make_openssl_error("EVP_DigestSignFinal");

    sig.resize(sig_len);
    return sig;
}

auto rsa_verify(signing_algorithm alg, EVP_PKEY* key,
                std::span<const uint8_t> data,
                std::span<const uint8_t> signature) -> expected<void> {
    auto params = get_rsa_params(alg);
    if (!params) return jose::unexpected(params.error());

    auto ctx = make_evp_md_ctx();
    if (!ctx) return make_openssl_error("EVP_MD_CTX_new");

    EVP_PKEY_CTX* pctx = nullptr; // owned by ctx
    if (EVP_DigestVerifyInit(ctx.get(), &pctx, params->md, nullptr, key) != 1)
        return make_openssl_error("EVP_DigestVerifyInit");

    auto cfg = configure_pkey_ctx(pctx, *params);
    if (!cfg) return jose::unexpected(cfg.error());

    if (EVP_DigestVerifyUpdate(ctx.get(), data.data(), data.size()) != 1)
        return make_openssl_error("EVP_DigestVerifyUpdate");

    if (EVP_DigestVerifyFinal(ctx.get(), signature.data(), signature.size()) != 1)
        return make_error(errc::invalid_signature, "RSA signature verification failed");

    return {};
}

} // namespace jose
