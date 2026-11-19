#include "jose/crypto/eddsa.hpp"

#include <openssl/evp.h>

namespace jose {

namespace {

auto expected_sig_size(EVP_PKEY* key) -> expected<size_t> {
    if (EVP_PKEY_is_a(key, "ED25519"))
        return 64;
    if (EVP_PKEY_is_a(key, "ED448"))
        return 114;
    return make_error(errc::invalid_key,
                      "EdDSA key is neither Ed25519 nor Ed448");
}

} // namespace

auto eddsa_sign(EVP_PKEY* key,
                std::span<const uint8_t> data) -> expected<secure_bytes> {
    auto sig_size = expected_sig_size(key);
    if (!sig_size) return jose::unexpected(sig_size.error());

    auto ctx = make_evp_md_ctx();
    if (!ctx) return make_openssl_error("EVP_MD_CTX_new");

    // md=NULL: Ed25519/Ed448 handle hashing internally
    if (EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, key) != 1)
        return make_openssl_error("EVP_DigestSignInit");

    // One-shot signing (required for EdDSA — Update/Final is not supported)
    size_t siglen = 0;
    if (EVP_DigestSign(ctx.get(), nullptr, &siglen, data.data(), data.size()) != 1)
        return make_openssl_error("EVP_DigestSign (length query)");

    secure_bytes sig(siglen);
    if (EVP_DigestSign(ctx.get(), sig.data(), &siglen, data.data(), data.size()) != 1)
        return make_openssl_error("EVP_DigestSign");

    sig.resize(siglen);
    return sig;
}

auto eddsa_verify(EVP_PKEY* key,
                  std::span<const uint8_t> data,
                  std::span<const uint8_t> signature) -> expected<void> {
    auto sig_size = expected_sig_size(key);
    if (!sig_size) return jose::unexpected(sig_size.error());

    if (signature.size() != *sig_size)
        return make_error(errc::invalid_signature,
                          "EdDSA signature has wrong length");

    auto ctx = make_evp_md_ctx();
    if (!ctx) return make_openssl_error("EVP_MD_CTX_new");

    // md=NULL: Ed25519/Ed448 handle hashing internally
    if (EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, key) != 1)
        return make_openssl_error("EVP_DigestVerifyInit");

    // One-shot verification (required for EdDSA — Update/Final is not supported)
    if (EVP_DigestVerify(ctx.get(), signature.data(), signature.size(),
                         data.data(), data.size()) != 1)
        return make_crypto_failure(errc::invalid_signature,
                                   "EdDSA signature verification failed");

    return {};
}

} // namespace jose
