#include "jose/crypto/hmac.hpp"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

namespace jose {

namespace {

struct hmac_params {
    const char* digest;
    size_t min_key_bytes;
};

auto get_hmac_params(signing_algorithm alg) -> expected<hmac_params> {
    switch (alg) {
    case signing_algorithm::HS256: return hmac_params{"SHA256", 32};
    case signing_algorithm::HS384: return hmac_params{"SHA384", 48};
    case signing_algorithm::HS512: return hmac_params{"SHA512", 64};
    default:
        return make_error(errc::unsupported_algorithm,
                          "not an HMAC algorithm");
    }
}

} // namespace

auto hmac_sign(signing_algorithm alg, std::span<const uint8_t> key,
               std::span<const uint8_t> data) -> expected<secure_bytes> {
    auto params = get_hmac_params(alg);
    if (!params) return jose::unexpected(params.error());

    if (key.size() < params->min_key_bytes)
        return make_error(errc::key_too_short,
                          "HMAC key must be at least " +
                              std::to_string(params->min_key_bytes) + " bytes");

    auto mac = make_evp_mac(EVP_MAC_fetch(nullptr, "HMAC", nullptr));
    if (!mac) return make_openssl_error("EVP_MAC_fetch");

    auto ctx = make_evp_mac_ctx(EVP_MAC_CTX_new(mac.get()));
    if (!ctx) return make_openssl_error("EVP_MAC_CTX_new");

    OSSL_PARAM ossl_params[] = {
        OSSL_PARAM_construct_utf8_string(
            OSSL_MAC_PARAM_DIGEST,
            const_cast<char*>(params->digest), 0),
        OSSL_PARAM_construct_end()};

    if (EVP_MAC_init(ctx.get(), key.data(), key.size(), ossl_params) != 1)
        return make_openssl_error("EVP_MAC_init");

    if (EVP_MAC_update(ctx.get(), data.data(), data.size()) != 1)
        return make_openssl_error("EVP_MAC_update");

    size_t out_len = EVP_MAC_CTX_get_mac_size(ctx.get());
    if (out_len == 0)
        return make_error(errc::openssl_error, "EVP_MAC_CTX_get_mac_size returned 0");

    secure_bytes result(out_len);
    if (EVP_MAC_final(ctx.get(), result.data(), &out_len, result.size()) != 1)
        return make_openssl_error("EVP_MAC_final");

    result.resize(out_len);
    return result;
}

auto hmac_verify(signing_algorithm alg, std::span<const uint8_t> key,
                 std::span<const uint8_t> data,
                 std::span<const uint8_t> signature) -> expected<void> {
    auto computed = hmac_sign(alg, key, data);
    if (!computed) return jose::unexpected(computed.error());

    if (computed->size() != signature.size() ||
        CRYPTO_memcmp(computed->data(), signature.data(),
                      computed->size()) != 0)
        return make_error(errc::invalid_signature, "HMAC verification failed");

    return {};
}

} // namespace jose
