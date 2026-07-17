#include "jose/crypto/hmac.hpp"

#include "hmac_util.hpp"

#include <openssl/crypto.h>

#include <string>

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

    return detail::hmac_digest(params->digest, key, {data});
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
