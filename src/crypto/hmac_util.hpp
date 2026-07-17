#pragma once

// Internal helper shared by the HMAC signing and AES-CBC-HMAC modules.
// Not installed; not part of the public API.

#include "jose/crypto/openssl_util.hpp"

#include <openssl/core_names.h>

#include <initializer_list>
#include <span>

namespace jose::detail {

// One-shot HMAC over the concatenation of `parts`, returning the full
// digest-length MAC.
inline auto hmac_digest(const char* digest, std::span<const uint8_t> key,
                        std::initializer_list<std::span<const uint8_t>> parts)
    -> expected<secure_bytes> {
    auto mac = make_evp_mac(EVP_MAC_fetch(nullptr, "HMAC", nullptr));
    if (!mac) return make_openssl_error("EVP_MAC_fetch");

    auto ctx = make_evp_mac_ctx(EVP_MAC_CTX_new(mac.get()));
    if (!ctx) return make_openssl_error("EVP_MAC_CTX_new");

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                         const_cast<char*>(digest), 0),
        OSSL_PARAM_construct_end()};

    if (EVP_MAC_init(ctx.get(), key.data(), key.size(), params) != 1)
        return make_openssl_error("EVP_MAC_init");

    for (auto part : parts) {
        if (part.empty()) continue;
        if (EVP_MAC_update(ctx.get(), part.data(), part.size()) != 1)
            return make_openssl_error("EVP_MAC_update");
    }

    secure_bytes out(EVP_MAX_MD_SIZE);
    size_t out_len = 0;
    if (EVP_MAC_final(ctx.get(), out.data(), &out_len, out.size()) != 1)
        return make_openssl_error("EVP_MAC_final");

    out.resize(out_len);
    return out;
}

} // namespace jose::detail
