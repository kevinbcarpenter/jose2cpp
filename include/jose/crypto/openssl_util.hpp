#pragma once

#include "jose/error.hpp"
#include "jose/secure_bytes.hpp"

#include <memory>
#include <string>

#include <openssl/evp.h>
#include <openssl/err.h>

namespace jose {

// --- OpenSSL RAII wrappers ---

using evp_pkey_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using evp_md_ctx_ptr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using evp_cipher_ctx_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
using evp_pkey_ctx_ptr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using evp_mac_ptr = std::unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)>;
using evp_mac_ctx_ptr = std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)>;

inline auto make_evp_pkey_ptr(EVP_PKEY* p = nullptr) -> evp_pkey_ptr {
    return {p, EVP_PKEY_free};
}

inline auto make_evp_md_ctx() -> evp_md_ctx_ptr {
    return {EVP_MD_CTX_new(), EVP_MD_CTX_free};
}

inline auto make_evp_cipher_ctx() -> evp_cipher_ctx_ptr {
    return {EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free};
}

inline auto make_evp_pkey_ctx(EVP_PKEY_CTX* p = nullptr) -> evp_pkey_ctx_ptr {
    return {p, EVP_PKEY_CTX_free};
}

inline auto make_evp_mac(EVP_MAC* p = nullptr) -> evp_mac_ptr {
    return {p, EVP_MAC_free};
}

inline auto make_evp_mac_ctx(EVP_MAC_CTX* p = nullptr) -> evp_mac_ctx_ptr {
    return {p, EVP_MAC_CTX_free};
}

// --- OpenSSL error helpers ---

inline auto openssl_error_string() -> std::string {
    unsigned long err = ERR_get_error();
    if (err == 0) return "unknown OpenSSL error";
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    return buf;
}

inline auto make_openssl_error(const std::string& context) -> unexpected {
    return make_error(errc::openssl_error, context + ": " + openssl_error_string());
}

} // namespace jose
