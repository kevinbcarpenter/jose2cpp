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

// OpenSSL keeps a per-thread error queue. Whenever the library turns an
// OpenSSL failure into a jose::error it must drain that queue: otherwise
// the entries accumulate, and a later failure would be reported with
// whatever stale error happened to be oldest.

// Describe the most recent OpenSSL error (the one raised by the call that
// just failed), then clear the queue.
inline auto openssl_error_string() -> std::string {
    const unsigned long err = ERR_peek_last_error();
    std::string out = "unknown OpenSSL error";
    if (err != 0) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        out = buf;
    }
    ERR_clear_error();
    return out;
}

// An OpenSSL call failed for an unexpected reason: report OpenSSL's error.
inline auto make_openssl_error(const std::string& context) -> unexpected {
    return make_error(errc::openssl_error, context + ": " + openssl_error_string());
}

// An OpenSSL call failed for an expected, input-dependent reason (bad tag,
// bad signature, bad padding, wrong key type): report a jose error code and
// discard OpenSSL's detail, which callers should not see or depend on.
inline auto make_crypto_failure(errc code, std::string message) -> unexpected {
    ERR_clear_error();
    return make_error(code, std::move(message));
}

} // namespace jose
