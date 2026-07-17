#pragma once

#include "jose/error.hpp"

#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#if defined(__unix__) || defined(__APPLE__)
#include <sys/mman.h>
#endif

namespace jose {

// --- Secure allocator ---

template <typename T>
struct secure_allocator {
    using value_type = T;

    secure_allocator() noexcept = default;

    template <typename U>
    constexpr secure_allocator(const secure_allocator<U>&) noexcept {}

    [[nodiscard]] auto allocate(std::size_t n) -> T* {
        return std::allocator<T>{}.allocate(n);
    }

    void deallocate(T* p, std::size_t n) noexcept {
        OPENSSL_cleanse(p, n * sizeof(T));
        std::allocator<T>{}.deallocate(p, n);
    }

    template <typename U>
    auto operator==(const secure_allocator<U>&) const noexcept -> bool { return true; }
};

using secure_bytes = std::vector<uint8_t, secure_allocator<uint8_t>>;

inline auto to_span(const secure_bytes& v) -> std::span<const uint8_t> {
    return {v.data(), v.size()};
}

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

// --- Secure mlock helper (best-effort) ---

inline void secure_mlock(void* ptr, std::size_t len) {
#if defined(__unix__) || defined(__APPLE__)
    ::mlock(ptr, len); // ignore failure — best-effort
#endif
}

inline void secure_munlock(void* ptr, std::size_t len) {
#if defined(__unix__) || defined(__APPLE__)
    ::munlock(ptr, len);
#endif
}

} // namespace jose
