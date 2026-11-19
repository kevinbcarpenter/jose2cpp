#include "jose/crypto/aes_kw.hpp"

#include <openssl/evp.h>

namespace jose {

namespace {

struct kw_params {
    const EVP_CIPHER* cipher;
    size_t kek_size;
};

auto get_kw_params(key_algorithm alg) -> expected<kw_params> {
    switch (alg) {
    case key_algorithm::A128KW: return kw_params{EVP_aes_128_wrap(), 16};
    case key_algorithm::A192KW: return kw_params{EVP_aes_192_wrap(), 24};
    case key_algorithm::A256KW: return kw_params{EVP_aes_256_wrap(), 32};
    default:
        return make_error(errc::unsupported_algorithm,
                          "not an AES-KW algorithm");
    }
}

// RFC 3394 default IV (A6)
constexpr uint8_t default_iv[8] = {
    0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6};

} // namespace

auto aes_key_wrap(key_algorithm alg, std::span<const uint8_t> kek,
                  std::span<const uint8_t> cek) -> expected<secure_bytes> {
    auto params = get_kw_params(alg);
    if (!params) return jose::unexpected(params.error());

    if (kek.size() != params->kek_size)
        return make_error(errc::invalid_key, "KEK size mismatch for AES-KW");

    if (cek.empty() || cek.size() % 8 != 0)
        return make_error(errc::invalid_key,
                          "CEK must be non-empty and a multiple of 8 bytes");

    auto ctx = make_evp_cipher_ctx();
    if (!ctx) return make_openssl_error("EVP_CIPHER_CTX_new");

    EVP_CIPHER_CTX_set_flags(ctx.get(), EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

    if (EVP_EncryptInit_ex(ctx.get(), params->cipher, nullptr, kek.data(),
                           default_iv) != 1)
        return make_openssl_error("EVP_EncryptInit_ex");

    // Wrapped output is 8 bytes longer than input
    secure_bytes out(cek.size() + 8);
    int out_len = 0;

    if (EVP_EncryptUpdate(ctx.get(), out.data(), &out_len, cek.data(),
                          static_cast<int>(cek.size())) != 1)
        return make_openssl_error("EVP_EncryptUpdate");

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), out.data() + out_len,
                            &final_len) != 1)
        return make_openssl_error("EVP_EncryptFinal_ex");

    out.resize(static_cast<size_t>(out_len + final_len));
    return out;
}

auto aes_key_unwrap(key_algorithm alg, std::span<const uint8_t> kek,
                    std::span<const uint8_t> encrypted_key)
    -> expected<secure_bytes> {
    auto params = get_kw_params(alg);
    if (!params) return jose::unexpected(params.error());

    if (kek.size() != params->kek_size)
        return make_error(errc::invalid_key, "KEK size mismatch for AES-KW");

    if (encrypted_key.size() < 24 || encrypted_key.size() % 8 != 0)
        return make_error(errc::invalid_key,
                          "encrypted key must be >= 24 bytes and a multiple of 8");

    auto ctx = make_evp_cipher_ctx();
    if (!ctx) return make_openssl_error("EVP_CIPHER_CTX_new");

    EVP_CIPHER_CTX_set_flags(ctx.get(), EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

    if (EVP_DecryptInit_ex(ctx.get(), params->cipher, nullptr, kek.data(),
                           default_iv) != 1)
        return make_openssl_error("EVP_DecryptInit_ex");

    // Unwrapped output is 8 bytes shorter than input
    secure_bytes out(encrypted_key.size() - 8);
    int out_len = 0;

    if (EVP_DecryptUpdate(ctx.get(), out.data(), &out_len,
                          encrypted_key.data(),
                          static_cast<int>(encrypted_key.size())) != 1)
        return make_crypto_failure(errc::decryption_failed,
                                   "AES key unwrap failed (integrity check)");

    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), out.data() + out_len,
                            &final_len) != 1)
        return make_crypto_failure(errc::decryption_failed,
                                   "AES key unwrap finalize failed");

    out.resize(static_cast<size_t>(out_len + final_len));
    return out;
}

} // namespace jose
