#include "jose/crypto/aes_gcm_kw.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>

namespace jose {

namespace {

constexpr size_t gcm_kw_iv_len = 12;
constexpr size_t gcm_kw_tag_len = 16;

struct gcm_kw_params {
    const EVP_CIPHER* cipher;
    size_t kek_size;
};

auto get_gcm_kw_params(key_algorithm alg) -> expected<gcm_kw_params> {
    switch (alg) {
    case key_algorithm::A128GCMKW: return gcm_kw_params{EVP_aes_128_gcm(), 16};
    case key_algorithm::A192GCMKW: return gcm_kw_params{EVP_aes_192_gcm(), 24};
    case key_algorithm::A256GCMKW: return gcm_kw_params{EVP_aes_256_gcm(), 32};
    default:
        return make_error(errc::unsupported_algorithm,
                          "not an AES-GCM-KW algorithm");
    }
}

} // namespace

auto aes_gcm_key_wrap(key_algorithm alg, std::span<const uint8_t> kek,
                      std::span<const uint8_t> cek)
    -> expected<gcm_kw_result> {
    auto params = get_gcm_kw_params(alg);
    if (!params) return jose::unexpected(params.error());

    if (kek.size() != params->kek_size)
        return make_error(errc::invalid_key, "KEK size mismatch for AES-GCM-KW");

    // Generate random 96-bit IV
    secure_bytes iv(gcm_kw_iv_len);
    if (RAND_bytes(iv.data(), static_cast<int>(gcm_kw_iv_len)) != 1)
        return make_openssl_error("RAND_bytes");

    auto ctx = make_evp_cipher_ctx();
    if (!ctx) return make_openssl_error("EVP_CIPHER_CTX_new");

    if (EVP_EncryptInit_ex(ctx.get(), params->cipher, nullptr, nullptr,
                           nullptr) != 1)
        return make_openssl_error("EVP_EncryptInit_ex");

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(gcm_kw_iv_len), nullptr) != 1)
        return make_openssl_error("EVP_CTRL_GCM_SET_IVLEN");

    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, kek.data(),
                           iv.data()) != 1)
        return make_openssl_error("EVP_EncryptInit_ex key/iv");

    // No AAD for key wrapping

    // Encrypt CEK
    secure_bytes encrypted_key(cek.size());
    int out_len = 0;
    if (EVP_EncryptUpdate(ctx.get(), encrypted_key.data(), &out_len,
                          cek.data(), static_cast<int>(cek.size())) != 1)
        return make_openssl_error("EVP_EncryptUpdate");

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), encrypted_key.data() + out_len,
                            &final_len) != 1)
        return make_openssl_error("EVP_EncryptFinal_ex");

    encrypted_key.resize(static_cast<size_t>(out_len + final_len));

    // Extract authentication tag
    secure_bytes tag(gcm_kw_tag_len);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
                            static_cast<int>(gcm_kw_tag_len),
                            tag.data()) != 1)
        return make_openssl_error("EVP_CTRL_GCM_GET_TAG");

    return gcm_kw_result{
        std::move(encrypted_key),
        std::move(iv),
        std::move(tag),
    };
}

auto aes_gcm_key_unwrap(key_algorithm alg, std::span<const uint8_t> kek,
                        std::span<const uint8_t> encrypted_key,
                        std::span<const uint8_t> iv,
                        std::span<const uint8_t> tag)
    -> expected<secure_bytes> {
    auto params = get_gcm_kw_params(alg);
    if (!params) return jose::unexpected(params.error());

    if (kek.size() != params->kek_size)
        return make_error(errc::invalid_key, "KEK size mismatch for AES-GCM-KW");
    if (iv.size() != gcm_kw_iv_len)
        return make_error(errc::invalid_iv, "IV must be 12 bytes for AES-GCM-KW");
    if (tag.size() != gcm_kw_tag_len)
        return make_error(errc::invalid_tag,
                          "tag must be 16 bytes for AES-GCM-KW");

    auto ctx = make_evp_cipher_ctx();
    if (!ctx) return make_openssl_error("EVP_CIPHER_CTX_new");

    if (EVP_DecryptInit_ex(ctx.get(), params->cipher, nullptr, nullptr,
                           nullptr) != 1)
        return make_openssl_error("EVP_DecryptInit_ex");

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(gcm_kw_iv_len), nullptr) != 1)
        return make_openssl_error("EVP_CTRL_GCM_SET_IVLEN");

    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, kek.data(),
                           iv.data()) != 1)
        return make_openssl_error("EVP_DecryptInit_ex key/iv");

    // No AAD for key wrapping

    // Decrypt encrypted key
    secure_bytes cek(encrypted_key.size());
    int out_len = 0;
    if (EVP_DecryptUpdate(ctx.get(), cek.data(), &out_len,
                          encrypted_key.data(),
                          static_cast<int>(encrypted_key.size())) != 1)
        return make_openssl_error("EVP_DecryptUpdate");

    // Set expected tag before finalizing
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
                            static_cast<int>(gcm_kw_tag_len),
                            const_cast<uint8_t*>(tag.data())) != 1)
        return make_openssl_error("EVP_CTRL_GCM_SET_TAG");

    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), cek.data() + out_len,
                            &final_len) != 1)
        return make_error(errc::decryption_failed,
                          "AES-GCM-KW authentication failed");

    cek.resize(static_cast<size_t>(out_len + final_len));
    return cek;
}

} // namespace jose
