#include "jose/crypto/aes_gcm.hpp"

#include <openssl/evp.h>

#include <array>

namespace jose {

namespace {

constexpr size_t gcm_iv_len = 12;
constexpr size_t gcm_tag_len = 16;

auto get_cipher(content_encryption enc)
    -> expected<const EVP_CIPHER*> {
    switch (enc) {
    case content_encryption::A128GCM: return EVP_aes_128_gcm();
    case content_encryption::A192GCM: return EVP_aes_192_gcm();
    case content_encryption::A256GCM: return EVP_aes_256_gcm();
    default:
        return make_error(errc::unsupported_algorithm,
                          "not an AES-GCM algorithm");
    }
}

} // namespace

auto aes_gcm_encrypt(content_encryption enc, std::span<const uint8_t> cek,
                     std::span<const uint8_t> iv,
                     std::span<const uint8_t> plaintext,
                     std::span<const uint8_t> aad)
    -> expected<std::pair<secure_bytes, secure_bytes>> {
    auto cipher = get_cipher(enc);
    if (!cipher) return jose::unexpected(cipher.error());

    if (cek.size() != cek_byte_size(enc))
        return make_error(errc::invalid_key, "CEK size mismatch");
    if (iv.size() != gcm_iv_len)
        return make_error(errc::invalid_iv, "IV must be 12 bytes for AES-GCM");

    auto ctx = make_evp_cipher_ctx();
    if (!ctx) return make_openssl_error("EVP_CIPHER_CTX_new");

    if (EVP_EncryptInit_ex(ctx.get(), *cipher, nullptr, nullptr, nullptr) != 1)
        return make_openssl_error("EVP_EncryptInit_ex");

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(gcm_iv_len), nullptr) != 1)
        return make_openssl_error("EVP_CTRL_GCM_SET_IVLEN");

    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, cek.data(),
                           iv.data()) != 1)
        return make_openssl_error("EVP_EncryptInit_ex key/iv");

    // Set AAD
    int aad_len = 0;
    if (EVP_EncryptUpdate(ctx.get(), nullptr, &aad_len, aad.data(),
                          static_cast<int>(aad.size())) != 1)
        return make_openssl_error("EVP_EncryptUpdate AAD");

    // Encrypt plaintext
    secure_bytes ciphertext(plaintext.size());
    int out_len = 0;
    if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &out_len,
                          plaintext.data(),
                          static_cast<int>(plaintext.size())) != 1)
        return make_openssl_error("EVP_EncryptUpdate");

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + out_len,
                            &final_len) != 1)
        return make_openssl_error("EVP_EncryptFinal_ex");

    ciphertext.resize(static_cast<size_t>(out_len + final_len));

    // Extract tag
    secure_bytes tag(gcm_tag_len);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
                            static_cast<int>(gcm_tag_len), tag.data()) != 1)
        return make_openssl_error("EVP_CTRL_GCM_GET_TAG");

    return std::pair{std::move(ciphertext), std::move(tag)};
}

auto aes_gcm_decrypt(content_encryption enc, std::span<const uint8_t> cek,
                     std::span<const uint8_t> iv,
                     std::span<const uint8_t> ciphertext,
                     std::span<const uint8_t> aad,
                     std::span<const uint8_t> tag)
    -> expected<secure_bytes> {
    auto cipher = get_cipher(enc);
    if (!cipher) return jose::unexpected(cipher.error());

    if (cek.size() != cek_byte_size(enc))
        return make_error(errc::invalid_key, "CEK size mismatch");
    if (iv.size() != gcm_iv_len)
        return make_error(errc::invalid_iv, "IV must be 12 bytes for AES-GCM");
    if (tag.size() != gcm_tag_len)
        return make_error(errc::invalid_tag, "tag must be 16 bytes for AES-GCM");

    auto ctx = make_evp_cipher_ctx();
    if (!ctx) return make_openssl_error("EVP_CIPHER_CTX_new");

    if (EVP_DecryptInit_ex(ctx.get(), *cipher, nullptr, nullptr, nullptr) != 1)
        return make_openssl_error("EVP_DecryptInit_ex");

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(gcm_iv_len), nullptr) != 1)
        return make_openssl_error("EVP_CTRL_GCM_SET_IVLEN");

    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, cek.data(),
                           iv.data()) != 1)
        return make_openssl_error("EVP_DecryptInit_ex key/iv");

    // Set AAD
    int aad_len = 0;
    if (EVP_DecryptUpdate(ctx.get(), nullptr, &aad_len, aad.data(),
                          static_cast<int>(aad.size())) != 1)
        return make_openssl_error("EVP_DecryptUpdate AAD");

    // Decrypt ciphertext
    secure_bytes plaintext(ciphertext.size());
    int out_len = 0;
    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &out_len,
                          ciphertext.data(),
                          static_cast<int>(ciphertext.size())) != 1)
        return make_openssl_error("EVP_DecryptUpdate");

    // Set expected tag before finalizing
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
                            static_cast<int>(gcm_tag_len),
                            const_cast<uint8_t*>(tag.data())) != 1)
        return make_openssl_error("EVP_CTRL_GCM_SET_TAG");

    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + out_len,
                            &final_len) != 1)
        return make_error(errc::decryption_failed,
                          "AES-GCM authentication failed");

    plaintext.resize(static_cast<size_t>(out_len + final_len));
    return plaintext;
}

} // namespace jose
