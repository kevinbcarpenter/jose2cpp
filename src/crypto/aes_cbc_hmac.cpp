#include "jose/crypto/aes_cbc_hmac.hpp"

#include <openssl/evp.h>
#include <openssl/crypto.h>

#include <array>
#include <cstring>

namespace jose {

namespace {

struct cbc_params {
    const EVP_CIPHER* cipher;
    const char* hmac_digest;
    size_t mac_key_len;
    size_t enc_key_len;
    size_t tag_len;
};

auto get_params(content_encryption enc) -> expected<cbc_params> {
    switch (enc) {
    case content_encryption::A128CBC_HS256:
        return cbc_params{EVP_aes_128_cbc(), "SHA256", 16, 16, 16};
    case content_encryption::A192CBC_HS384:
        return cbc_params{EVP_aes_192_cbc(), "SHA384", 24, 24, 24};
    case content_encryption::A256CBC_HS512:
        return cbc_params{EVP_aes_256_cbc(), "SHA512", 32, 32, 32};
    default:
        return make_error(errc::unsupported_algorithm,
                          "not an AES-CBC-HMAC algorithm");
    }
}

auto compute_tag(const cbc_params& p, std::span<const uint8_t> mac_key,
                 std::span<const uint8_t> aad, std::span<const uint8_t> iv,
                 std::span<const uint8_t> ciphertext)
    -> expected<secure_bytes> {
    // AL = AAD length in bits as 64-bit big-endian
    uint64_t al = static_cast<uint64_t>(aad.size()) * 8;
    std::array<uint8_t, 8> al_bytes{};
    for (int i = 7; i >= 0; --i) {
        al_bytes[static_cast<size_t>(i)] = static_cast<uint8_t>(al & 0xFF);
        al >>= 8;
    }

    auto mac = make_evp_mac(EVP_MAC_fetch(nullptr, "HMAC", nullptr));
    if (!mac) return make_openssl_error("EVP_MAC_fetch HMAC");

    auto ctx = make_evp_mac_ctx(EVP_MAC_CTX_new(mac.get()));
    if (!ctx) return make_openssl_error("EVP_MAC_CTX_new");

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(
            "digest", const_cast<char*>(p.hmac_digest), 0),
        OSSL_PARAM_construct_end()};

    if (EVP_MAC_init(ctx.get(), mac_key.data(), mac_key.size(), params) != 1)
        return make_openssl_error("EVP_MAC_init");

    // HMAC input per RFC 7518 §5.2.2.1: A || IV || E || AL
    if (EVP_MAC_update(ctx.get(), aad.data(), aad.size()) != 1 ||
        EVP_MAC_update(ctx.get(), iv.data(), iv.size()) != 1 ||
        EVP_MAC_update(ctx.get(), ciphertext.data(), ciphertext.size()) != 1 ||
        EVP_MAC_update(ctx.get(), al_bytes.data(), al_bytes.size()) != 1)
        return make_openssl_error("EVP_MAC_update");

    secure_bytes full_mac(EVP_MAX_MD_SIZE);
    size_t mac_len = 0;
    if (EVP_MAC_final(ctx.get(), full_mac.data(), &mac_len,
                      full_mac.size()) != 1)
        return make_openssl_error("EVP_MAC_final");

    // Truncate to tag length (first half of HMAC output)
    full_mac.resize(p.tag_len);
    return full_mac;
}

} // namespace

auto aes_cbc_hmac_encrypt(content_encryption enc, std::span<const uint8_t> cek,
                          std::span<const uint8_t> iv,
                          std::span<const uint8_t> plaintext,
                          std::span<const uint8_t> aad)
    -> expected<std::pair<secure_bytes, secure_bytes>> {
    auto params = get_params(enc);
    if (!params) return jose::unexpected(params.error());

    if (cek.size() != cek_byte_size(enc))
        return make_error(errc::invalid_key, "CEK size mismatch");
    if (iv.size() != iv_byte_size(enc))
        return make_error(errc::invalid_iv, "IV size mismatch");

    // Split CEK: first half = MAC key, second half = encryption key
    auto mac_key = cek.subspan(0, params->mac_key_len);
    auto enc_key = cek.subspan(params->mac_key_len, params->enc_key_len);

    // AES-CBC encrypt with PKCS7 padding
    auto ctx = make_evp_cipher_ctx();
    if (!ctx) return make_openssl_error("EVP_CIPHER_CTX_new");

    if (EVP_EncryptInit_ex(ctx.get(), params->cipher, nullptr, enc_key.data(),
                           iv.data()) != 1)
        return make_openssl_error("EVP_EncryptInit_ex");

    secure_bytes ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
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

    // Compute authentication tag
    auto tag = compute_tag(*params, mac_key, aad, iv, ciphertext);
    if (!tag) return jose::unexpected(tag.error());

    return std::pair{std::move(ciphertext), std::move(*tag)};
}

auto aes_cbc_hmac_decrypt(content_encryption enc, std::span<const uint8_t> cek,
                          std::span<const uint8_t> iv,
                          std::span<const uint8_t> ciphertext,
                          std::span<const uint8_t> aad,
                          std::span<const uint8_t> tag)
    -> expected<secure_bytes> {
    auto params = get_params(enc);
    if (!params) return jose::unexpected(params.error());

    if (cek.size() != cek_byte_size(enc))
        return make_error(errc::invalid_key, "CEK size mismatch");
    if (iv.size() != iv_byte_size(enc))
        return make_error(errc::invalid_iv, "IV size mismatch");
    if (tag.size() != tag_byte_size(enc))
        return make_error(errc::invalid_tag, "tag size mismatch");

    // Split CEK
    auto mac_key = cek.subspan(0, params->mac_key_len);
    auto enc_key = cek.subspan(params->mac_key_len, params->enc_key_len);

    // Verify tag first (constant-time comparison)
    auto computed_tag = compute_tag(*params, mac_key, aad, iv, ciphertext);
    if (!computed_tag) return jose::unexpected(computed_tag.error());

    if (CRYPTO_memcmp(computed_tag->data(), tag.data(), params->tag_len) != 0)
        return make_error(errc::invalid_tag, "authentication tag mismatch");

    // AES-CBC decrypt
    auto ctx = make_evp_cipher_ctx();
    if (!ctx) return make_openssl_error("EVP_CIPHER_CTX_new");

    if (EVP_DecryptInit_ex(ctx.get(), params->cipher, nullptr, enc_key.data(),
                           iv.data()) != 1)
        return make_openssl_error("EVP_DecryptInit_ex");

    secure_bytes plaintext(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);
    int out_len = 0;

    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &out_len,
                          ciphertext.data(),
                          static_cast<int>(ciphertext.size())) != 1)
        return make_openssl_error("EVP_DecryptUpdate");

    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + out_len,
                            &final_len) != 1)
        return make_error(errc::decryption_failed,
                          "AES-CBC decryption failed (bad padding)");

    plaintext.resize(static_cast<size_t>(out_len + final_len));
    return plaintext;
}

} // namespace jose
