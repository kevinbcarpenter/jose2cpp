#include "jose/crypto/encryption.hpp"

#include "jose/crypto/aes_cbc_hmac.hpp"
#include "jose/crypto/aes_gcm.hpp"
#include "jose/crypto/keygen.hpp"

namespace jose {

namespace {

auto is_gcm(content_encryption enc) -> bool {
    switch (enc) {
    case content_encryption::A128GCM:
    case content_encryption::A192GCM:
    case content_encryption::A256GCM:
        return true;
    case content_encryption::A128CBC_HS256:
    case content_encryption::A192CBC_HS384:
    case content_encryption::A256CBC_HS512:
        return false;
    }
    return false;
}

} // namespace

auto encrypt(content_encryption enc, std::span<const uint8_t> cek,
             std::span<const uint8_t> iv,
             std::span<const uint8_t> plaintext,
             std::span<const uint8_t> aad) -> expected<encryption_result> {
    return is_gcm(enc) ? aes_gcm_encrypt(enc, cek, iv, plaintext, aad)
                       : aes_cbc_hmac_encrypt(enc, cek, iv, plaintext, aad);
}

auto decrypt(content_encryption enc, std::span<const uint8_t> cek,
             std::span<const uint8_t> iv,
             std::span<const uint8_t> ciphertext,
             std::span<const uint8_t> aad,
             std::span<const uint8_t> tag) -> expected<secure_bytes> {
    return is_gcm(enc) ? aes_gcm_decrypt(enc, cek, iv, ciphertext, aad, tag)
                       : aes_cbc_hmac_decrypt(enc, cek, iv, ciphertext, aad, tag);
}

auto generate_cek(content_encryption enc) -> expected<secure_bytes> {
    return random_bytes(cek_byte_size(enc));
}

auto generate_iv(content_encryption enc) -> expected<secure_bytes> {
    return random_bytes(iv_byte_size(enc));
}

} // namespace jose
