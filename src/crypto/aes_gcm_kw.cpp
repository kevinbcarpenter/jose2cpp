#include "jose/crypto/aes_gcm_kw.hpp"

#include "jose/crypto/aes_gcm.hpp"
#include "jose/crypto/keygen.hpp"

namespace jose {

namespace {

// AES-GCM-KW is AES-GCM over the CEK with no AAD; map the key-management
// algorithm to the matching content-encryption algorithm and reuse it.
auto to_gcm_alg(key_algorithm alg) -> expected<content_encryption> {
    switch (alg) {
    case key_algorithm::A128GCMKW: return content_encryption::A128GCM;
    case key_algorithm::A192GCMKW: return content_encryption::A192GCM;
    case key_algorithm::A256GCMKW: return content_encryption::A256GCM;
    default:
        return make_error(errc::unsupported_algorithm,
                          "not an AES-GCM-KW algorithm");
    }
}

auto check_kek(std::span<const uint8_t> kek, content_encryption gcm)
    -> expected<void> {
    if (kek.size() != cek_byte_size(gcm))
        return make_error(errc::invalid_key, "KEK size mismatch for AES-GCM-KW");
    return {};
}

} // namespace

auto aes_gcm_key_wrap(key_algorithm alg, std::span<const uint8_t> kek,
                      std::span<const uint8_t> cek)
    -> expected<gcm_kw_result> {
    auto gcm = to_gcm_alg(alg);
    if (!gcm) return jose::unexpected(gcm.error());

    auto kek_ok = check_kek(kek, *gcm);
    if (!kek_ok) return jose::unexpected(kek_ok.error());

    auto iv = random_bytes(iv_byte_size(*gcm));
    if (!iv) return jose::unexpected(iv.error());

    auto sealed = aes_gcm_encrypt(*gcm, kek, *iv, cek, {});
    if (!sealed) return jose::unexpected(sealed.error());

    return gcm_kw_result{
        std::move(sealed->ciphertext),
        std::move(*iv),
        std::move(sealed->tag),
    };
}

auto aes_gcm_key_unwrap(key_algorithm alg, std::span<const uint8_t> kek,
                        std::span<const uint8_t> encrypted_key,
                        std::span<const uint8_t> iv,
                        std::span<const uint8_t> tag)
    -> expected<secure_bytes> {
    auto gcm = to_gcm_alg(alg);
    if (!gcm) return jose::unexpected(gcm.error());

    auto kek_ok = check_kek(kek, *gcm);
    if (!kek_ok) return jose::unexpected(kek_ok.error());

    return aes_gcm_decrypt(*gcm, kek, iv, encrypted_key, {}, tag);
}

} // namespace jose
