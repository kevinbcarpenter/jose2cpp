#include "jose/crypto/rsa.hpp"

#include "jose/crypto/keygen.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <climits>
#include <string>

namespace jose {

namespace {

struct rsa_alg_params {
    const EVP_MD* md;
    int padding;
    int salt_len; // only meaningful for PSS
};

auto get_rsa_params(signing_algorithm alg) -> expected<rsa_alg_params> {
    switch (alg) {
    case signing_algorithm::RS256:
        return rsa_alg_params{EVP_sha256(), RSA_PKCS1_PADDING, 0};
    case signing_algorithm::RS384:
        return rsa_alg_params{EVP_sha384(), RSA_PKCS1_PADDING, 0};
    case signing_algorithm::RS512:
        return rsa_alg_params{EVP_sha512(), RSA_PKCS1_PADDING, 0};
    case signing_algorithm::PS256:
        return rsa_alg_params{EVP_sha256(), RSA_PKCS1_PSS_PADDING, RSA_PSS_SALTLEN_DIGEST};
    case signing_algorithm::PS384:
        return rsa_alg_params{EVP_sha384(), RSA_PKCS1_PSS_PADDING, RSA_PSS_SALTLEN_DIGEST};
    case signing_algorithm::PS512:
        return rsa_alg_params{EVP_sha512(), RSA_PKCS1_PSS_PADDING, RSA_PSS_SALTLEN_DIGEST};
    default:
        return make_error(errc::unsupported_algorithm,
                          "not an RSA signing algorithm");
    }
}

// RFC 7518 §3.3 / §4.2: RSA keys of fewer than 2048 bits are too weak.
auto check_key_size(EVP_PKEY* key) -> expected<void> {
    const int bits = EVP_PKEY_get_bits(key);
    if (bits < 2048)
        return make_error(errc::key_size_too_small,
                          "RSA key must be at least 2048 bits (got " +
                              std::to_string(bits) + ")");
    return {};
}

auto configure_pkey_ctx(EVP_PKEY_CTX* pctx, const rsa_alg_params& params)
    -> expected<void> {
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, params.padding) <= 0)
        return make_openssl_error("EVP_PKEY_CTX_set_rsa_padding");

    if (params.padding == RSA_PKCS1_PSS_PADDING) {
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, params.salt_len) <= 0)
            return make_openssl_error("EVP_PKEY_CTX_set_rsa_pss_saltlen");
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, params.md) <= 0)
            return make_openssl_error("EVP_PKEY_CTX_set_rsa_mgf1_md");
    }
    return {};
}

} // namespace

auto rsa_sign(signing_algorithm alg, EVP_PKEY* key,
              std::span<const uint8_t> data) -> expected<secure_bytes> {
    auto params = get_rsa_params(alg);
    if (!params) return jose::unexpected(params.error());

    auto size_ok = check_key_size(key);
    if (!size_ok) return jose::unexpected(size_ok.error());

    auto ctx = make_evp_md_ctx();
    if (!ctx) return make_openssl_error("EVP_MD_CTX_new");

    EVP_PKEY_CTX* pctx = nullptr; // owned by ctx
    if (EVP_DigestSignInit(ctx.get(), &pctx, params->md, nullptr, key) != 1)
        return make_openssl_error("EVP_DigestSignInit");

    auto cfg = configure_pkey_ctx(pctx, *params);
    if (!cfg) return jose::unexpected(cfg.error());

    if (EVP_DigestSignUpdate(ctx.get(), data.data(), data.size()) != 1)
        return make_openssl_error("EVP_DigestSignUpdate");

    size_t sig_len = 0;
    if (EVP_DigestSignFinal(ctx.get(), nullptr, &sig_len) != 1)
        return make_openssl_error("EVP_DigestSignFinal (length query)");

    secure_bytes sig(sig_len);
    if (EVP_DigestSignFinal(ctx.get(), sig.data(), &sig_len) != 1)
        return make_openssl_error("EVP_DigestSignFinal");

    sig.resize(sig_len);
    return sig;
}

auto rsa_verify(signing_algorithm alg, EVP_PKEY* key,
                std::span<const uint8_t> data,
                std::span<const uint8_t> signature) -> expected<void> {
    auto params = get_rsa_params(alg);
    if (!params) return jose::unexpected(params.error());

    auto size_ok = check_key_size(key);
    if (!size_ok) return jose::unexpected(size_ok.error());

    auto ctx = make_evp_md_ctx();
    if (!ctx) return make_openssl_error("EVP_MD_CTX_new");

    EVP_PKEY_CTX* pctx = nullptr; // owned by ctx
    if (EVP_DigestVerifyInit(ctx.get(), &pctx, params->md, nullptr, key) != 1)
        return make_openssl_error("EVP_DigestVerifyInit");

    auto cfg = configure_pkey_ctx(pctx, *params);
    if (!cfg) return jose::unexpected(cfg.error());

    if (EVP_DigestVerifyUpdate(ctx.get(), data.data(), data.size()) != 1)
        return make_openssl_error("EVP_DigestVerifyUpdate");

    if (EVP_DigestVerifyFinal(ctx.get(), signature.data(), signature.size()) != 1)
        return make_crypto_failure(errc::invalid_signature, "RSA signature verification failed");

    return {};
}

// ---------------------------------------------------------------------------
// Key encryption
// ---------------------------------------------------------------------------

namespace {

struct rsa_kek_params {
    int padding;
    const EVP_MD* oaep_md; // nullptr for PKCS#1 v1.5
};

auto get_kek_params(key_algorithm alg, legacy_options legacy)
    -> expected<rsa_kek_params> {
    switch (alg) {
    case key_algorithm::RSA1_5:
        if (!legacy.allow_rsa1_5)
            return make_error(errc::legacy_algorithm_disabled,
                              "RSA1_5 is disabled (padding-oracle risk); "
                              "set legacy_options::allow_rsa1_5 to opt in");
        return rsa_kek_params{RSA_PKCS1_PADDING, nullptr};
    case key_algorithm::RSA_OAEP:
        return rsa_kek_params{RSA_PKCS1_OAEP_PADDING, EVP_sha1()};
    case key_algorithm::RSA_OAEP_256:
        return rsa_kek_params{RSA_PKCS1_OAEP_PADDING, EVP_sha256()};
    default:
        return make_error(errc::unsupported_algorithm,
                          "not an RSA key encryption algorithm");
    }
}

auto check_kek_key(EVP_PKEY* key) -> expected<void> {
    if (key == nullptr || EVP_PKEY_base_id(key) != EVP_PKEY_RSA)
        return make_error(errc::invalid_key,
                          "RSA key encryption requires an RSA key");
    return check_key_size(key);
}

auto configure_kek_ctx(EVP_PKEY_CTX* ctx, const rsa_kek_params& params)
    -> expected<void> {
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, params.padding) <= 0)
        return make_openssl_error("EVP_PKEY_CTX_set_rsa_padding");
    if (params.oaep_md != nullptr) {
        if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, params.oaep_md) <= 0)
            return make_openssl_error("EVP_PKEY_CTX_set_rsa_oaep_md");
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, params.oaep_md) <= 0)
            return make_openssl_error("EVP_PKEY_CTX_set_rsa_mgf1_md");
    }
    return {};
}

// 0xFF if a == b, 0x00 otherwise, without data-dependent branches.
auto ct_eq_mask(size_t a, size_t b) -> uint8_t {
    const size_t x = a ^ b;
    // Top bit of (x | -x) is set iff x != 0.
    const size_t nonzero = (x | (0 - x)) >> (sizeof(size_t) * CHAR_BIT - 1);
    return static_cast<uint8_t>(nonzero - 1);
}

} // namespace

auto rsa_encrypt_key(key_algorithm alg, EVP_PKEY* public_key,
                     std::span<const uint8_t> cek, legacy_options legacy)
    -> expected<secure_bytes> {
    auto params = get_kek_params(alg, legacy);
    if (!params) return jose::unexpected(params.error());

    auto key_ok = check_kek_key(public_key);
    if (!key_ok) return jose::unexpected(key_ok.error());

    if (cek.empty())
        return make_error(errc::invalid_key, "CEK must not be empty");

    auto ctx = make_evp_pkey_ctx(EVP_PKEY_CTX_new(public_key, nullptr));
    if (!ctx) return make_openssl_error("EVP_PKEY_CTX_new");

    if (EVP_PKEY_encrypt_init(ctx.get()) <= 0)
        return make_openssl_error("EVP_PKEY_encrypt_init");

    auto cfg = configure_kek_ctx(ctx.get(), *params);
    if (!cfg) return jose::unexpected(cfg.error());

    size_t out_len = 0;
    if (EVP_PKEY_encrypt(ctx.get(), nullptr, &out_len, cek.data(), cek.size()) <= 0)
        return make_openssl_error("EVP_PKEY_encrypt (length query)");

    secure_bytes out(out_len);
    if (EVP_PKEY_encrypt(ctx.get(), out.data(), &out_len, cek.data(), cek.size()) <= 0)
        return make_openssl_error("EVP_PKEY_encrypt");

    out.resize(out_len);
    return out;
}

auto rsa_decrypt_key(key_algorithm alg, EVP_PKEY* private_key,
                     std::span<const uint8_t> encrypted_key, size_t cek_len,
                     legacy_options legacy) -> expected<secure_bytes> {
    auto params = get_kek_params(alg, legacy);
    if (!params) return jose::unexpected(params.error());

    auto key_ok = check_kek_key(private_key);
    if (!key_ok) return jose::unexpected(key_ok.error());

    // Everything checked up to here (algorithm, key, requested length) is
    // public, so failing loudly leaks nothing about the ciphertext.
    const auto modulus_len = static_cast<size_t>(EVP_PKEY_get_size(private_key));
    if (cek_len == 0 || cek_len > modulus_len)
        return make_error(errc::invalid_argument, "invalid expected CEK length");

    auto ctx = make_evp_pkey_ctx(EVP_PKEY_CTX_new(private_key, nullptr));
    if (!ctx) return make_openssl_error("EVP_PKEY_CTX_new");

    if (EVP_PKEY_decrypt_init(ctx.get()) <= 0)
        return make_openssl_error("EVP_PKEY_decrypt_init");

    auto cfg = configure_kek_ctx(ctx.get(), *params);
    if (!cfg) return jose::unexpected(cfg.error());

    if (params->padding == RSA_PKCS1_PADDING) {
        // Bleichenbacher countermeasure: draw the substitute CEK before
        // touching the ciphertext, then select between it and the real
        // result without branching on whether decryption succeeded.
        auto fallback = random_bytes(cek_len);
        if (!fallback) return jose::unexpected(fallback.error());

        secure_bytes buf(modulus_len);
        size_t out_len = buf.size();
        const int rc = EVP_PKEY_decrypt(ctx.get(), buf.data(), &out_len,
                                        encrypted_key.data(),
                                        encrypted_key.size());
        // Never leave a padding error on the queue for a caller to observe.
        ERR_clear_error();

        const uint8_t good = static_cast<uint8_t>(
            ct_eq_mask(static_cast<size_t>(rc), 1) & ct_eq_mask(out_len, cek_len));

        secure_bytes cek(cek_len);
        for (size_t i = 0; i < cek_len; ++i)
            cek[i] = static_cast<uint8_t>((buf[i] & good) |
                                          ((*fallback)[i] & static_cast<uint8_t>(~good)));
        return cek;
    }

    size_t out_len = 0;
    if (EVP_PKEY_decrypt(ctx.get(), nullptr, &out_len, encrypted_key.data(),
                         encrypted_key.size()) <= 0) {
        return make_crypto_failure(errc::decryption_failed, "RSA key decryption failed");
    }

    secure_bytes cek(out_len);
    if (EVP_PKEY_decrypt(ctx.get(), cek.data(), &out_len, encrypted_key.data(),
                         encrypted_key.size()) <= 0 ||
        out_len != cek_len) {
        return make_crypto_failure(errc::decryption_failed, "RSA key decryption failed");
    }

    cek.resize(out_len);
    return cek;
}

} // namespace jose
