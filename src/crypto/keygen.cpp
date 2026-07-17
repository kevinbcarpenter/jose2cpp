#include "jose/crypto/keygen.hpp"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#include <string>

namespace jose {

namespace {

auto keygen_by_id(int id) -> expected<evp_pkey_ptr> {
    auto ctx = make_evp_pkey_ctx(EVP_PKEY_CTX_new_id(id, nullptr));
    if (!ctx) return make_openssl_error("EVP_PKEY_CTX_new_id");

    if (EVP_PKEY_keygen_init(ctx.get()) <= 0)
        return make_openssl_error("EVP_PKEY_keygen_init");

    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &raw) <= 0)
        return make_openssl_error("EVP_PKEY_keygen");

    return make_evp_pkey_ptr(raw);
}

} // namespace

auto generate_rsa_key(int bits) -> expected<evp_pkey_ptr> {
    if (bits < 2048)
        return make_error(errc::key_size_too_small,
                          "RSA keys must be at least 2048 bits (got " +
                              std::to_string(bits) + ")");

    auto ctx = make_evp_pkey_ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
    if (!ctx) return make_openssl_error("EVP_PKEY_CTX_new_id RSA");

    if (EVP_PKEY_keygen_init(ctx.get()) <= 0)
        return make_openssl_error("EVP_PKEY_keygen_init");

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits) <= 0)
        return make_openssl_error("EVP_PKEY_CTX_set_rsa_keygen_bits");

    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &raw) <= 0)
        return make_openssl_error("EVP_PKEY_keygen RSA");

    return make_evp_pkey_ptr(raw);
}

auto generate_ec_key(ec_curve crv) -> expected<evp_pkey_ptr> {
    auto ctx = make_evp_pkey_ctx(
        EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    if (!ctx) return make_openssl_error("EVP_PKEY_CTX_new_from_name EC");

    if (EVP_PKEY_keygen_init(ctx.get()) <= 0)
        return make_openssl_error("EVP_PKEY_keygen_init EC");

    // OpenSSL 3 accepts the JOSE curve names ("P-256", ...) as group aliases.
    const auto group = std::string(to_string(crv));
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(
            OSSL_PKEY_PARAM_GROUP_NAME, const_cast<char*>(group.c_str()), 0),
        OSSL_PARAM_construct_end()};
    if (EVP_PKEY_CTX_set_params(ctx.get(), params) != 1)
        return make_openssl_error("EVP_PKEY_CTX_set_params");

    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &raw) <= 0)
        return make_openssl_error("EVP_PKEY_keygen EC");

    return make_evp_pkey_ptr(raw);
}

auto generate_okp_key(okp_curve crv) -> expected<evp_pkey_ptr> {
    switch (crv) {
    case okp_curve::Ed25519: return keygen_by_id(EVP_PKEY_ED25519);
    case okp_curve::Ed448:   return keygen_by_id(EVP_PKEY_ED448);
    case okp_curve::X25519:  return keygen_by_id(EVP_PKEY_X25519);
    case okp_curve::X448:    return keygen_by_id(EVP_PKEY_X448);
    }
    return make_error(errc::invalid_key, "unknown OKP curve");
}

auto random_bytes(size_t len) -> expected<secure_bytes> {
    secure_bytes out(len);
    if (len > 0 && RAND_bytes(out.data(), static_cast<int>(len)) != 1)
        return make_openssl_error("RAND_bytes");
    return out;
}

} // namespace jose
