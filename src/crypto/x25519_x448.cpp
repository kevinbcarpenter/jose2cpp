#include "jose/crypto/x25519_x448.hpp"

#include <openssl/evp.h>

namespace jose {

namespace {

auto generate_okp_keypair(int nid) -> expected<evp_pkey_ptr> {
    auto ctx = make_evp_pkey_ctx(EVP_PKEY_CTX_new_id(nid, nullptr));
    if (!ctx) return make_openssl_error("EVP_PKEY_CTX_new_id");

    if (EVP_PKEY_keygen_init(ctx.get()) <= 0)
        return make_openssl_error("EVP_PKEY_keygen_init");

    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &raw) <= 0)
        return make_openssl_error("EVP_PKEY_keygen");

    return make_evp_pkey_ptr(raw);
}

} // namespace

auto generate_x25519_keypair() -> expected<evp_pkey_ptr> {
    return generate_okp_keypair(EVP_PKEY_X25519);
}

auto generate_x448_keypair() -> expected<evp_pkey_ptr> {
    return generate_okp_keypair(EVP_PKEY_X448);
}

} // namespace jose
