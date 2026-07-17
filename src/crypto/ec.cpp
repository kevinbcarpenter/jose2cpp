#include "jose/crypto/ec.hpp"

#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>

#include <memory>
#include <string>
#include <string_view>

namespace jose {

namespace {

using bn_ptr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using ecdsa_sig_ptr = std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)>;

struct ec_alg_params {
    const EVP_MD* md;
    int component_size;      // bytes per R or S component
    const char* group_name;  // OpenSSL canonical curve name
    const char* jose_name;   // JOSE curve name (RFC 7518)
};

auto get_ec_params(signing_algorithm alg) -> expected<ec_alg_params> {
    switch (alg) {
    case signing_algorithm::ES256:
        return ec_alg_params{EVP_sha256(), 32, "prime256v1", "P-256"};
    case signing_algorithm::ES384:
        return ec_alg_params{EVP_sha384(), 48, "secp384r1", "P-384"};
    case signing_algorithm::ES512:
        return ec_alg_params{EVP_sha512(), 66, "secp521r1", "P-521"};
    default:
        return make_error(errc::unsupported_algorithm,
                          "not an ECDSA signing algorithm");
    }
}

// RFC 7518 §3.4: each ES* algorithm is bound to a specific curve. Reject
// mismatched keys instead of silently signing with the wrong pairing.
auto check_curve(EVP_PKEY* key, const ec_alg_params& p) -> expected<void> {
    char name[64] = {};
    size_t name_len = 0;
    if (!EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME,
                                        name, sizeof(name), &name_len))
        return make_error(errc::invalid_key, "key is not an EC key");

    auto group = std::string_view(name, name_len);
    if (group != p.group_name && group != p.jose_name)
        return make_error(errc::algorithm_mismatch,
                          std::string("key curve '") + std::string(group) +
                              "' does not match required curve " + p.jose_name);
    return {};
}

// Convert DER-encoded ECDSA signature to fixed-size R||S (RFC 7515 A.3)
auto der_to_fixed(std::span<const uint8_t> der_sig, int component_size)
    -> expected<secure_bytes> {
    const auto* p = der_sig.data();
    auto sig = ecdsa_sig_ptr(
        d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(der_sig.size())),
        ECDSA_SIG_free);
    if (!sig)
        return make_openssl_error("d2i_ECDSA_SIG");

    const BIGNUM* r = nullptr;
    const BIGNUM* s = nullptr;
    ECDSA_SIG_get0(sig.get(), &r, &s);

    secure_bytes out(2 * component_size, 0);
    if (BN_bn2binpad(r, out.data(), component_size) != component_size ||
        BN_bn2binpad(s, out.data() + component_size, component_size) != component_size)
        return make_openssl_error("BN_bn2binpad");

    return out;
}

// Convert fixed-size R||S to DER-encoded ECDSA signature
auto fixed_to_der(std::span<const uint8_t> fixed_sig, int component_size)
    -> expected<std::vector<uint8_t>> {
    if (static_cast<int>(fixed_sig.size()) != 2 * component_size)
        return make_error(errc::invalid_signature,
                          "ECDSA signature has wrong length");

    auto r = bn_ptr(BN_bin2bn(fixed_sig.data(), component_size, nullptr), BN_free);
    auto s = bn_ptr(BN_bin2bn(fixed_sig.data() + component_size, component_size,
                              nullptr), BN_free);
    if (!r || !s)
        return make_openssl_error("BN_bin2bn");

    auto sig = ecdsa_sig_ptr(ECDSA_SIG_new(), ECDSA_SIG_free);
    if (!sig)
        return make_openssl_error("ECDSA_SIG_new");

    // ECDSA_SIG_set0 takes ownership of r and s on success
    if (ECDSA_SIG_set0(sig.get(), r.get(), s.get()) != 1)
        return make_openssl_error("ECDSA_SIG_set0");
    r.release();
    s.release();

    int der_len = i2d_ECDSA_SIG(sig.get(), nullptr);
    if (der_len <= 0)
        return make_openssl_error("i2d_ECDSA_SIG (length)");

    std::vector<uint8_t> der(static_cast<size_t>(der_len));
    auto* out = der.data();
    if (i2d_ECDSA_SIG(sig.get(), &out) != der_len)
        return make_openssl_error("i2d_ECDSA_SIG");

    return der;
}

} // namespace

auto ec_sign(signing_algorithm alg, EVP_PKEY* key,
             std::span<const uint8_t> data) -> expected<secure_bytes> {
    auto params = get_ec_params(alg);
    if (!params) return jose::unexpected(params.error());

    auto curve_ok = check_curve(key, *params);
    if (!curve_ok) return jose::unexpected(curve_ok.error());

    auto ctx = make_evp_md_ctx();
    if (!ctx) return make_openssl_error("EVP_MD_CTX_new");

    if (EVP_DigestSignInit(ctx.get(), nullptr, params->md, nullptr, key) != 1)
        return make_openssl_error("EVP_DigestSignInit");

    if (EVP_DigestSignUpdate(ctx.get(), data.data(), data.size()) != 1)
        return make_openssl_error("EVP_DigestSignUpdate");

    size_t der_len = 0;
    if (EVP_DigestSignFinal(ctx.get(), nullptr, &der_len) != 1)
        return make_openssl_error("EVP_DigestSignFinal (length query)");

    secure_bytes der_sig(der_len);
    if (EVP_DigestSignFinal(ctx.get(), der_sig.data(), &der_len) != 1)
        return make_openssl_error("EVP_DigestSignFinal");

    der_sig.resize(der_len);

    // Convert DER to fixed-size R||S for JOSE
    return der_to_fixed(to_span(der_sig), params->component_size);
}

auto ec_verify(signing_algorithm alg, EVP_PKEY* key,
               std::span<const uint8_t> data,
               std::span<const uint8_t> signature) -> expected<void> {
    auto params = get_ec_params(alg);
    if (!params) return jose::unexpected(params.error());

    auto curve_ok = check_curve(key, *params);
    if (!curve_ok) return jose::unexpected(curve_ok.error());

    // Convert fixed-size R||S back to DER for OpenSSL
    auto der_sig = fixed_to_der(signature, params->component_size);
    if (!der_sig) return jose::unexpected(der_sig.error());

    auto ctx = make_evp_md_ctx();
    if (!ctx) return make_openssl_error("EVP_MD_CTX_new");

    if (EVP_DigestVerifyInit(ctx.get(), nullptr, params->md, nullptr, key) != 1)
        return make_openssl_error("EVP_DigestVerifyInit");

    if (EVP_DigestVerifyUpdate(ctx.get(), data.data(), data.size()) != 1)
        return make_openssl_error("EVP_DigestVerifyUpdate");

    if (EVP_DigestVerifyFinal(ctx.get(), der_sig->data(), der_sig->size()) != 1)
        return make_error(errc::invalid_signature, "ECDSA signature verification failed");

    return {};
}

} // namespace jose
