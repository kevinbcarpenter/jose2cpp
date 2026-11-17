#include "jose/jwk.hpp"

#include "jose/base64url.hpp"
#include "jose/crypto/keygen.hpp"

#include "internal/codec.hpp"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <set>

namespace jose {

namespace {

using json = nlohmann::json;
using bn_ptr = std::unique_ptr<BIGNUM, decltype(&BN_clear_free)>;
using bn_ctx_ptr = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;
using param_bld_ptr = std::unique_ptr<OSSL_PARAM_BLD, decltype(&OSSL_PARAM_BLD_free)>;
using params_ptr = std::unique_ptr<OSSL_PARAM, decltype(&OSSL_PARAM_free)>;
using x509_ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using bio_ptr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using decoder_ctx_ptr = std::unique_ptr<OSSL_DECODER_CTX, decltype(&OSSL_DECODER_CTX_free)>;

auto invalid(std::string message) -> unexpected {
    return make_error(errc::invalid_key, std::move(message));
}

// ---------------------------------------------------------------------------
// Curve tables
// ---------------------------------------------------------------------------

struct ec_info {
    ec_curve crv;
    std::string_view jose_name;
    const char* group; // OpenSSL group name
    size_t size;       // coordinate / scalar size in octets (RFC 7518 §6.2.1)
};

constexpr std::array<ec_info, 3> k_ec_curves{{
    {ec_curve::P256, "P-256", "prime256v1", 32},
    {ec_curve::P384, "P-384", "secp384r1", 48},
    {ec_curve::P521, "P-521", "secp521r1", 66},
}};

auto ec_by_curve(ec_curve crv) -> const ec_info& {
    for (const auto& e : k_ec_curves)
        if (e.crv == crv) return e;
    return k_ec_curves[0]; // unreachable: every ec_curve is listed
}

auto ec_by_group(std::string_view group) -> const ec_info* {
    for (const auto& e : k_ec_curves)
        if (group == e.group || group == e.jose_name) return &e;
    // OpenSSL may report the NIST name for P-256.
    if (group == "P-256" || group == "secp256r1") return &k_ec_curves[0];
    return nullptr;
}

struct okp_info {
    okp_curve crv;
    int pkey_id;
    size_t key_size; // public and private key size in octets (RFC 8032/7748)
};

constexpr std::array<okp_info, 4> k_okp_curves{{
    {okp_curve::Ed25519, EVP_PKEY_ED25519, 32},
    {okp_curve::Ed448, EVP_PKEY_ED448, 57},
    {okp_curve::X25519, EVP_PKEY_X25519, 32},
    {okp_curve::X448, EVP_PKEY_X448, 56},
}};

auto okp_by_curve(okp_curve crv) -> const okp_info& {
    for (const auto& o : k_okp_curves)
        if (o.crv == crv) return o;
    return k_okp_curves[0];
}

auto okp_by_id(int id) -> const okp_info* {
    for (const auto& o : k_okp_curves)
        if (o.pkey_id == id) return &o;
    return nullptr;
}

// ---------------------------------------------------------------------------
// JSON member helpers
// ---------------------------------------------------------------------------

auto opt_string(const json& j, const std::string& name)
    -> expected<std::optional<std::string>> {
    auto it = j.find(name);
    if (it == j.end()) return std::optional<std::string>{};
    if (!it->is_string()) return invalid("JWK member \"" + name + "\" must be a string");
    return std::optional<std::string>{it->get<std::string>()};
}

auto opt_b64(const json& j, const std::string& name) -> expected<std::optional<secure_bytes>> {
    auto s = opt_string(j, name);
    if (!s) return jose::unexpected(s.error());
    if (!*s) return std::optional<secure_bytes>{};
    auto bytes = base64url::decode(**s);
    if (!bytes)
        return make_error(errc::invalid_base64,
                          "JWK member \"" + name + "\": " + bytes.error().message);
    return std::optional<secure_bytes>{std::move(*bytes)};
}

auto req_b64(const json& j, const std::string& name) -> expected<secure_bytes> {
    auto v = opt_b64(j, name);
    if (!v) return jose::unexpected(v.error());
    if (!*v) return invalid("JWK is missing required member \"" + name + "\"");
    return std::move(**v);
}

using internal::b64std_decode;
using internal::b64std_encode;
using internal::digest;

// ---------------------------------------------------------------------------
// Key import from JWK members
// ---------------------------------------------------------------------------

auto to_bn(std::span<const uint8_t> bytes) -> expected<bn_ptr> {
    bn_ptr bn{BN_bin2bn(bytes.data(), static_cast<int>(bytes.size()), nullptr), BN_clear_free};
    if (!bn) return make_openssl_error("BN_bin2bn");
    return bn;
}

auto from_params(const char* type, OSSL_PARAM_BLD* bld, bool priv) -> expected<evp_pkey_ptr> {
    params_ptr params{OSSL_PARAM_BLD_to_param(bld), OSSL_PARAM_free};
    if (!params) return make_openssl_error("OSSL_PARAM_BLD_to_param");

    auto ctx = make_evp_pkey_ctx(EVP_PKEY_CTX_new_from_name(nullptr, type, nullptr));
    if (!ctx) return make_openssl_error("EVP_PKEY_CTX_new_from_name");
    if (EVP_PKEY_fromdata_init(ctx.get()) != 1)
        return make_openssl_error("EVP_PKEY_fromdata_init");

    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_fromdata(ctx.get(), &raw, priv ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY,
                          params.get()) != 1)
        return make_crypto_failure(errc::invalid_key, "JWK key parameters were rejected");
    return make_evp_pkey_ptr(raw);
}

auto rsa_from_json(const json& j) -> expected<evp_pkey_ptr> {
    if (j.contains("oth"))
        return make_error(errc::unsupported_algorithm,
                          "multi-prime RSA keys (\"oth\") are not supported");

    param_bld_ptr bld{OSSL_PARAM_BLD_new(), OSSL_PARAM_BLD_free};
    if (!bld) return make_openssl_error("OSSL_PARAM_BLD_new");
    std::vector<bn_ptr> keep; // must outlive OSSL_PARAM_BLD_to_param

    auto push = [&](const char* param, std::span<const uint8_t> bytes) -> expected<void> {
        auto bn = to_bn(bytes);
        if (!bn) return jose::unexpected(bn.error());
        if (OSSL_PARAM_BLD_push_BN(bld.get(), param, bn->get()) != 1)
            return make_openssl_error("OSSL_PARAM_BLD_push_BN");
        keep.push_back(std::move(*bn));
        return {};
    };
    auto push_bn = [&](const char* param, bn_ptr bn) -> expected<void> {
        if (OSSL_PARAM_BLD_push_BN(bld.get(), param, bn.get()) != 1)
            return make_openssl_error("OSSL_PARAM_BLD_push_BN");
        keep.push_back(std::move(bn));
        return {};
    };

    auto n = req_b64(j, "n");
    if (!n) return jose::unexpected(n.error());
    auto e = req_b64(j, "e");
    if (!e) return jose::unexpected(e.error());
    if (auto r = push(OSSL_PKEY_PARAM_RSA_N, *n); !r) return jose::unexpected(r.error());
    if (auto r = push(OSSL_PKEY_PARAM_RSA_E, *e); !r) return jose::unexpected(r.error());

    auto d = opt_b64(j, "d");
    if (!d) return jose::unexpected(d.error());
    const bool priv = d->has_value();
    if (priv) {
        // Like go-jose, require the prime factors; the CRT values are
        // computed when absent.
        auto p = req_b64(j, "p");
        if (!p) return jose::unexpected(p.error());
        auto q = req_b64(j, "q");
        if (!q) return jose::unexpected(q.error());
        auto dp = opt_b64(j, "dp");
        if (!dp) return jose::unexpected(dp.error());
        auto dq = opt_b64(j, "dq");
        if (!dq) return jose::unexpected(dq.error());
        auto qi = opt_b64(j, "qi");
        if (!qi) return jose::unexpected(qi.error());

        if (auto r = push(OSSL_PKEY_PARAM_RSA_D, **d); !r) return jose::unexpected(r.error());
        if (auto r = push(OSSL_PKEY_PARAM_RSA_FACTOR1, *p); !r) return jose::unexpected(r.error());
        if (auto r = push(OSSL_PKEY_PARAM_RSA_FACTOR2, *q); !r) return jose::unexpected(r.error());

        if (*dp && *dq && *qi) {
            if (auto r = push(OSSL_PKEY_PARAM_RSA_EXPONENT1, **dp); !r) return jose::unexpected(r.error());
            if (auto r = push(OSSL_PKEY_PARAM_RSA_EXPONENT2, **dq); !r) return jose::unexpected(r.error());
            if (auto r = push(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, **qi); !r) return jose::unexpected(r.error());
        } else {
            bn_ctx_ptr ctx{BN_CTX_secure_new(), BN_CTX_free};
            auto bd = to_bn(**d);
            auto bp = to_bn(*p);
            auto bq = to_bn(*q);
            if (!ctx || !bd || !bp || !bq) return make_openssl_error("BN setup");
            bn_ptr pm1{BN_dup(bp->get()), BN_clear_free};
            bn_ptr qm1{BN_dup(bq->get()), BN_clear_free};
            bn_ptr bdp{BN_secure_new(), BN_clear_free};
            bn_ptr bdq{BN_secure_new(), BN_clear_free};
            if (!pm1 || !qm1 || !bdp || !bdq ||
                BN_sub_word(pm1.get(), 1) != 1 || BN_sub_word(qm1.get(), 1) != 1 ||
                BN_mod(bdp.get(), bd->get(), pm1.get(), ctx.get()) != 1 ||
                BN_mod(bdq.get(), bd->get(), qm1.get(), ctx.get()) != 1)
                return make_crypto_failure(errc::invalid_key, "invalid RSA private key");
            bn_ptr bqi{BN_mod_inverse(nullptr, bq->get(), bp->get(), ctx.get()), BN_clear_free};
            if (!bqi) return make_crypto_failure(errc::invalid_key, "invalid RSA private key");
            if (auto r = push_bn(OSSL_PKEY_PARAM_RSA_EXPONENT1, std::move(bdp)); !r) return jose::unexpected(r.error());
            if (auto r = push_bn(OSSL_PKEY_PARAM_RSA_EXPONENT2, std::move(bdq)); !r) return jose::unexpected(r.error());
            if (auto r = push_bn(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, std::move(bqi)); !r) return jose::unexpected(r.error());
        }
    }
    return from_params("RSA", bld.get(), priv);
}

auto ec_from_json(const json& j) -> expected<evp_pkey_ptr> {
    auto crv_name = opt_string(j, "crv");
    if (!crv_name) return jose::unexpected(crv_name.error());
    if (!*crv_name) return invalid("EC JWK is missing \"crv\"");
    auto crv = parse_ec_curve(**crv_name);
    if (!crv) return make_error(errc::unsupported_algorithm, "unsupported EC curve: " + **crv_name);
    const auto& info = ec_by_curve(*crv);

    auto x = req_b64(j, "x");
    if (!x) return jose::unexpected(x.error());
    auto y = req_b64(j, "y");
    if (!y) return jose::unexpected(y.error());
    // RFC 7518 §6.2.1.2/3: coordinates MUST be the full curve size.
    if (x->size() != info.size || y->size() != info.size)
        return make_error(errc::invalid_curve_point,
                          "EC coordinates must be " + std::to_string(info.size) +
                              " octets for " + std::string(info.jose_name));

    std::vector<uint8_t> point{0x04}; // uncompressed: 0x04 || X || Y
    point.insert(point.end(), x->begin(), x->end());
    point.insert(point.end(), y->begin(), y->end());

    param_bld_ptr bld{OSSL_PARAM_BLD_new(), OSSL_PARAM_BLD_free};
    if (!bld) return make_openssl_error("OSSL_PARAM_BLD_new");
    if (OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_GROUP_NAME, info.group, 0) != 1 ||
        OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY, point.data(),
                                         point.size()) != 1)
        return make_openssl_error("OSSL_PARAM_BLD_push");

    auto d = opt_b64(j, "d");
    if (!d) return jose::unexpected(d.error());
    bn_ptr bd{nullptr, BN_clear_free};
    if (*d) {
        // RFC 7518 §6.2.2.1: "d" MUST be the full curve size.
        if ((*d)->size() != info.size)
            return invalid("EC private key \"d\" must be " + std::to_string(info.size) + " octets");
        auto bn = to_bn(**d);
        if (!bn) return jose::unexpected(bn.error());
        bd = std::move(*bn);
        if (OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_PRIV_KEY, bd.get()) != 1)
            return make_openssl_error("OSSL_PARAM_BLD_push_BN");
    }
    return from_params("EC", bld.get(), d->has_value());
}

auto okp_from_json(const json& j) -> expected<evp_pkey_ptr> {
    auto crv_name = opt_string(j, "crv");
    if (!crv_name) return jose::unexpected(crv_name.error());
    if (!*crv_name) return invalid("OKP JWK is missing \"crv\"");
    auto crv = parse_okp_curve(**crv_name);
    if (!crv) return make_error(errc::unsupported_algorithm, "unsupported OKP curve: " + **crv_name);
    const auto& info = okp_by_curve(*crv);

    auto x = req_b64(j, "x");
    if (!x) return jose::unexpected(x.error());
    if (x->size() != info.key_size)
        return invalid("OKP \"x\" must be " + std::to_string(info.key_size) + " octets for " + **crv_name);

    auto d = opt_b64(j, "d");
    if (!d) return jose::unexpected(d.error());
    if (!*d) {
        auto key = make_evp_pkey_ptr(
            EVP_PKEY_new_raw_public_key(info.pkey_id, nullptr, x->data(), x->size()));
        if (!key) return make_crypto_failure(errc::invalid_key, "invalid OKP public key");
        return key;
    }

    if ((*d)->size() != info.key_size)
        return invalid("OKP \"d\" must be " + std::to_string(info.key_size) + " octets for " + **crv_name);
    auto key = make_evp_pkey_ptr(
        EVP_PKEY_new_raw_private_key(info.pkey_id, nullptr, (*d)->data(), (*d)->size()));
    if (!key) return make_crypto_failure(errc::invalid_key, "invalid OKP private key");

    // "x" must be the public key that "d" actually derives.
    secure_bytes derived(info.key_size);
    size_t len = derived.size();
    if (EVP_PKEY_get_raw_public_key(key.get(), derived.data(), &len) != 1)
        return make_openssl_error("EVP_PKEY_get_raw_public_key");
    if (len != x->size() || CRYPTO_memcmp(derived.data(), x->data(), len) != 0)
        return invalid("OKP \"x\" does not match the public key derived from \"d\"");
    return key;
}

// ---------------------------------------------------------------------------
// Validation of an EVP_PKEY (shared by every construction path)
// ---------------------------------------------------------------------------

struct key_facts {
    kty type;
    bool priv;
    std::optional<ec_curve> ec;
    std::optional<okp_curve> okp;
};

auto has_bn_param(EVP_PKEY* key, const char* name) -> bool {
    BIGNUM* bn = nullptr;
    const bool ok = EVP_PKEY_get_bn_param(key, name, &bn) == 1;
    BN_clear_free(bn);
    ERR_clear_error(); // absence is reported via the queue; it isn't an error here
    return ok;
}

auto run_check(EVP_PKEY* key, bool priv) -> expected<void> {
    auto ctx = make_evp_pkey_ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr));
    if (!ctx) return make_openssl_error("EVP_PKEY_CTX_new_from_pkey");
    const int rc = priv ? EVP_PKEY_check(ctx.get()) : EVP_PKEY_public_check(ctx.get());
    if (rc != 1)
        return make_crypto_failure(errc::invalid_key, priv ? "private key failed validation"
                                                           : "public key failed validation");
    return {};
}

// PLAN.md §Key Validation: RSA >= 2048 bits and internally consistent; EC
// points on the declared curve (and d matching); OKP sizes per curve.
auto inspect_and_validate(EVP_PKEY* key) -> expected<key_facts> {
    if (key == nullptr) return invalid("null key");

    const int id = EVP_PKEY_get_base_id(key);
    if (id == EVP_PKEY_RSA) {
        const int bits = EVP_PKEY_get_bits(key);
        if (bits < 2048)
            return make_error(errc::key_size_too_small,
                              "RSA keys must be at least 2048 bits (got " + std::to_string(bits) + ")");
        const bool priv = has_bn_param(key, OSSL_PKEY_PARAM_RSA_D);
        if (auto r = run_check(key, priv); !r) return jose::unexpected(r.error());
        return key_facts{kty::RSA, priv, std::nullopt, std::nullopt};
    }

    if (id == EVP_PKEY_EC) {
        char group[64] = {};
        size_t len = 0;
        if (EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof(group),
                                           &len) != 1)
            return make_crypto_failure(errc::invalid_key, "EC key has no named curve");
        const auto* info = ec_by_group(std::string_view(group, len));
        if (info == nullptr)
            return make_error(errc::unsupported_algorithm,
                              "unsupported EC curve: " + std::string(group, len));
        const bool priv = has_bn_param(key, OSSL_PKEY_PARAM_PRIV_KEY);
        if (auto r = run_check(key, priv); !r) return jose::unexpected(r.error());
        return key_facts{kty::EC, priv, info->crv, std::nullopt};
    }

    if (const auto* info = okp_by_id(id)) {
        size_t len = 0;
        const bool priv = EVP_PKEY_get_raw_private_key(key, nullptr, &len) == 1;
        ERR_clear_error();
        if (auto r = run_check(key, priv); !r) return jose::unexpected(r.error());
        return key_facts{kty::OKP, priv, std::nullopt, info->crv};
    }

    return make_error(errc::unsupported_algorithm,
                      "unsupported key type (only RSA, EC P-256/384/521, Ed25519, Ed448, "
                      "X25519 and X448 are supported)");
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

auto get_bn(EVP_PKEY* key, const char* name) -> expected<bn_ptr> {
    BIGNUM* bn = nullptr;
    if (EVP_PKEY_get_bn_param(key, name, &bn) != 1)
        return make_openssl_error(std::string("EVP_PKEY_get_bn_param ") + name);
    return bn_ptr{bn, BN_clear_free};
}

// Base64url of a big-endian integer: minimal octets, or left-padded to
// `size` octets when size != 0.
auto bn_b64(const BIGNUM* bn, size_t size = 0) -> std::string {
    const size_t len = size != 0 ? size : static_cast<size_t>(BN_num_bytes(bn));
    secure_bytes buf(std::max<size_t>(len, 1));
    BN_bn2binpad(bn, buf.data(), static_cast<int>(buf.size()));
    return base64url::encode(buf);
}

auto add_bn(json& out, EVP_PKEY* key, const char* member, const char* param, size_t size = 0)
    -> expected<void> {
    auto bn = get_bn(key, param);
    if (!bn) return jose::unexpected(bn.error());
    out[member] = bn_b64(bn->get(), size);
    return {};
}

// --- "alg" compatibility ---

auto hmac_min_bytes(signing_algorithm alg) -> size_t {
    switch (alg) {
    case signing_algorithm::HS256: return 32;
    case signing_algorithm::HS384: return 48;
    case signing_algorithm::HS512: return 64;
    default: return 0;
    }
}

auto kw_key_bytes(key_algorithm alg) -> size_t {
    switch (alg) {
    case key_algorithm::A128KW:
    case key_algorithm::A128GCMKW: return 16;
    case key_algorithm::A192KW:
    case key_algorithm::A192GCMKW: return 24;
    case key_algorithm::A256KW:
    case key_algorithm::A256GCMKW: return 32;
    default: return 0;
    }
}

auto mismatch(const std::string& alg) -> unexpected {
    return make_error(errc::algorithm_mismatch,
                      "JWK \"alg\" " + alg + " is not compatible with this key");
}

} // namespace

// ===========================================================================
// jwk
// ===========================================================================

auto jwk::adopt(evp_pkey_ptr key) -> expected<jwk> {
    auto facts = inspect_and_validate(key.get());
    if (!facts) return jose::unexpected(facts.error());
    jwk out;
    out.kty_ = facts->type;
    out.private_ = facts->priv;
    out.ec_crv_ = facts->ec;
    out.okp_crv_ = facts->okp;
    out.pkey_ = std::shared_ptr<EVP_PKEY>(key.release(), EVP_PKEY_free);
    return out;
}

auto jwk::from_pkey(evp_pkey_ptr key) -> expected<jwk> {
    return adopt(std::move(key));
}

auto jwk::from_oct(std::span<const uint8_t> key) -> expected<jwk> {
    if (key.empty()) return invalid("oct key must not be empty");
    jwk out;
    out.kty_ = kty::oct;
    out.private_ = true;
    out.oct_.assign(key.begin(), key.end());
    return out;
}

auto jwk::generate_rsa(int bits) -> expected<jwk> {
    auto key = generate_rsa_key(bits);
    if (!key) return jose::unexpected(key.error());
    return adopt(std::move(*key));
}

auto jwk::generate_ec(ec_curve crv) -> expected<jwk> {
    auto key = generate_ec_key(crv);
    if (!key) return jose::unexpected(key.error());
    return adopt(std::move(*key));
}

auto jwk::generate_okp(okp_curve crv) -> expected<jwk> {
    auto key = generate_okp_key(crv);
    if (!key) return jose::unexpected(key.error());
    return adopt(std::move(*key));
}

auto jwk::generate_oct(size_t bytes) -> expected<jwk> {
    auto key = random_bytes(bytes);
    if (!key) return jose::unexpected(key.error());
    return from_oct(*key);
}

auto jwk::from_json(std::string_view text) -> expected<jwk> {
    auto j = internal::parse_json_strict(text, "JWK");
    if (!j) return jose::unexpected(j.error());
    return from_json(*j);
}

auto jwk::from_json(const json& j) -> expected<jwk> {
    if (!j.is_object()) return invalid("JWK must be a JSON object");

    auto kty_name = opt_string(j, "kty");
    if (!kty_name) return jose::unexpected(kty_name.error());
    if (!*kty_name) return invalid("JWK is missing \"kty\"");
    auto type = parse_kty(**kty_name);
    if (!type) return make_error(errc::unsupported_algorithm, "unsupported kty: " + **kty_name);

    expected<jwk> key = make_error(errc::invalid_key, "unreachable");
    switch (*type) {
    case kty::oct: {
        auto k = req_b64(j, "k");
        if (!k) return jose::unexpected(k.error());
        key = from_oct(*k);
        break;
    }
    case kty::RSA: {
        auto pk = rsa_from_json(j);
        if (!pk) return jose::unexpected(pk.error());
        key = adopt(std::move(*pk));
        break;
    }
    case kty::EC: {
        auto pk = ec_from_json(j);
        if (!pk) return jose::unexpected(pk.error());
        key = adopt(std::move(*pk));
        break;
    }
    case kty::OKP: {
        auto pk = okp_from_json(j);
        if (!pk) return jose::unexpected(pk.error());
        key = adopt(std::move(*pk));
        break;
    }
    }
    if (!key) return key;

    // --- metadata ---
    auto read = [&](const char* name, std::optional<std::string>& field) -> expected<void> {
        auto v = opt_string(j, name);
        if (!v) return jose::unexpected(v.error());
        field = std::move(*v);
        return {};
    };
    if (auto r = read("kid", key->kid_); !r) return jose::unexpected(r.error());
    if (auto r = read("alg", key->alg_); !r) return jose::unexpected(r.error());
    if (auto r = read("use", key->use_); !r) return jose::unexpected(r.error());
    if (auto r = read("x5u", key->x5u_); !r) return jose::unexpected(r.error());

    if (auto it = j.find("key_ops"); it != j.end()) {
        if (!it->is_array()) return invalid("JWK \"key_ops\" must be an array of strings");
        std::vector<std::string> ops;
        for (const auto& op : *it) {
            if (!op.is_string()) return invalid("JWK \"key_ops\" must be an array of strings");
            ops.push_back(op.get<std::string>());
        }
        key->key_ops_ = std::move(ops);
    }

    if (auto it = j.find("x5c"); it != j.end()) {
        if (!it->is_array() || it->empty())
            return invalid("JWK \"x5c\" must be a non-empty array of strings");
        for (const auto& cert : *it) {
            if (!cert.is_string()) return invalid("JWK \"x5c\" must be a non-empty array of strings");
            auto der = b64std_decode(cert.get<std::string>());
            if (!der) return jose::unexpected(der.error());
            key->x5c_.push_back(std::move(*der));
        }
    }

    auto read_thumb = [&](const char* name, std::optional<std::vector<uint8_t>>& field) -> expected<void> {
        auto v = opt_b64(j, name);
        if (!v) return jose::unexpected(v.error());
        if (*v) field = std::vector<uint8_t>((*v)->begin(), (*v)->end());
        return {};
    };
    if (auto r = read_thumb("x5t", key->x5t_); !r) return jose::unexpected(r.error());
    if (auto r = read_thumb("x5t#S256", key->x5t_s256_); !r) return jose::unexpected(r.error());

    if (auto r = key->validate_metadata(); !r) return jose::unexpected(r.error());
    return key;
}

auto jwk::from_pem(std::string_view pem) -> expected<jwk> {
    bio_ptr bio{BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free};
    if (!bio) return make_openssl_error("BIO_new_mem_buf");

    if (pem.find("-----BEGIN CERTIFICATE-----") != std::string_view::npos) {
        // One or more certificates, leaf first: the key comes from the leaf
        // and the whole chain becomes x5c.
        std::vector<std::vector<uint8_t>> chain;
        evp_pkey_ptr leaf_key = make_evp_pkey_ptr();
        while (true) {
            x509_ptr cert{PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr), X509_free};
            if (!cert) break;
            unsigned char* der = nullptr;
            const int len = i2d_X509(cert.get(), &der);
            if (len <= 0) return make_openssl_error("i2d_X509");
            chain.emplace_back(der, der + len);
            OPENSSL_free(der);
            if (!leaf_key) {
                leaf_key = make_evp_pkey_ptr(X509_get_pubkey(cert.get()));
                if (!leaf_key) return make_crypto_failure(errc::invalid_key, "certificate has no usable public key");
            }
        }
        ERR_clear_error(); // end-of-input is reported via the queue
        if (chain.empty()) return invalid("no certificate found in PEM input");
        auto key = adopt(std::move(leaf_key));
        if (!key) return key;
        key->x5c_ = std::move(chain);
        if (auto r = key->validate_metadata(); !r) return jose::unexpected(r.error());
        return key;
    }

    // Any private or public key encoding OpenSSL understands (PKCS#8,
    // SubjectPublicKeyInfo, PKCS#1, SEC1). Encrypted keys are not supported:
    // no passphrase callback is installed, so they fail instead of prompting.
    EVP_PKEY* raw = nullptr;
    decoder_ctx_ptr dctx{OSSL_DECODER_CTX_new_for_pkey(&raw, "PEM", nullptr, nullptr, 0, nullptr,
                                                       nullptr),
                         OSSL_DECODER_CTX_free};
    if (!dctx) return make_openssl_error("OSSL_DECODER_CTX_new_for_pkey");
    if (OSSL_DECODER_from_bio(dctx.get(), bio.get()) != 1 || raw == nullptr)
        return make_crypto_failure(errc::invalid_key,
                                   "PEM input is not a supported (unencrypted) key or certificate");
    return adopt(make_evp_pkey_ptr(raw));
}

// --- serialization ---

auto jwk::key_members(bool include_private) const -> expected<json> {
    json out = json::object();
    out["kty"] = std::string(to_string(kty_));
    EVP_PKEY* key = pkey_.get();

    switch (kty_) {
    case kty::oct:
        // Required for RFC 7638 thumbprints even when "public".
        out["k"] = base64url::encode(oct_);
        break;

    case kty::RSA: {
        if (auto r = add_bn(out, key, "n", OSSL_PKEY_PARAM_RSA_N); !r) return jose::unexpected(r.error());
        if (auto r = add_bn(out, key, "e", OSSL_PKEY_PARAM_RSA_E); !r) return jose::unexpected(r.error());
        if (include_private && private_) {
            const std::array<std::pair<const char*, const char*>, 6> members{{
                {"d", OSSL_PKEY_PARAM_RSA_D},
                {"p", OSSL_PKEY_PARAM_RSA_FACTOR1},
                {"q", OSSL_PKEY_PARAM_RSA_FACTOR2},
                {"dp", OSSL_PKEY_PARAM_RSA_EXPONENT1},
                {"dq", OSSL_PKEY_PARAM_RSA_EXPONENT2},
                {"qi", OSSL_PKEY_PARAM_RSA_COEFFICIENT1},
            }};
            for (const auto& [member, param] : members)
                if (auto r = add_bn(out, key, member, param); !r) return jose::unexpected(r.error());
        }
        break;
    }

    case kty::EC: {
        const auto& info = ec_by_curve(*ec_crv_);
        out["crv"] = std::string(info.jose_name);
        if (auto r = add_bn(out, key, "x", OSSL_PKEY_PARAM_EC_PUB_X, info.size); !r) return jose::unexpected(r.error());
        if (auto r = add_bn(out, key, "y", OSSL_PKEY_PARAM_EC_PUB_Y, info.size); !r) return jose::unexpected(r.error());
        if (include_private && private_)
            if (auto r = add_bn(out, key, "d", OSSL_PKEY_PARAM_PRIV_KEY, info.size); !r)
                return jose::unexpected(r.error());
        break;
    }

    case kty::OKP: {
        const auto& info = okp_by_curve(*okp_crv_);
        out["crv"] = std::string(to_string(*okp_crv_));
        secure_bytes buf(info.key_size);
        size_t len = buf.size();
        if (EVP_PKEY_get_raw_public_key(key, buf.data(), &len) != 1)
            return make_openssl_error("EVP_PKEY_get_raw_public_key");
        buf.resize(len);
        out["x"] = base64url::encode(buf);
        if (include_private && private_) {
            buf.assign(info.key_size, 0);
            len = buf.size();
            if (EVP_PKEY_get_raw_private_key(key, buf.data(), &len) != 1)
                return make_openssl_error("EVP_PKEY_get_raw_private_key");
            buf.resize(len);
            out["d"] = base64url::encode(buf);
        }
        break;
    }
    }
    return out;
}

auto jwk::to_json() const -> expected<json> {
    auto out = key_members(/*include_private=*/true);
    if (!out) return out;
    if (kid_) (*out)["kid"] = *kid_;
    if (alg_) (*out)["alg"] = *alg_;
    if (use_) (*out)["use"] = *use_;
    if (key_ops_) (*out)["key_ops"] = *key_ops_;
    if (x5u_) (*out)["x5u"] = *x5u_;
    if (!x5c_.empty()) {
        json chain = json::array();
        for (const auto& der : x5c_) chain.push_back(b64std_encode(der));
        (*out)["x5c"] = std::move(chain);
    }
    if (x5t_) (*out)["x5t"] = base64url::encode(*x5t_);
    if (x5t_s256_) (*out)["x5t#S256"] = base64url::encode(*x5t_s256_);
    return out;
}

auto jwk::to_json_string() const -> expected<std::string> {
    auto j = to_json();
    if (!j) return jose::unexpected(j.error());
    return j->dump();
}

auto jwk::public_key() const -> expected<jwk> {
    if (kty_ == kty::oct)
        return invalid("symmetric (oct) keys have no public part");

    // Round-trip through SubjectPublicKeyInfo to drop private material.
    unsigned char* der = nullptr;
    const int len = i2d_PUBKEY(pkey_.get(), &der);
    if (len <= 0) return make_openssl_error("i2d_PUBKEY");
    const unsigned char* p = der;
    auto pub = make_evp_pkey_ptr(d2i_PUBKEY(nullptr, &p, len));
    OPENSSL_free(der);
    if (!pub) return make_openssl_error("d2i_PUBKEY");

    jwk out = *this;
    out.private_ = false;
    out.pkey_ = std::shared_ptr<EVP_PKEY>(pub.release(), EVP_PKEY_free);
    return out;
}

auto jwk::thumbprint(hash_algorithm h) const -> expected<std::vector<uint8_t>> {
    // key_members(false) yields exactly the RFC 7638 required members, and
    // nlohmann::json objects serialize with sorted keys and no whitespace.
    auto members = key_members(/*include_private=*/false);
    if (!members) return jose::unexpected(members.error());
    const std::string canonical = members->dump();

    const EVP_MD* md = h == hash_algorithm::SHA256   ? EVP_sha256()
                       : h == hash_algorithm::SHA384 ? EVP_sha384()
                                                     : EVP_sha512();
    return digest(md, std::span<const uint8_t>(
                          reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size()));
}

// --- metadata validation ---

auto jwk::check_alg(const std::string& alg) const -> expected<void> {
    if (auto s = parse_signing_algorithm(alg)) {
        switch (*s) {
        case signing_algorithm::HS256:
        case signing_algorithm::HS384:
        case signing_algorithm::HS512:
            if (kty_ != kty::oct) return mismatch(alg);
            if (oct_.size() < hmac_min_bytes(*s))
                return make_error(errc::key_too_short,
                                  alg + " requires a key of at least " +
                                      std::to_string(hmac_min_bytes(*s)) + " octets");
            return {};
        case signing_algorithm::RS256: case signing_algorithm::RS384: case signing_algorithm::RS512:
        case signing_algorithm::PS256: case signing_algorithm::PS384: case signing_algorithm::PS512:
            return kty_ == kty::RSA ? expected<void>{} : mismatch(alg);
        case signing_algorithm::ES256:
            return ec_crv_ == ec_curve::P256 ? expected<void>{} : mismatch(alg);
        case signing_algorithm::ES384:
            return ec_crv_ == ec_curve::P384 ? expected<void>{} : mismatch(alg);
        case signing_algorithm::ES512:
            return ec_crv_ == ec_curve::P521 ? expected<void>{} : mismatch(alg);
        case signing_algorithm::EdDSA:
            return (okp_crv_ == okp_curve::Ed25519 || okp_crv_ == okp_curve::Ed448)
                       ? expected<void>{} : mismatch(alg);
        }
    }

    if (auto k = parse_key_algorithm(alg)) {
        switch (*k) {
        case key_algorithm::RSA1_5:
        case key_algorithm::RSA_OAEP:
        case key_algorithm::RSA_OAEP_256:
            return kty_ == kty::RSA ? expected<void>{} : mismatch(alg);
        case key_algorithm::ECDH_ES:
        case key_algorithm::ECDH_ES_A128KW:
        case key_algorithm::ECDH_ES_A192KW:
        case key_algorithm::ECDH_ES_A256KW:
            return (kty_ == kty::EC || okp_crv_ == okp_curve::X25519 || okp_crv_ == okp_curve::X448)
                       ? expected<void>{} : mismatch(alg);
        case key_algorithm::A128KW: case key_algorithm::A192KW: case key_algorithm::A256KW:
        case key_algorithm::A128GCMKW: case key_algorithm::A192GCMKW: case key_algorithm::A256GCMKW:
            if (kty_ != kty::oct) return mismatch(alg);
            if (oct_.size() != kw_key_bytes(*k))
                return invalid(alg + " requires a " + std::to_string(kw_key_bytes(*k)) + "-octet key");
            return {};
        case key_algorithm::dir:
        case key_algorithm::PBES2_HS256_A128KW:
        case key_algorithm::PBES2_HS384_A192KW:
        case key_algorithm::PBES2_HS512_A256KW:
            return kty_ == kty::oct ? expected<void>{} : mismatch(alg);
        }
    }

    if (auto e = parse_content_encryption(alg)) {
        // A key labelled with an "enc" value is a direct-encryption CEK.
        if (kty_ != kty::oct) return mismatch(alg);
        if (oct_.size() != cek_byte_size(*e))
            return invalid(alg + " requires a " + std::to_string(cek_byte_size(*e)) + "-octet key");
        return {};
    }

    // Unregistered "alg" values are permitted (RFC 7517 §4.4).
    return {};
}

auto jwk::validate_metadata() const -> expected<void> {
    if (alg_)
        if (auto r = check_alg(*alg_); !r) return r;

    if (key_ops_) {
        std::set<std::string> seen;
        for (const auto& op : *key_ops_)
            if (!seen.insert(op).second)
                return invalid("JWK \"key_ops\" contains duplicate value \"" + op + "\"");

        // RFC 7517 §4.3: if both are present they MUST be consistent.
        if (use_ == "sig" || use_ == "enc") {
            static const std::set<std::string> sig_ops{"sign", "verify"};
            static const std::set<std::string> enc_ops{"encrypt", "decrypt", "wrapKey",
                                                       "unwrapKey", "deriveKey", "deriveBits"};
            const auto& allowed = *use_ == "sig" ? sig_ops : enc_ops;
            for (const auto& op : *key_ops_)
                if (allowed.count(op) == 0)
                    return invalid("JWK \"key_ops\" value \"" + op + "\" is inconsistent with \"use\":\"" +
                                   *use_ + "\"");
        }
    }

    if (x5t_ && x5t_->size() != 20) return invalid("JWK \"x5t\" must be a 20-octet SHA-1 digest");
    if (x5t_s256_ && x5t_s256_->size() != 32)
        return invalid("JWK \"x5t#S256\" must be a 32-octet SHA-256 digest");

    if (!x5c_.empty()) {
        if (kty_ == kty::oct) return invalid("JWK \"x5c\" is not valid for oct keys");

        const auto& leaf = x5c_.front();
        for (const auto& der : x5c_) {
            const unsigned char* p = der.data();
            x509_ptr cert{d2i_X509(nullptr, &p, static_cast<long>(der.size())), X509_free};
            if (!cert || p != der.data() + der.size())
                return make_crypto_failure(errc::invalid_key, "JWK \"x5c\" contains an invalid certificate");
            // RFC 7517 §4.7: the leaf's key MUST match the JWK's key.
            if (&der == &leaf && EVP_PKEY_eq(X509_get0_pubkey(cert.get()), pkey_.get()) != 1)
                return make_crypto_failure(errc::invalid_key,
                                           "JWK \"x5c\" leaf certificate does not match the key");
        }

        if (x5t_) {
            auto sha1 = digest(EVP_sha1(), leaf);
            if (!sha1) return jose::unexpected(sha1.error());
            if (*sha1 != *x5t_) return invalid("JWK \"x5t\" does not match the \"x5c\" leaf certificate");
        }
        if (x5t_s256_) {
            auto sha256 = digest(EVP_sha256(), leaf);
            if (!sha256) return jose::unexpected(sha256.error());
            if (*sha256 != *x5t_s256_)
                return invalid("JWK \"x5t#S256\" does not match the \"x5c\" leaf certificate");
        }
    }
    return {};
}

// --- setters ---

namespace {

template <typename T>
auto set_checked(jwk& key, T& field, T value, expected<void> (jwk::*check)() const) -> expected<void> {
    T old = std::move(field);
    field = std::move(value);
    if (auto r = (key.*check)(); !r) {
        field = std::move(old);
        return r;
    }
    return {};
}

} // namespace

auto jwk::set_algorithm(std::optional<std::string> alg) -> expected<void> {
    return set_checked(*this, alg_, std::move(alg), &jwk::validate_metadata);
}

auto jwk::set_use(std::optional<std::string> use) -> expected<void> {
    return set_checked(*this, use_, std::move(use), &jwk::validate_metadata);
}

auto jwk::set_key_ops(std::optional<std::vector<std::string>> ops) -> expected<void> {
    return set_checked(*this, key_ops_, std::move(ops), &jwk::validate_metadata);
}

// ===========================================================================
// jwk_set
// ===========================================================================

auto jwk_set::from_json(std::string_view text) -> expected<jwk_set> {
    auto j = internal::parse_json_strict(text, "JWK Set");
    if (!j) return jose::unexpected(j.error());
    return from_json(*j);
}

auto jwk_set::from_json(const json& j) -> expected<jwk_set> {
    if (!j.is_object()) return invalid("JWK Set must be a JSON object");
    auto it = j.find("keys");
    if (it == j.end() || !it->is_array()) return invalid("JWK Set must have a \"keys\" array");

    jwk_set out;
    for (const auto& member : *it) {
        auto key = jwk::from_json(member);
        if (key)
            out.keys_.push_back(std::move(*key));
        else
            out.skipped_.push_back(key.error());
    }
    return out;
}

auto jwk_set::to_json() const -> expected<json> {
    json keys = json::array();
    for (const auto& key : keys_) {
        auto j = key.to_json();
        if (!j) return jose::unexpected(j.error());
        keys.push_back(std::move(*j));
    }
    return json{{"keys", std::move(keys)}};
}

auto jwk_set::find(std::string_view kid) const -> std::optional<std::reference_wrapper<const jwk>> {
    for (const auto& key : keys_)
        if (key.key_id() && *key.key_id() == kid) return std::cref(key);
    return std::nullopt;
}

auto jwk_set::find_all(std::string_view kid) const -> std::vector<std::reference_wrapper<const jwk>> {
    std::vector<std::reference_wrapper<const jwk>> out;
    for (const auto& key : keys_)
        if (key.key_id() && *key.key_id() == kid) out.push_back(std::cref(key));
    return out;
}

} // namespace jose
