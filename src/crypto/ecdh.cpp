#include "jose/crypto/ecdh.hpp"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/sha.h>

#include <array>
#include <cstring>

namespace jose {

namespace {

// Write a 32-bit big-endian integer into buf.
void write_be32(uint8_t* buf, uint32_t val) {
    buf[0] = static_cast<uint8_t>(val >> 24);
    buf[1] = static_cast<uint8_t>(val >> 16);
    buf[2] = static_cast<uint8_t>(val >> 8);
    buf[3] = static_cast<uint8_t>(val);
}

// Concat KDF (NIST SP 800-56A, single-pass SHA-256).
// otherinfo = len(alg) || alg || len(apu) || apu || len(apv) || apv || keydatalen
auto concat_kdf(std::span<const uint8_t> shared_secret,
                std::string_view algorithm,
                std::string_view apu,
                std::string_view apv,
                size_t key_length_bits) -> expected<secure_bytes> {
    const size_t key_length_bytes = key_length_bits / 8;
    const uint32_t reps =
        static_cast<uint32_t>((key_length_bytes + 31) / 32); // SHA-256 = 32 bytes

    // Build otherinfo
    std::vector<uint8_t> otherinfo;
    otherinfo.reserve(4 + algorithm.size() + 4 + apu.size() + 4 + apv.size() + 4);

    auto append_length_prefixed = [&](std::string_view data) {
        std::array<uint8_t, 4> len_buf{};
        write_be32(len_buf.data(), static_cast<uint32_t>(data.size()));
        otherinfo.insert(otherinfo.end(), len_buf.begin(), len_buf.end());
        otherinfo.insert(otherinfo.end(),
                         reinterpret_cast<const uint8_t*>(data.data()),
                         reinterpret_cast<const uint8_t*>(data.data()) + data.size());
    };

    append_length_prefixed(algorithm);
    append_length_prefixed(apu);
    append_length_prefixed(apv);

    // keydatalen in bits as 32-bit big-endian
    std::array<uint8_t, 4> kdl_buf{};
    write_be32(kdl_buf.data(), static_cast<uint32_t>(key_length_bits));
    otherinfo.insert(otherinfo.end(), kdl_buf.begin(), kdl_buf.end());

    // Derive: for each round, hash(round || Z || otherinfo)
    secure_bytes derived;
    derived.reserve(reps * 32);

    for (uint32_t round = 1; round <= reps; ++round) {
        auto ctx = make_evp_md_ctx();
        if (!ctx) return make_openssl_error("EVP_MD_CTX_new");

        if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1)
            return make_openssl_error("EVP_DigestInit_ex");

        std::array<uint8_t, 4> round_buf{};
        write_be32(round_buf.data(), round);

        if (EVP_DigestUpdate(ctx.get(), round_buf.data(), 4) != 1)
            return make_openssl_error("EVP_DigestUpdate round");
        if (EVP_DigestUpdate(ctx.get(), shared_secret.data(),
                             shared_secret.size()) != 1)
            return make_openssl_error("EVP_DigestUpdate Z");
        if (EVP_DigestUpdate(ctx.get(), otherinfo.data(),
                             otherinfo.size()) != 1)
            return make_openssl_error("EVP_DigestUpdate otherinfo");

        std::array<uint8_t, 32> hash{};
        unsigned int hash_len = 0;
        if (EVP_DigestFinal_ex(ctx.get(), hash.data(), &hash_len) != 1)
            return make_openssl_error("EVP_DigestFinal_ex");

        derived.insert(derived.end(), hash.begin(),
                       hash.begin() + hash_len);
    }

    derived.resize(key_length_bytes);
    return derived;
}

// Generate an ephemeral key pair matching the recipient's key type/curve.
auto generate_ephemeral_key(EVP_PKEY* peer) -> expected<evp_pkey_ptr> {
    int key_type = EVP_PKEY_base_id(peer);

    if (key_type == EVP_PKEY_X25519 || key_type == EVP_PKEY_X448) {
        auto ctx = make_evp_pkey_ctx(EVP_PKEY_CTX_new_id(key_type, nullptr));
        if (!ctx)
            return make_openssl_error("EVP_PKEY_CTX_new_id for keygen");
        if (EVP_PKEY_keygen_init(ctx.get()) != 1)
            return make_openssl_error("EVP_PKEY_keygen_init");
        EVP_PKEY* raw = nullptr;
        if (EVP_PKEY_keygen(ctx.get(), &raw) != 1)
            return make_openssl_error("EVP_PKEY_keygen");
        return make_evp_pkey_ptr(raw);
    }

    if (key_type == EVP_PKEY_EC) {
        // Extract the curve name from the recipient key
        char curve_name[64] = {};
        size_t name_len = 0;
        if (!EVP_PKEY_get_utf8_string_param(
                peer, OSSL_PKEY_PARAM_GROUP_NAME,
                curve_name, sizeof(curve_name), &name_len))
            return make_openssl_error("failed to get EC group name");

        auto ctx = make_evp_pkey_ctx(
            EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
        if (!ctx)
            return make_openssl_error("EVP_PKEY_CTX_new_from_name EC");
        if (EVP_PKEY_keygen_init(ctx.get()) != 1)
            return make_openssl_error("EVP_PKEY_keygen_init EC");

        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string(
                OSSL_PKEY_PARAM_GROUP_NAME, curve_name, 0),
            OSSL_PARAM_construct_end()};
        if (EVP_PKEY_CTX_set_params(ctx.get(), params) != 1)
            return make_openssl_error("EVP_PKEY_CTX_set_params");

        EVP_PKEY* raw = nullptr;
        if (EVP_PKEY_keygen(ctx.get(), &raw) != 1)
            return make_openssl_error("EVP_PKEY_keygen EC");
        return make_evp_pkey_ptr(raw);
    }

    return make_error(errc::invalid_key,
                      "unsupported key type for ECDH");
}

// Compute the raw ECDH shared secret between a private key and a peer public key.
auto compute_shared_secret(EVP_PKEY* privkey,
                           EVP_PKEY* peerkey) -> expected<secure_bytes> {
    auto ctx = make_evp_pkey_ctx(EVP_PKEY_CTX_new(privkey, nullptr));
    if (!ctx)
        return make_openssl_error("EVP_PKEY_CTX_new for derive");
    if (EVP_PKEY_derive_init(ctx.get()) != 1)
        return make_openssl_error("EVP_PKEY_derive_init");
    if (EVP_PKEY_derive_set_peer(ctx.get(), peerkey) != 1)
        return make_openssl_error("EVP_PKEY_derive_set_peer");

    // Determine shared secret length
    size_t secret_len = 0;
    if (EVP_PKEY_derive(ctx.get(), nullptr, &secret_len) != 1)
        return make_openssl_error("EVP_PKEY_derive length");

    secure_bytes secret(secret_len);
    if (EVP_PKEY_derive(ctx.get(), secret.data(), &secret_len) != 1)
        return make_openssl_error("EVP_PKEY_derive");

    secret.resize(secret_len);
    return secret;
}

} // namespace

auto ecdh_derive_key(
    EVP_PKEY* recipient_public_key,
    std::string_view algorithm,
    std::string_view apu,
    std::string_view apv,
    size_t key_length_bits) -> expected<ecdh_result> {

    auto ephemeral = generate_ephemeral_key(recipient_public_key);
    if (!ephemeral) return jose::unexpected(ephemeral.error());

    auto secret = compute_shared_secret(ephemeral->get(), recipient_public_key);
    if (!secret) return jose::unexpected(secret.error());

    auto derived = concat_kdf(*secret, algorithm, apu, apv, key_length_bits);
    if (!derived) return jose::unexpected(derived.error());

    return ecdh_result{std::move(*derived), std::move(*ephemeral)};
}

auto ecdh_derive_key_from_epk(
    EVP_PKEY* recipient_private_key,
    EVP_PKEY* ephemeral_public_key,
    std::string_view algorithm,
    std::string_view apu,
    std::string_view apv,
    size_t key_length_bits) -> expected<secure_bytes> {

    auto secret =
        compute_shared_secret(recipient_private_key, ephemeral_public_key);
    if (!secret) return jose::unexpected(secret.error());

    return concat_kdf(*secret, algorithm, apu, apv, key_length_bits);
}

} // namespace jose
