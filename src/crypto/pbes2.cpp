#include "jose/crypto/pbes2.hpp"
#include "jose/crypto/aes_kw.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>

namespace jose {

namespace {

struct pbes2_params {
    const EVP_MD* md;
    size_t derived_key_len;
    key_algorithm kw_alg;
    std::string_view alg_id;  // UTF8(alg) for salt prefix
};

auto get_pbes2_params(key_algorithm alg) -> expected<pbes2_params> {
    switch (alg) {
    case key_algorithm::PBES2_HS256_A128KW:
        return pbes2_params{EVP_sha256(), 16, key_algorithm::A128KW,
                            "PBES2-HS256+A128KW"};
    case key_algorithm::PBES2_HS384_A192KW:
        return pbes2_params{EVP_sha384(), 24, key_algorithm::A192KW,
                            "PBES2-HS384+A192KW"};
    case key_algorithm::PBES2_HS512_A256KW:
        return pbes2_params{EVP_sha512(), 32, key_algorithm::A256KW,
                            "PBES2-HS512+A256KW"};
    default:
        return make_error(errc::unsupported_algorithm,
                          "not a PBES2 algorithm");
    }
}

// Construct PBKDF2 salt: UTF8(alg) || 0x00 || p2s
auto build_salt(std::string_view alg_id, std::span<const uint8_t> p2s)
    -> secure_bytes {
    secure_bytes salt;
    salt.reserve(alg_id.size() + 1 + p2s.size());
    salt.insert(salt.end(),
                reinterpret_cast<const uint8_t*>(alg_id.data()),
                reinterpret_cast<const uint8_t*>(alg_id.data() + alg_id.size()));
    salt.push_back(0x00);
    salt.insert(salt.end(), p2s.begin(), p2s.end());
    return salt;
}

auto derive_key(const pbes2_params& params, std::string_view password,
                std::span<const uint8_t> p2s, int p2c)
    -> expected<secure_bytes> {
    auto salt = build_salt(params.alg_id, p2s);

    secure_bytes derived(params.derived_key_len);
    if (PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
                           salt.data(), static_cast<int>(salt.size()),
                           p2c, params.md,
                           static_cast<int>(derived.size()),
                           derived.data()) != 1)
        return make_openssl_error("PKCS5_PBKDF2_HMAC");

    return derived;
}

} // namespace

auto pbes2_key_wrap(key_algorithm alg, std::string_view password,
                    std::span<const uint8_t> cek,
                    int iteration_count) -> expected<pbes2_result> {
    auto params = get_pbes2_params(alg);
    if (!params) return jose::unexpected(params.error());

    // Generate random p2s (16 bytes)
    secure_bytes p2s(16);
    if (RAND_bytes(p2s.data(), static_cast<int>(p2s.size())) != 1)
        return make_openssl_error("RAND_bytes");

    auto derived = derive_key(*params, password, p2s, iteration_count);
    if (!derived) return jose::unexpected(derived.error());

    auto wrapped = aes_key_wrap(params->kw_alg, *derived, cek);
    if (!wrapped) return jose::unexpected(wrapped.error());

    return pbes2_result{
        .encrypted_key = std::move(*wrapped),
        .p2s = std::move(p2s),
        .p2c = iteration_count,
    };
}

auto pbes2_key_unwrap(key_algorithm alg, std::string_view password,
                      std::span<const uint8_t> encrypted_key,
                      std::span<const uint8_t> p2s,
                      int p2c) -> expected<secure_bytes> {
    auto params = get_pbes2_params(alg);
    if (!params) return jose::unexpected(params.error());

    auto derived = derive_key(*params, password, p2s, p2c);
    if (!derived) return jose::unexpected(derived.error());

    return aes_key_unwrap(params->kw_alg, *derived, encrypted_key);
}

} // namespace jose
