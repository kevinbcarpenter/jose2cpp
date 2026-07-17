#include "jose/crypto/signing.hpp"

#include "jose/crypto/ec.hpp"
#include "jose/crypto/eddsa.hpp"
#include "jose/crypto/hmac.hpp"
#include "jose/crypto/rsa.hpp"

#include <string>

namespace jose {

namespace {

enum class key_family { oct, rsa, ec, okp };

auto family_of(signing_algorithm alg) -> key_family {
    switch (alg) {
    case signing_algorithm::HS256:
    case signing_algorithm::HS384:
    case signing_algorithm::HS512:
        return key_family::oct;
    case signing_algorithm::RS256:
    case signing_algorithm::RS384:
    case signing_algorithm::RS512:
    case signing_algorithm::PS256:
    case signing_algorithm::PS384:
    case signing_algorithm::PS512:
        return key_family::rsa;
    case signing_algorithm::ES256:
    case signing_algorithm::ES384:
    case signing_algorithm::ES512:
        return key_family::ec;
    case signing_algorithm::EdDSA:
        return key_family::okp;
    }
    return key_family::oct; // unreachable
}

auto wrong_key_kind(signing_algorithm alg, bool got_symmetric) -> unexpected {
    return make_error(errc::algorithm_mismatch,
                      std::string(to_string(alg)) +
                          (got_symmetric
                               ? " requires an asymmetric (EVP_PKEY) key"
                               : " requires a symmetric (oct) key"));
}

} // namespace

auto sign(signing_algorithm alg, std::span<const uint8_t> key,
          std::span<const uint8_t> data) -> expected<secure_bytes> {
    if (family_of(alg) != key_family::oct) return wrong_key_kind(alg, true);
    return hmac_sign(alg, key, data);
}

auto verify(signing_algorithm alg, std::span<const uint8_t> key,
            std::span<const uint8_t> data,
            std::span<const uint8_t> signature) -> expected<void> {
    if (family_of(alg) != key_family::oct) return wrong_key_kind(alg, true);
    return hmac_verify(alg, key, data, signature);
}

auto sign(signing_algorithm alg, EVP_PKEY* key,
          std::span<const uint8_t> data) -> expected<secure_bytes> {
    switch (family_of(alg)) {
    case key_family::rsa: return rsa_sign(alg, key, data);
    case key_family::ec:  return ec_sign(alg, key, data);
    case key_family::okp: return eddsa_sign(key, data);
    case key_family::oct: break;
    }
    return wrong_key_kind(alg, false);
}

auto verify(signing_algorithm alg, EVP_PKEY* key,
            std::span<const uint8_t> data,
            std::span<const uint8_t> signature) -> expected<void> {
    switch (family_of(alg)) {
    case key_family::rsa: return rsa_verify(alg, key, data, signature);
    case key_family::ec:  return ec_verify(alg, key, data, signature);
    case key_family::okp: return eddsa_verify(key, data, signature);
    case key_family::oct: break;
    }
    return wrong_key_kind(alg, false);
}

} // namespace jose
