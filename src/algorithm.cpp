#include "jose/algorithm.hpp"

#include <array>
#include <utility>

namespace jose {

namespace {

template <typename E, std::size_t N>
auto lookup(const std::array<std::pair<std::string_view, E>, N>& table,
            std::string_view s) -> expected<E> {
    for (const auto& [name, val] : table) {
        if (name == s) return val;
    }
    return make_error(errc::unsupported_algorithm,
        std::string("unknown algorithm: ") + std::string(s));
}

template <typename E, std::size_t N>
auto reverse_lookup(const std::array<std::pair<std::string_view, E>, N>& table,
                    E val) -> std::string_view {
    for (const auto& [name, v] : table) {
        if (v == val) return name;
    }
    return "unknown";
}

constexpr auto k_signing_algorithms = std::array<std::pair<std::string_view, signing_algorithm>, 13>{{
    {"HS256", signing_algorithm::HS256},
    {"HS384", signing_algorithm::HS384},
    {"HS512", signing_algorithm::HS512},
    {"RS256", signing_algorithm::RS256},
    {"RS384", signing_algorithm::RS384},
    {"RS512", signing_algorithm::RS512},
    {"ES256", signing_algorithm::ES256},
    {"ES384", signing_algorithm::ES384},
    {"ES512", signing_algorithm::ES512},
    {"PS256", signing_algorithm::PS256},
    {"PS384", signing_algorithm::PS384},
    {"PS512", signing_algorithm::PS512},
    {"EdDSA", signing_algorithm::EdDSA},
}};

constexpr auto k_key_algorithms = std::array<std::pair<std::string_view, key_algorithm>, 17>{{
    {"RSA1_5",              key_algorithm::RSA1_5},
    {"RSA-OAEP",            key_algorithm::RSA_OAEP},
    {"RSA-OAEP-256",        key_algorithm::RSA_OAEP_256},
    {"A128KW",              key_algorithm::A128KW},
    {"A192KW",              key_algorithm::A192KW},
    {"A256KW",              key_algorithm::A256KW},
    {"dir",                 key_algorithm::dir},
    {"ECDH-ES",             key_algorithm::ECDH_ES},
    {"ECDH-ES+A128KW",     key_algorithm::ECDH_ES_A128KW},
    {"ECDH-ES+A192KW",     key_algorithm::ECDH_ES_A192KW},
    {"ECDH-ES+A256KW",     key_algorithm::ECDH_ES_A256KW},
    {"A128GCMKW",           key_algorithm::A128GCMKW},
    {"A192GCMKW",           key_algorithm::A192GCMKW},
    {"A256GCMKW",           key_algorithm::A256GCMKW},
    {"PBES2-HS256+A128KW",  key_algorithm::PBES2_HS256_A128KW},
    {"PBES2-HS384+A192KW",  key_algorithm::PBES2_HS384_A192KW},
    {"PBES2-HS512+A256KW",  key_algorithm::PBES2_HS512_A256KW},
}};

constexpr auto k_content_encryptions = std::array<std::pair<std::string_view, content_encryption>, 6>{{
    {"A128CBC-HS256", content_encryption::A128CBC_HS256},
    {"A192CBC-HS384", content_encryption::A192CBC_HS384},
    {"A256CBC-HS512", content_encryption::A256CBC_HS512},
    {"A128GCM",       content_encryption::A128GCM},
    {"A192GCM",       content_encryption::A192GCM},
    {"A256GCM",       content_encryption::A256GCM},
}};

constexpr auto k_ec_curves = std::array<std::pair<std::string_view, ec_curve>, 3>{{
    {"P-256", ec_curve::P256},
    {"P-384", ec_curve::P384},
    {"P-521", ec_curve::P521},
}};

constexpr auto k_okp_curves = std::array<std::pair<std::string_view, okp_curve>, 4>{{
    {"Ed25519", okp_curve::Ed25519},
    {"Ed448",   okp_curve::Ed448},
    {"X25519",  okp_curve::X25519},
    {"X448",    okp_curve::X448},
}};

constexpr auto k_key_types = std::array<std::pair<std::string_view, kty>, 4>{{
    {"RSA", kty::RSA},
    {"EC",  kty::EC},
    {"oct", kty::oct},
    {"OKP", kty::OKP},
}};

} // namespace

// --- signing_algorithm ---

auto to_string(signing_algorithm alg) -> std::string_view {
    return reverse_lookup(k_signing_algorithms, alg);
}

auto parse_signing_algorithm(std::string_view s) -> expected<signing_algorithm> {
    return lookup(k_signing_algorithms, s);
}

// --- key_algorithm ---

auto to_string(key_algorithm alg) -> std::string_view {
    return reverse_lookup(k_key_algorithms, alg);
}

auto parse_key_algorithm(std::string_view s) -> expected<key_algorithm> {
    return lookup(k_key_algorithms, s);
}

auto is_legacy_algorithm(key_algorithm alg) -> bool {
    return alg == key_algorithm::RSA1_5;
}

// --- content_encryption ---

auto to_string(content_encryption alg) -> std::string_view {
    return reverse_lookup(k_content_encryptions, alg);
}

auto parse_content_encryption(std::string_view s) -> expected<content_encryption> {
    return lookup(k_content_encryptions, s);
}

auto cek_byte_size(content_encryption enc) -> size_t {
    switch (enc) {
        case content_encryption::A128CBC_HS256: return 32;  // 2 * 16
        case content_encryption::A192CBC_HS384: return 48;  // 2 * 24
        case content_encryption::A256CBC_HS512: return 64;  // 2 * 32
        case content_encryption::A128GCM:       return 16;
        case content_encryption::A192GCM:       return 24;
        case content_encryption::A256GCM:       return 32;
    }
    return 0;
}

auto iv_byte_size(content_encryption enc) -> size_t {
    switch (enc) {
        case content_encryption::A128CBC_HS256:
        case content_encryption::A192CBC_HS384:
        case content_encryption::A256CBC_HS512:
            return 16; // AES-CBC IV
        case content_encryption::A128GCM:
        case content_encryption::A192GCM:
        case content_encryption::A256GCM:
            return 12; // AES-GCM IV
    }
    return 0;
}

auto tag_byte_size(content_encryption enc) -> size_t {
    switch (enc) {
        case content_encryption::A128CBC_HS256: return 16;
        case content_encryption::A192CBC_HS384: return 24;
        case content_encryption::A256CBC_HS512: return 32;
        case content_encryption::A128GCM:
        case content_encryption::A192GCM:
        case content_encryption::A256GCM:
            return 16; // GCM tag
    }
    return 0;
}

// --- ec_curve ---

auto to_string(ec_curve crv) -> std::string_view {
    return reverse_lookup(k_ec_curves, crv);
}

auto parse_ec_curve(std::string_view s) -> expected<ec_curve> {
    return lookup(k_ec_curves, s);
}

// --- okp_curve ---

auto to_string(okp_curve crv) -> std::string_view {
    return reverse_lookup(k_okp_curves, crv);
}

auto parse_okp_curve(std::string_view s) -> expected<okp_curve> {
    return lookup(k_okp_curves, s);
}

// --- kty ---

auto to_string(kty k) -> std::string_view {
    return reverse_lookup(k_key_types, k);
}

auto parse_kty(std::string_view s) -> expected<kty> {
    return lookup(k_key_types, s);
}

} // namespace jose
