#pragma once

// JSON Web Key (RFC 7517), JWK Thumbprint (RFC 7638), and OKP keys
// (RFC 8037).
//
// A jwk always holds valid key material: every construction path (JSON,
// PEM, an EVP_PKEY, raw oct bytes, generation) validates the key, and there
// is no way to build a jwk around an invalid one. See PLAN.md §Key Validation.
//
//   auto key = jose::jwk::from_json(json_text);
//   if (!key) { /* key.error().code, key.error().message */ }
//   auto sig = jose::sign(signing_algorithm::ES256, key->pkey(), payload);
//
// jwk is a cheap-to-copy value type. The underlying EVP_PKEY is shared and
// never modified, so const operations are safe to use from multiple threads.

#include "jose/algorithm.hpp"
#include "jose/crypto/openssl_util.hpp"
#include "jose/error.hpp"
#include "jose/secure_bytes.hpp"

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace jose {

class jwk {
public:
    // --- Construction (all paths validate) ---

    // Parse a JWK. Unknown members are ignored (RFC 7517 §4).
    static auto from_json(std::string_view json) -> expected<jwk>;
    static auto from_json(const nlohmann::json& json) -> expected<jwk>;

    // Import a PEM public key, private key, or X.509 certificate. A
    // certificate yields a public jwk whose x5c holds that certificate.
    static auto from_pem(std::string_view pem) -> expected<jwk>;

    // Wrap an existing RSA, EC (P-256/384/521), or OKP key.
    static auto from_pkey(evp_pkey_ptr key) -> expected<jwk>;

    // A symmetric ("oct") key.
    static auto from_oct(std::span<const uint8_t> key) -> expected<jwk>;

    static auto generate_rsa(int bits = 2048) -> expected<jwk>;
    static auto generate_ec(ec_curve crv) -> expected<jwk>;
    static auto generate_okp(okp_curve crv) -> expected<jwk>;
    static auto generate_oct(size_t bytes) -> expected<jwk>;

    // --- Serialization ---

    // Serialize, including private members if this key has them (use
    // public_key() first to publish a key). Integers use minimal octets
    // (RSA) or full curve-size octets (EC), per RFC 7518 §6. Only fails if
    // OpenSSL cannot export the key's parameters.
    [[nodiscard]] auto to_json() const -> expected<nlohmann::json>;
    [[nodiscard]] auto to_json_string() const -> expected<std::string>;

    // The public half: same metadata, private members removed. Fails for
    // oct keys, which have no public part.
    [[nodiscard]] auto public_key() const -> expected<jwk>;

    // RFC 7638 thumbprint: hash of the required public members (RSA: e, kty,
    // n; EC: crv, kty, x, y; OKP: crv, kty, x; oct: k, kty) in lexicographic
    // order with no whitespace. A private key and its public half have the
    // same thumbprint.
    [[nodiscard]] auto thumbprint(hash_algorithm h = hash_algorithm::SHA256) const
        -> expected<std::vector<uint8_t>>;

    // --- Key material ---

    [[nodiscard]] auto key_type() const noexcept -> kty { return kty_; }
    [[nodiscard]] auto is_private() const noexcept -> bool { return private_; }
    [[nodiscard]] auto is_public() const noexcept -> bool { return !private_; }

    // The asymmetric key, or nullptr for oct keys. Owned by this jwk.
    [[nodiscard]] auto pkey() const noexcept -> EVP_PKEY* { return pkey_.get(); }

    // The symmetric key bytes; empty for asymmetric keys.
    [[nodiscard]] auto oct() const noexcept -> std::span<const uint8_t> { return to_span(oct_); }

    [[nodiscard]] auto ec_crv() const noexcept -> std::optional<ec_curve> { return ec_crv_; }
    [[nodiscard]] auto okp_crv() const noexcept -> std::optional<okp_curve> { return okp_crv_; }

    // --- Metadata (RFC 7517 §4) ---

    [[nodiscard]] auto key_id() const -> const std::optional<std::string>& { return kid_; }
    [[nodiscard]] auto algorithm() const -> const std::optional<std::string>& { return alg_; }
    [[nodiscard]] auto use() const -> const std::optional<std::string>& { return use_; }
    [[nodiscard]] auto key_ops() const -> const std::optional<std::vector<std::string>>& { return key_ops_; }
    [[nodiscard]] auto x5u() const -> const std::optional<std::string>& { return x5u_; }
    // DER-encoded certificates, leaf first.
    [[nodiscard]] auto x5c() const -> const std::vector<std::vector<uint8_t>>& { return x5c_; }
    [[nodiscard]] auto x5t() const -> const std::optional<std::vector<uint8_t>>& { return x5t_; }
    [[nodiscard]] auto x5t_s256() const -> const std::optional<std::vector<uint8_t>>& { return x5t_s256_; }

    // --- Usage checks (used by JWS / JWE before every operation) ---

    // Succeeds if this key can be used with the JOSE algorithm `alg`: right
    // key type, curve and size (e.g. ES256 needs P-256, HS256 >= 32 octets),
    // and the key's own "alg", if set, is exactly `alg`. Fails with
    // errc::algorithm_mismatch or errc::key_too_short.
    [[nodiscard]] auto check_algorithm(std::string_view alg) const -> expected<void>;

    // Succeeds if the key's "use" / "key_ops" permit `op` (an RFC 7517
    // §4.3 key_ops value: "sign", "verify", "encrypt", "wrapKey", ...).
    // Absent members permit everything. Fails with errc::invalid_key.
    [[nodiscard]] auto check_operation(std::string_view op) const -> expected<void>;

    // Setters validate the same rules as parsing (e.g. "alg" must be
    // compatible with the key, "use" and "key_ops" must agree).
    auto set_key_id(std::optional<std::string> kid) -> void { kid_ = std::move(kid); }
    auto set_algorithm(std::optional<std::string> alg) -> expected<void>;
    auto set_use(std::optional<std::string> use) -> expected<void>;
    auto set_key_ops(std::optional<std::vector<std::string>> ops) -> expected<void>;

private:
    jwk() = default;

    // Builds a jwk around an already-validated key; see jwk.cpp.
    static auto adopt(evp_pkey_ptr key) -> expected<jwk>;

    // Checks the metadata invariants ("alg", "use"/"key_ops", x5c/x5t);
    // called by every construction path and setter.
    auto validate_metadata() const -> expected<void>;
    auto check_alg(const std::string& alg) const -> expected<void>;
    auto key_members(bool include_private) const -> expected<nlohmann::json>;

    kty kty_ = kty::oct;
    bool private_ = false;
    std::shared_ptr<EVP_PKEY> pkey_;
    secure_bytes oct_;
    std::optional<ec_curve> ec_crv_;
    std::optional<okp_curve> okp_crv_;

    std::optional<std::string> kid_;
    std::optional<std::string> alg_;
    std::optional<std::string> use_;
    std::optional<std::vector<std::string>> key_ops_;
    std::optional<std::string> x5u_;
    std::vector<std::vector<uint8_t>> x5c_;
    std::optional<std::vector<uint8_t>> x5t_;
    std::optional<std::vector<uint8_t>> x5t_s256_;

    friend class jwk_set;
};

// JWK Set (RFC 7517 §5).
class jwk_set {
public:
    jwk_set() = default;
    explicit jwk_set(std::vector<jwk> keys) : keys_(std::move(keys)) {}

    // Parse {"keys": [...]}. Per RFC 7517 §5, member keys that are invalid
    // or use an unsupported "kty"/"crv" are skipped rather than failing the
    // whole set; each skipped key's error is kept in skipped(). A missing or
    // non-array "keys" member is an error.
    static auto from_json(std::string_view json) -> expected<jwk_set>;
    static auto from_json(const nlohmann::json& json) -> expected<jwk_set>;

    [[nodiscard]] auto to_json() const -> expected<nlohmann::json>;

    [[nodiscard]] auto keys() const noexcept -> std::span<const jwk> { return keys_; }
    [[nodiscard]] auto skipped() const noexcept -> std::span<const error> { return skipped_; }
    [[nodiscard]] auto size() const noexcept -> size_t { return keys_.size(); }
    [[nodiscard]] auto empty() const noexcept -> bool { return keys_.empty(); }

    // "kid" is not required to be unique; find() returns the first match,
    // find_all() every match.
    [[nodiscard]] auto find(std::string_view kid) const
        -> std::optional<std::reference_wrapper<const jwk>>;
    [[nodiscard]] auto find_all(std::string_view kid) const
        -> std::vector<std::reference_wrapper<const jwk>>;

    auto add(jwk key) -> void { keys_.push_back(std::move(key)); }

private:
    std::vector<jwk> keys_;
    std::vector<error> skipped_;
};

} // namespace jose
