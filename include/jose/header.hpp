#pragma once

// JOSE Header (RFC 7515 §4, RFC 7516 §4, RFC 7518 §4, RFC 7797 §3).
//
// A jose::header is one JSON object of header parameters: a JWS/JWE
// Protected Header, a shared Unprotected Header, or a per-signature /
// per-recipient Unprotected Header. Every registered parameter present is
// type-checked when the header is built, so the typed accessors below never
// fail. Unregistered (extension) parameters are kept verbatim and can be
// read with get().
//
// join_headers() combines the parts that apply to one signature or
// recipient and enforces the rules that span them: names must be disjoint,
// "crit" / "b64" / "zip" must be integrity protected, and every critical
// extension must be understood (see PLAN.md §Critical Header Extensions).
//
//   auto prot = jose::header::from_base64url(encoded_protected);
//   auto joined = jose::join_headers(jose::header_context::jws, *prot);
//   if (!joined) { /* joined.error().code == errc::unrecognized_critical_extension, ... */ }

#include "jose/error.hpp"
#include "jose/jwk.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace jose {

// Where a header is being used. Determines which parameters are required
// and which extensions the library itself understands.
enum class header_context {
    jws,
    jwe,
};

// Names of application-defined extension parameters the caller understands
// and will process. Used as the "crit" allowlist.
using extension_set = std::set<std::string, std::less<>>;

// True for every Header Parameter name defined by RFC 7515, 7516 or 7518
// ("alg", "enc", "epk", "p2c", ...). These may never be listed in "crit"
// (RFC 7515 §4.1.11). "b64" (RFC 7797) is not one of them: it is an
// extension, and must be listed in "crit" whenever it is used.
auto is_registered_header_parameter(std::string_view name) -> bool;

class header {
public:
    header() = default;

    // Parse a header JSON object. Duplicate member names are rejected
    // (RFC 7515 §4). Registered parameters are type-checked:
    //   strings:     alg enc zip kid typ cty jku x5u
    //   base64url:   x5t (20 octets) x5t#S256 (32 octets) apu apv iv tag p2s
    //   JWK objects: jwk epk (public keys only)
    //   other:       x5c (non-empty array of base64 DER certificates; x5t and
    //                x5t#S256 must match the first), crit (non-empty array of
    //                unique strings naming unregistered parameters), p2c
    //                (positive integer), b64 (boolean)
    static auto parse(std::string_view json) -> expected<header>;
    static auto from_json(nlohmann::json json) -> expected<header>;

    // Decode a base64url Protected Header, then parse() it.
    static auto from_base64url(std::string_view encoded) -> expected<header>;

    // The header as a JSON object, exactly as parsed or set.
    [[nodiscard]] auto to_json() const noexcept -> const nlohmann::json& { return json_; }

    [[nodiscard]] auto empty() const noexcept -> bool { return json_.empty(); }
    [[nodiscard]] auto contains(std::string_view name) const -> bool;

    // Any parameter, registered or not; nullptr if absent.
    [[nodiscard]] auto get(std::string_view name) const -> const nlohmann::json*;

    // Add or replace a parameter. The whole header is re-validated; on
    // failure it is left unchanged.
    auto set(std::string name, nlohmann::json value) -> expected<void>;
    auto erase(std::string_view name) -> bool;

    // --- Registered parameters ---

    [[nodiscard]] auto alg() const -> std::optional<std::string_view> { return str("alg"); }
    [[nodiscard]] auto enc() const -> std::optional<std::string_view> { return str("enc"); }
    [[nodiscard]] auto zip() const -> std::optional<std::string_view> { return str("zip"); }
    [[nodiscard]] auto kid() const -> std::optional<std::string_view> { return str("kid"); }
    [[nodiscard]] auto typ() const -> std::optional<std::string_view> { return str("typ"); }
    [[nodiscard]] auto cty() const -> std::optional<std::string_view> { return str("cty"); }
    [[nodiscard]] auto jku() const -> std::optional<std::string_view> { return str("jku"); }
    [[nodiscard]] auto x5u() const -> std::optional<std::string_view> { return str("x5u"); }

    [[nodiscard]] auto jwk() const noexcept -> const std::optional<jose::jwk>& { return jwk_; }
    [[nodiscard]] auto epk() const noexcept -> const std::optional<jose::jwk>& { return epk_; }

    // DER certificates, leaf first.
    [[nodiscard]] auto x5c() const noexcept -> const std::vector<std::vector<uint8_t>>& { return x5c_; }
    [[nodiscard]] auto x5t() const -> std::optional<std::vector<uint8_t>> { return bytes("x5t"); }
    [[nodiscard]] auto x5t_s256() const -> std::optional<std::vector<uint8_t>> { return bytes("x5t#S256"); }

    [[nodiscard]] auto apu() const -> std::optional<std::vector<uint8_t>> { return bytes("apu"); }
    [[nodiscard]] auto apv() const -> std::optional<std::vector<uint8_t>> { return bytes("apv"); }
    [[nodiscard]] auto iv() const -> std::optional<std::vector<uint8_t>> { return bytes("iv"); }
    [[nodiscard]] auto tag() const -> std::optional<std::vector<uint8_t>> { return bytes("tag"); }
    [[nodiscard]] auto p2s() const -> std::optional<std::vector<uint8_t>> { return bytes("p2s"); }
    [[nodiscard]] auto p2c() const -> std::optional<uint64_t>;

    [[nodiscard]] auto crit() const -> std::vector<std::string>;
    [[nodiscard]] auto b64() const -> std::optional<bool>;

private:
    [[nodiscard]] auto str(std::string_view name) const -> std::optional<std::string_view>;
    [[nodiscard]] auto bytes(std::string_view name) const -> std::optional<std::vector<uint8_t>>;

    nlohmann::json json_ = nlohmann::json::object();
    // Parsed forms of the structured parameters, kept in sync with json_.
    std::optional<jose::jwk> jwk_;
    std::optional<jose::jwk> epk_;
    std::vector<std::vector<uint8_t>> x5c_;
};

// Combine the header parts that apply to one JWS signature or JWE recipient
// (RFC 7515 §7.2.1, RFC 7516 §7.2.1) into a single JOSE Header. For the
// compact serialization pass only the protected header.
//
// Fails with errc::invalid_header if:
//   - a parameter name appears in more than one part;
//   - "crit" (and, for JWS, "b64"; for JWE, "zip") is not in the protected
//     header;
//   - "alg" is missing (and, for JWE, "enc");
//   - for JWS, "b64" is present but not listed in "crit" (RFC 7797 §6);
//   - a name listed in "crit" is absent from the protected header.
//
// Fails with errc::unrecognized_critical_extension if "crit" lists a name
// that is neither understood by the library ("b64" for JWS) nor in
// `understood`. The default (empty) set rejects every application
// extension: safe by default.
auto join_headers(header_context ctx, const header& protected_header,
                  const header& shared_unprotected = {}, const header& per_recipient = {},
                  const extension_set& understood = {}) -> expected<header>;

} // namespace jose
