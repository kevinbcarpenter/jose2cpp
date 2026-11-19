#pragma once

/// @file
/// JOSE Header (RFC 7515 §4, RFC 7516 §4, RFC 7518 §4, RFC 7797 §3).
///
/// A jose::header is one JSON object of header parameters: a JWS/JWE
/// Protected Header, a shared Unprotected Header, or a per-signature /
/// per-recipient Unprotected Header. Every registered parameter present is
/// type-checked when the header is built, so the typed accessors below never
/// fail. Unregistered (extension) parameters are kept verbatim and can be
/// read with get().
///
/// join_headers() combines the parts that apply to one signature or
/// recipient and enforces the rules that span them: names must be disjoint,
/// "crit" / "b64" / "zip" must be integrity protected, and every critical
/// extension must be understood (see PLAN.md §Critical Header Extensions).
///
/// @code{.cpp}
/// auto prot = jose::header::from_base64url(encoded_protected);
/// auto joined = jose::join_headers(jose::header_context::jws, *prot);
/// if (!joined) { /* joined.error().code == errc::unrecognized_critical_extension, ... */ }
/// @endcode

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

/// Where a header is being used. Determines which parameters are required
/// and which extensions the library itself understands.
enum class header_context {
    jws,
    jwe,
};

/// Names of application-defined extension parameters the caller understands
/// and will process. Used as the "crit" allowlist.
using extension_set = std::set<std::string, std::less<>>;

/// True for every Header Parameter name defined by RFC 7515, 7516 or 7518
/// ("alg", "enc", "epk", "p2c", ...). These may never be listed in "crit"
/// (RFC 7515 §4.1.11). "b64" (RFC 7797) is not one of them: it is an
/// extension, and must be listed in "crit" whenever it is used.
auto is_registered_header_parameter(std::string_view name) -> bool;

/// One JOSE header object, with its registered parameters type-checked.
class header {
public:
    /// An empty header.
    header() = default;

    /// Parse a header JSON object. Duplicate member names are rejected
    /// (RFC 7515 §4). Registered parameters are type-checked:
    ///
    /// - strings: alg, enc, zip, kid, typ, cty, jku, x5u
    /// - base64url: x5t (20 octets), x5t#S256 (32 octets), apu, apv, iv, tag, p2s
    /// - JWK objects, public keys only: jwk, epk
    /// - x5c: a non-empty array of base64 DER certificates; x5t and x5t#S256
    ///   must match the first
    /// - crit: a non-empty array of unique strings naming unregistered
    ///   parameters
    /// - p2c: a positive integer
    /// - b64: a boolean
    static auto parse(std::string_view json) -> expected<header>;
    /// As parse(), from JSON already parsed. It must be an object.
    static auto from_json(nlohmann::json json) -> expected<header>;

    /// Decode a base64url Protected Header, then parse() it.
    static auto from_base64url(std::string_view encoded) -> expected<header>;

    /// The header as a JSON object, exactly as parsed or set.
    [[nodiscard]] auto to_json() const noexcept -> const nlohmann::json& { return json_; }

    /// No parameters at all.
    [[nodiscard]] auto empty() const noexcept -> bool { return json_.empty(); }
    /// The parameter is present, registered or not.
    [[nodiscard]] auto contains(std::string_view name) const -> bool;

    /// Any parameter, registered or not; nullptr if absent.
    [[nodiscard]] auto get(std::string_view name) const -> const nlohmann::json*;

    /// Add or replace a parameter. The whole header is re-validated; on
    /// failure it is left unchanged.
    auto set(std::string name, nlohmann::json value) -> expected<void>;
    /// Remove a parameter; false if it wasn't there.
    auto erase(std::string_view name) -> bool;

    /// @name Registered parameters
    /// Each returns std::nullopt (or an empty container) when the parameter
    /// is absent. The values were type-checked when the header was built.
    ///@{

    /// "alg": the signature or key-management algorithm.
    [[nodiscard]] auto alg() const -> std::optional<std::string_view> { return str("alg"); }
    /// "enc": the JWE content-encryption algorithm.
    [[nodiscard]] auto enc() const -> std::optional<std::string_view> { return str("enc"); }
    /// "zip": JWE compression ("DEF").
    [[nodiscard]] auto zip() const -> std::optional<std::string_view> { return str("zip"); }
    /// "kid": the key ID.
    [[nodiscard]] auto kid() const -> std::optional<std::string_view> { return str("kid"); }
    /// "typ": the media type of the whole token ("JWT", ...).
    [[nodiscard]] auto typ() const -> std::optional<std::string_view> { return str("typ"); }
    /// "cty": the media type of the payload ("JWT" for a nested token).
    [[nodiscard]] auto cty() const -> std::optional<std::string_view> { return str("cty"); }
    /// "jku": a JWK Set URL. Never fetched by the library.
    [[nodiscard]] auto jku() const -> std::optional<std::string_view> { return str("jku"); }
    /// "x5u": an X.509 URL. Never fetched by the library.
    [[nodiscard]] auto x5u() const -> std::optional<std::string_view> { return str("x5u"); }

    /// "jwk": an embedded public key. Never used to verify implicitly.
    [[nodiscard]] auto jwk() const noexcept -> const std::optional<jose::jwk>& { return jwk_; }
    /// "epk": the ECDH-ES ephemeral public key.
    [[nodiscard]] auto epk() const noexcept -> const std::optional<jose::jwk>& { return epk_; }

    /// DER certificates, leaf first.
    [[nodiscard]] auto x5c() const noexcept -> const std::vector<std::vector<uint8_t>>& { return x5c_; }
    /// "x5t": SHA-1 thumbprint of the leaf certificate (20 octets).
    [[nodiscard]] auto x5t() const -> std::optional<std::vector<uint8_t>> { return bytes("x5t"); }
    /// "x5t#S256": SHA-256 thumbprint of the leaf certificate (32 octets).
    [[nodiscard]] auto x5t_s256() const -> std::optional<std::vector<uint8_t>> { return bytes("x5t#S256"); }

    /// "apu": ECDH-ES Agreement PartyUInfo, decoded.
    [[nodiscard]] auto apu() const -> std::optional<std::vector<uint8_t>> { return bytes("apu"); }
    /// "apv": ECDH-ES Agreement PartyVInfo, decoded.
    [[nodiscard]] auto apv() const -> std::optional<std::vector<uint8_t>> { return bytes("apv"); }
    /// "iv": the AES-GCM key-wrap initialization vector, decoded.
    [[nodiscard]] auto iv() const -> std::optional<std::vector<uint8_t>> { return bytes("iv"); }
    /// "tag": the AES-GCM key-wrap authentication tag, decoded.
    [[nodiscard]] auto tag() const -> std::optional<std::vector<uint8_t>> { return bytes("tag"); }
    /// "p2s": the PBES2 salt input, decoded.
    [[nodiscard]] auto p2s() const -> std::optional<std::vector<uint8_t>> { return bytes("p2s"); }
    /// "p2c": the PBES2 iteration count.
    [[nodiscard]] auto p2c() const -> std::optional<uint64_t>;

    /// "crit": the critical extension names; empty if absent.
    [[nodiscard]] auto crit() const -> std::vector<std::string>;
    /// "b64" (RFC 7797): false for an unencoded payload.
    [[nodiscard]] auto b64() const -> std::optional<bool>;
    ///@}

private:
    [[nodiscard]] auto str(std::string_view name) const -> std::optional<std::string_view>;
    [[nodiscard]] auto bytes(std::string_view name) const -> std::optional<std::vector<uint8_t>>;

    nlohmann::json json_ = nlohmann::json::object();
    /// Parsed forms of the structured parameters, kept in sync with json_.
    std::optional<jose::jwk> jwk_;
    std::optional<jose::jwk> epk_;
    std::vector<std::vector<uint8_t>> x5c_;
};

/// Combine the header parts that apply to one JWS signature or JWE recipient
/// (RFC 7515 §7.2.1, RFC 7516 §7.2.1) into a single JOSE Header. For the
/// compact serialization pass only the protected header.
///
/// Fails with errc::invalid_header if:
/// - a parameter name appears in more than one part;
/// - "crit" (and, for JWS, "b64"; for JWE, "zip") is not in the protected
///   header;
/// - "alg" is missing (and, for JWE, "enc");
/// - for JWS, "b64" is present but not listed in "crit" (RFC 7797 §6);
/// - a name listed in "crit" is absent from the protected header.
///
/// Fails with errc::unrecognized_critical_extension if "crit" lists a name
/// that is neither understood by the library ("b64" for JWS) nor in
/// `understood`. The default (empty) set rejects every application
/// extension: safe by default.
auto join_headers(header_context ctx, const header& protected_header,
                  const header& shared_unprotected = {}, const header& per_recipient = {},
                  const extension_set& understood = {}) -> expected<header>;

} // namespace jose
