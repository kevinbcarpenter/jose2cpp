#include "jose/header.hpp"

#include "jose/base64url.hpp"
#include "jose/crypto/openssl_util.hpp"

#include "internal/codec.hpp"

#include <openssl/x509.h>

#include <algorithm>
#include <array>

namespace jose {

namespace {

using json = nlohmann::json;
using x509_ptr = std::unique_ptr<X509, decltype(&X509_free)>;

auto invalid(std::string message) -> unexpected {
    return make_error(errc::invalid_header, std::move(message));
}

auto in_quotes(std::string_view name) -> std::string {
    return "\"" + std::string(name) + "\"";
}

// Header Parameter names defined by RFC 7515 §4.1, RFC 7516 §4.1 and
// RFC 7518 §4.6.1 / §4.7.1 / §4.8.1: the names "crit" may not list.
// "b64" (RFC 7797) is deliberately absent: it is an extension and must be
// listed in "crit" when used.
constexpr std::array<std::string_view, 20> k_registered{
    // RFC 7515 §4.1 (all except "crit" also registered for JWE by RFC 7516)
    "alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit",
    // RFC 7516 §4.1
    "enc", "zip",
    // RFC 7518 §4.6.1 (ECDH-ES), §4.7.1 (AES-GCM KW), §4.8.1 (PBES2)
    "epk", "apu", "apv", "iv", "tag", "p2s", "p2c",
};

// Parameters that must be base64url strings, with a required decoded
// length (0 = any).
struct b64_param {
    std::string_view name;
    size_t size;
};
constexpr std::array<b64_param, 7> k_b64_params{{
    {"x5t", 20},
    {"x5t#S256", 32},
    {"apu", 0},
    {"apv", 0},
    {"iv", 0},
    {"tag", 0},
    {"p2s", 0},
}};

constexpr std::array<std::string_view, 8> k_string_params{
    "alg", "enc", "zip", "kid", "typ", "cty", "jku", "x5u",
};

auto find(const json& j, std::string_view name) -> const json* {
    auto it = j.find(std::string(name));
    return it == j.end() ? nullptr : &*it;
}

auto parse_public_jwk(const json& value, std::string_view name) -> expected<jose::jwk> {
    if (!value.is_object()) return invalid("header " + in_quotes(name) + " must be a JWK object");
    auto key = jose::jwk::from_json(value);
    if (!key) return invalid("header " + in_quotes(name) + ": " + key.error().message);
    if (key->key_type() == kty::oct)
        return invalid("header " + in_quotes(name) + " must be a public key, not a symmetric one");
    if (key->is_private())
        return invalid("header " + in_quotes(name) + " must be a public key, not a private one");
    return std::move(*key);
}

auto parse_x5c(const json& value) -> expected<std::vector<std::vector<uint8_t>>> {
    const auto bad = [] { return invalid("header \"x5c\" must be a non-empty array of base64 strings"); };
    if (!value.is_array() || value.empty()) return bad();
    std::vector<std::vector<uint8_t>> chain;
    for (const auto& entry : value) {
        if (!entry.is_string()) return bad();
        auto der = internal::b64std_decode(entry.get_ref<const std::string&>());
        if (!der) return invalid("header \"x5c\": " + der.error().message);
        const unsigned char* p = der->data();
        x509_ptr cert{d2i_X509(nullptr, &p, static_cast<long>(der->size())), X509_free};
        if (!cert || p != der->data() + der->size())
            return make_crypto_failure(errc::invalid_header, "header \"x5c\" contains an invalid certificate");
        chain.push_back(std::move(*der));
    }
    return chain;
}

auto check_thumbprint(const json& j, std::string_view name, const EVP_MD* md,
                      std::span<const uint8_t> leaf) -> expected<void> {
    const json* v = find(j, name);
    if (v == nullptr) return {};
    auto expected_bytes = base64url::decode(v->get_ref<const std::string&>());
    if (!expected_bytes) return jose::unexpected(expected_bytes.error());
    auto actual = internal::digest(md, leaf);
    if (!actual) return jose::unexpected(actual.error());
    if (!std::equal(actual->begin(), actual->end(), expected_bytes->begin(), expected_bytes->end()))
        return invalid("header " + in_quotes(name) + " does not match the \"x5c\" leaf certificate");
    return {};
}

// JSON text yields number_unsigned for non-negative integers, but a json
// built in C++ from an int literal holds number_integer.
auto is_positive_integer(const json& v) -> bool {
    if (v.is_number_unsigned()) return v.get<uint64_t>() > 0;
    return v.is_number_integer() && v.get<int64_t>() > 0;
}

auto check_crit(const json& value) -> expected<void> {
    const auto bad = [] { return invalid("header \"crit\" must be a non-empty array of strings"); };
    // RFC 7515 §4.1.11: producers MUST NOT use the empty list.
    if (!value.is_array() || value.empty()) return bad();
    std::set<std::string_view> seen;
    for (const auto& entry : value) {
        if (!entry.is_string()) return bad();
        const auto& name = entry.get_ref<const std::string&>();
        if (name.empty()) return bad();
        if (!seen.insert(name).second) return invalid("header \"crit\" lists " + in_quotes(name) + " twice");
        if (is_registered_header_parameter(name))
            return invalid("header \"crit\" must not list the registered parameter " + in_quotes(name));
    }
    return {};
}

} // namespace

auto is_registered_header_parameter(std::string_view name) -> bool {
    return std::find(k_registered.begin(), k_registered.end(), name) != k_registered.end();
}

// ---------------------------------------------------------------------------
// header
// ---------------------------------------------------------------------------

auto header::parse(std::string_view text) -> expected<header> {
    auto j = internal::parse_json_strict(text, "JOSE header");
    if (!j) return jose::unexpected(j.error());
    return from_json(std::move(*j));
}

auto header::from_base64url(std::string_view encoded) -> expected<header> {
    auto raw = base64url::decode(encoded);
    if (!raw)
        return make_error(errc::invalid_base64, "JOSE header is not valid base64url: " + raw.error().message);
    return parse(std::string_view(reinterpret_cast<const char*>(raw->data()), raw->size()));
}

auto header::from_json(json j) -> expected<header> {
    if (!j.is_object()) return invalid("JOSE header must be a JSON object");

    for (auto name : k_string_params)
        if (const json* v = find(j, name); v != nullptr && !v->is_string())
            return invalid("header " + in_quotes(name) + " must be a string");

    for (const auto& p : k_b64_params) {
        const json* v = find(j, p.name);
        if (v == nullptr) continue;
        if (!v->is_string()) return invalid("header " + in_quotes(p.name) + " must be a base64url string");
        auto bytes = base64url::decode(v->get_ref<const std::string&>());
        if (!bytes)
            return make_error(errc::invalid_base64, "header " + in_quotes(p.name) + ": " + bytes.error().message);
        if (p.size != 0 && bytes->size() != p.size)
            return invalid("header " + in_quotes(p.name) + " must be " + std::to_string(p.size) + " octets");
    }

    header out;

    if (const json* v = find(j, "jwk")) {
        auto key = parse_public_jwk(*v, "jwk");
        if (!key) return jose::unexpected(key.error());
        out.jwk_ = std::move(*key);
    }
    if (const json* v = find(j, "epk")) {
        auto key = parse_public_jwk(*v, "epk");
        if (!key) return jose::unexpected(key.error());
        out.epk_ = std::move(*key);
    }

    if (const json* v = find(j, "x5c")) {
        auto chain = parse_x5c(*v);
        if (!chain) return jose::unexpected(chain.error());
        out.x5c_ = std::move(*chain);
        if (auto r = check_thumbprint(j, "x5t", EVP_sha1(), out.x5c_.front()); !r)
            return jose::unexpected(r.error());
        if (auto r = check_thumbprint(j, "x5t#S256", EVP_sha256(), out.x5c_.front()); !r)
            return jose::unexpected(r.error());
    }

    if (const json* v = find(j, "crit"))
        if (auto r = check_crit(*v); !r) return jose::unexpected(r.error());

    // RFC 7518 §4.8.1.2: a positive integer. Upper bounds are enforced by
    // the PBES2 key-unwrap code, which knows its own limits.
    if (const json* v = find(j, "p2c"); v != nullptr && !is_positive_integer(*v))
        return invalid("header \"p2c\" must be a positive integer");

    // RFC 7797 §3.
    if (const json* v = find(j, "b64"); v != nullptr && !v->is_boolean())
        return invalid("header \"b64\" must be a boolean");

    out.json_ = std::move(j);
    return out;
}

auto header::contains(std::string_view name) const -> bool {
    return find(json_, name) != nullptr;
}

auto header::get(std::string_view name) const -> const json* {
    return find(json_, name);
}

auto header::set(std::string name, json value) -> expected<void> {
    json next = json_;
    next[std::move(name)] = std::move(value);
    auto parsed = from_json(std::move(next));
    if (!parsed) return jose::unexpected(parsed.error());
    *this = std::move(*parsed);
    return {};
}

auto header::erase(std::string_view name) -> bool {
    if (json_.erase(std::string(name)) == 0) return false;
    if (name == "jwk") jwk_.reset();
    if (name == "epk") epk_.reset();
    if (name == "x5c") x5c_.clear();
    return true;
}

auto header::str(std::string_view name) const -> std::optional<std::string_view> {
    const json* v = find(json_, name);
    if (v == nullptr) return std::nullopt;
    return std::string_view(v->get_ref<const std::string&>());
}

auto header::bytes(std::string_view name) const -> std::optional<std::vector<uint8_t>> {
    const json* v = find(json_, name);
    if (v == nullptr) return std::nullopt;
    // Validated as base64url when the header was built.
    auto decoded = base64url::decode(v->get_ref<const std::string&>());
    if (!decoded) return std::nullopt;
    return std::vector<uint8_t>(decoded->begin(), decoded->end());
}

auto header::p2c() const -> std::optional<uint64_t> {
    const json* v = find(json_, "p2c");
    if (v == nullptr) return std::nullopt;
    // Positive, so the conversion is exact whichever way it was stored.
    return v->is_number_unsigned() ? v->get<uint64_t>() : static_cast<uint64_t>(v->get<int64_t>());
}

auto header::crit() const -> std::vector<std::string> {
    const json* v = find(json_, "crit");
    if (v == nullptr) return {};
    return v->get<std::vector<std::string>>();
}

auto header::b64() const -> std::optional<bool> {
    const json* v = find(json_, "b64");
    if (v == nullptr) return std::nullopt;
    return v->get<bool>();
}

// ---------------------------------------------------------------------------
// join_headers
// ---------------------------------------------------------------------------

auto join_headers(header_context ctx, const header& protected_header, const header& shared_unprotected,
                  const header& per_recipient, const extension_set& understood) -> expected<header> {
    // RFC 7515 §7.2.1 / RFC 7516 §7.2.1: the parts must be disjoint.
    json joined = protected_header.to_json();
    for (const header* part : {&shared_unprotected, &per_recipient}) {
        for (const auto& [name, value] : part->to_json().items()) {
            if (joined.contains(name))
                return invalid("header parameter " + in_quotes(name) +
                               " appears in more than one header part");
            joined[name] = value;
        }
    }

    // Parameters that must be integrity protected.
    auto must_be_protected = [&](std::string_view name, const char* rfc) -> expected<void> {
        if (shared_unprotected.contains(name) || per_recipient.contains(name))
            return invalid("header " + in_quotes(name) + " must be in the protected header (" + rfc + ")");
        return {};
    };
    if (auto r = must_be_protected("crit", "RFC 7515 §4.1.11"); !r) return jose::unexpected(r.error());
    if (ctx == header_context::jws)
        if (auto r = must_be_protected("b64", "RFC 7797 §3"); !r) return jose::unexpected(r.error());
    if (ctx == header_context::jwe)
        if (auto r = must_be_protected("zip", "RFC 7516 §4.1.3"); !r) return jose::unexpected(r.error());

    if (!joined.contains("alg")) return invalid("JOSE header is missing \"alg\"");
    if (ctx == header_context::jwe && !joined.contains("enc"))
        return invalid("JWE header is missing \"enc\"");

    const auto crit = protected_header.crit();
    for (const auto& name : crit) {
        const bool library_understood = ctx == header_context::jws && name == "b64";
        if (!library_understood && understood.find(name) == understood.end())
            return make_error(errc::unrecognized_critical_extension,
                              "critical header extension " + in_quotes(name) + " is not understood");
        // A critical extension that isn't there can't be processed; and it
        // must be protected, or its value could be changed in transit.
        if (!protected_header.contains(name))
            return invalid("critical header extension " + in_quotes(name) + " is not in the protected header");
    }

    // RFC 7797 §6: "b64" must always be listed in "crit".
    if (ctx == header_context::jws && protected_header.contains("b64") &&
        std::find(crit.begin(), crit.end(), "b64") == crit.end())
        return invalid("header \"b64\" must be listed in \"crit\" (RFC 7797 §6)");

    // Every part was validated individually; the join only adds the
    // cross-part x5c/x5t check, which from_json repeats.
    return header::from_json(std::move(joined));
}

} // namespace jose
