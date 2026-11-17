#include "jose/jws.hpp"

#include "jose/base64url.hpp"
#include "jose/crypto/signing.hpp"

#include "internal/codec.hpp"

#include <algorithm>
#include <array>
#include <optional>

namespace jose {

namespace {

using json = nlohmann::json;

auto bad_token(std::string message) -> unexpected {
    return make_error(errc::invalid_token, std::move(message));
}

auto bad_argument(std::string message) -> unexpected {
    return make_error(errc::invalid_argument, std::move(message));
}

auto to_bytes(std::string_view s) -> std::vector<uint8_t> {
    return {s.begin(), s.end()};
}

auto as_view(std::span<const uint8_t> b) -> std::string_view {
    return {reinterpret_cast<const char*>(b.data()), b.size()};
}

auto decode_b64u(std::string_view s, const char* what) -> expected<std::vector<uint8_t>> {
    auto bytes = base64url::decode(s);
    if (!bytes)
        return make_error(errc::invalid_base64, std::string("JWS ") + what + ": " + bytes.error().message);
    return std::vector<uint8_t>(bytes->begin(), bytes->end());
}

// Everything about one signature that doesn't depend on the payload.
auto parse_signature(const std::string* encoded_protected, const json* unprotected,
                     std::string_view encoded_signature, const std::vector<signing_algorithm>& algorithms,
                     const extension_set& understood) -> expected<jws_signature> {
    header prot;
    if (encoded_protected != nullptr) {
        // RFC 7515 §7.2.1: when there is no protected header the member is
        // omitted, so an empty one is malformed.
        if (encoded_protected->empty()) return bad_token("JWS protected header is empty");
        auto h = header::from_base64url(*encoded_protected);
        if (!h) return jose::unexpected(h.error());
        prot = std::move(*h);
    }

    header unprot;
    if (unprotected != nullptr) {
        if (!unprotected->is_object()) return bad_token("JWS \"header\" must be a JSON object");
        auto h = header::from_json(*unprotected);
        if (!h) return jose::unexpected(h.error());
        unprot = std::move(*h);
    }

    auto joined = join_headers(header_context::jws, prot, {}, unprot, understood);
    if (!joined) return jose::unexpected(joined.error());

    const auto alg_name = *joined->alg(); // join_headers requires "alg"
    auto alg = parse_signing_algorithm(alg_name);
    if (!alg)
        return make_error(errc::unsupported_algorithm,
                          "unsupported JWS algorithm \"" + std::string(alg_name) + "\"");
    if (std::find(algorithms.begin(), algorithms.end(), *alg) == algorithms.end())
        return make_error(errc::algorithm_mismatch,
                          "JWS algorithm \"" + std::string(alg_name) + "\" is not in the allowed list");

    auto signature = decode_b64u(encoded_signature, "signature");
    if (!signature) return jose::unexpected(signature.error());

    return jws_signature{
        .alg = *alg,
        .protected_header = std::move(prot),
        .unprotected_header = std::move(unprot),
        .joined = std::move(*joined),
        .signature = std::move(*signature),
        .encoded_protected = encoded_protected != nullptr ? *encoded_protected : std::string(),
    };
}

auto b64_of(const jws_signature& sig) -> bool { return sig.joined.b64().value_or(true); }

template <typename T>
auto contains(const std::vector<T>& v, T x) -> bool {
    return std::find(v.begin(), v.end(), x) != v.end();
}

// Catches the usual opaque-signer mistake: a DER-encoded ECDSA signature
// (what most HSMs and KMSs return) instead of JWS's fixed-size R || S.
auto check_signature_size(signing_algorithm alg, std::span<const uint8_t> sig) -> expected<void> {
    size_t want = 0;
    switch (alg) {
    case signing_algorithm::ES256: want = 64; break;
    case signing_algorithm::ES384: want = 96; break;
    case signing_algorithm::ES512: want = 132; break;
    default:
        if (sig.empty()) return make_error(errc::invalid_signature, "the opaque signer returned an empty signature");
        return {};
    }
    if (sig.size() == want) return {};
    return make_error(errc::invalid_signature,
                      "the opaque signer returned a " + std::to_string(sig.size()) + "-octet " +
                          std::string(to_string(alg)) + " signature; JWS needs " + std::to_string(want) +
                          " (R || S, not DER)");
}

auto first_non_space(std::string_view s) -> char {
    for (char c : s)
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') return c;
    return '\0';
}

} // namespace

// ===========================================================================
// Signing
// ===========================================================================

auto jws::sign(std::span<const uint8_t> payload, const jws_signer& signer, const jws_sign_options& options)
    -> expected<jws> {
    return sign(payload, std::span<const jws_signer>(&signer, 1), options);
}

auto jws::sign(std::string_view payload, const jws_signer& signer, const jws_sign_options& options)
    -> expected<jws> {
    return sign(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(payload.data()), payload.size()),
                signer, options);
}

auto jws::sign(std::span<const uint8_t> payload, std::span<const jws_signer> signers,
               const jws_sign_options& options) -> expected<jws> {
    if (signers.empty()) return bad_argument("JWS needs at least one signer");

    jws out;
    out.payload_.assign(payload.begin(), payload.end());
    out.b64_ = options.b64;
    out.encoded_payload_ = options.b64 ? base64url::encode(payload) : std::string(as_view(payload));

    for (const auto& signer : signers) {
        const auto alg_name = to_string(signer.alg);
        const jwk* local = std::get_if<jwk>(&signer.key);
        opaque_signer* opaque = local ? nullptr : std::get<std::shared_ptr<opaque_signer>>(signer.key).get();

        // The public key, for "kid" and "jwk"; asked of an opaque signer
        // only when needed.
        std::optional<jwk> public_key;
        if (local) {
            const jwk& key = *local;
            if (key.key_type() != kty::oct && !key.is_private())
                return make_error(errc::invalid_key, "signing requires a private key");
            if (auto r = key.check_algorithm(alg_name); !r) return jose::unexpected(r.error());
            if (auto r = key.check_operation("sign"); !r) return jose::unexpected(r.error());
        } else {
            if (!opaque) return bad_argument("jws_signer has a null opaque signer");
            if (!contains(opaque->algorithms(), signer.alg))
                return make_error(errc::algorithm_mismatch,
                                  "the opaque signer does not support " + std::string(alg_name));
            if (options.include_kid || options.embed_jwk) {
                auto pub = opaque->public_key();
                if (!pub) return jose::unexpected(pub.error());
                public_key = std::move(*pub);
            }
        }
        const jwk* key_info = local ? local : public_key ? &*public_key : nullptr;

        header prot = signer.protected_header;
        const header& unprot = signer.unprotected_header;

        if (auto a = prot.alg(); a && *a != alg_name)
            return bad_argument("protected header \"alg\" (" + std::string(*a) + ") differs from the signer's " +
                                std::string(alg_name));
        if (auto r = prot.set("alg", alg_name); !r) return jose::unexpected(r.error());

        if (options.include_kid && key_info && key_info->key_id() && !prot.contains("kid") &&
            !unprot.contains("kid"))
            if (auto r = prot.set("kid", *key_info->key_id()); !r) return jose::unexpected(r.error());

        if (options.embed_jwk) {
            if (prot.contains("jwk")) return bad_argument("protected header already has \"jwk\"");
            if (key_info->key_type() == kty::oct) return bad_argument("cannot embed a symmetric key");
            auto pub = key_info->public_key();
            if (!pub) return jose::unexpected(pub.error());
            auto pub_json = pub->to_json();
            if (!pub_json) return jose::unexpected(pub_json.error());
            if (auto r = prot.set("jwk", std::move(*pub_json)); !r) return jose::unexpected(r.error());
        }

        if (prot.contains("b64") || unprot.contains("b64"))
            return bad_argument("set \"b64\" with jws_sign_options::b64, not in a header");
        if (!options.b64) {
            auto crit = prot.crit();
            crit.emplace_back("b64");
            if (auto r = prot.set("b64", false); !r) return jose::unexpected(r.error());
            if (auto r = prot.set("crit", crit); !r) return jose::unexpected(r.error());
        }

        // The producer understands its own extensions; this checks the
        // structural rules (disjoint parts, "crit" protected, ...).
        const auto own = prot.crit();
        auto joined = join_headers(header_context::jws, prot, {}, unprot, extension_set(own.begin(), own.end()));
        if (!joined) return jose::unexpected(joined.error());

        jws_signature sig{
            .alg = signer.alg,
            .protected_header = prot,
            .unprotected_header = unprot,
            .joined = std::move(*joined),
            .signature = {},
            .encoded_protected = base64url::encode(std::string_view(prot.to_json().dump())),
        };

        const auto input = out.signing_input(sig);
        if (local) {
            auto value = local->key_type() == kty::oct ? jose::sign(signer.alg, local->oct(), input)
                                                       : jose::sign(signer.alg, local->pkey(), input);
            if (!value) return jose::unexpected(value.error());
            sig.signature.assign(value->begin(), value->end());
        } else {
            auto value = opaque->sign(input, signer.alg);
            if (!value) return jose::unexpected(value.error());
            if (auto r = check_signature_size(signer.alg, *value); !r) return jose::unexpected(r.error());
            sig.signature = std::move(*value);
        }
        out.signatures_.push_back(std::move(sig));
    }
    return out;
}

auto jws::signing_input(const jws_signature& sig) const -> std::vector<uint8_t> {
    // RFC 7515 §5.1 / RFC 7797 §3:
    //   ASCII(BASE64URL(protected)) || '.' || (BASE64URL(payload) or payload)
    std::vector<uint8_t> input;
    input.reserve(sig.encoded_protected.size() + 1 + encoded_payload_.size());
    input.insert(input.end(), sig.encoded_protected.begin(), sig.encoded_protected.end());
    input.push_back('.');
    input.insert(input.end(), encoded_payload_.begin(), encoded_payload_.end());
    return input;
}

// ===========================================================================
// Parsing
// ===========================================================================

namespace {

auto require_algorithms(const std::vector<signing_algorithm>& algorithms) -> expected<void> {
    if (algorithms.empty()) return bad_argument("JWS parsing needs a non-empty list of allowed algorithms");
    return {};
}

} // namespace

auto jws::parse(std::string_view input, const std::vector<signing_algorithm>& algorithms,
                const extension_set& understood) -> expected<jws> {
    return first_non_space(input) == '{' ? parse_json(input, algorithms, understood)
                                         : parse_compact(input, algorithms, understood);
}

namespace {

// Shared by parse_compact / parse_detached.
auto parse_compact_parts(std::string_view input) -> expected<std::array<std::string_view, 3>> {
    std::array<std::string_view, 3> parts;
    size_t start = 0;
    for (size_t i = 0; i < 3; ++i) {
        const size_t dot = input.find('.', start);
        if ((i < 2) == (dot == std::string_view::npos))
            return bad_token("JWS compact serialization must have exactly three parts");
        parts[i] = input.substr(start, i < 2 ? dot - start : std::string_view::npos);
        start = dot + 1;
    }
    return parts;
}

} // namespace

auto jws::parse_compact(std::string_view input, const std::vector<signing_algorithm>& algorithms,
                        const extension_set& understood) -> expected<jws> {
    if (auto r = require_algorithms(algorithms); !r) return jose::unexpected(r.error());
    auto parts = parse_compact_parts(input);
    if (!parts) return jose::unexpected(parts.error());
    const auto& [prot, payload, signature] = *parts;

    const std::string encoded_protected(prot);
    auto sig = parse_signature(&encoded_protected, nullptr, signature, algorithms, understood);
    if (!sig) return jose::unexpected(sig.error());

    jws out;
    out.b64_ = b64_of(*sig);
    out.encoded_payload_ = std::string(payload);
    if (out.b64_) {
        auto bytes = decode_b64u(payload, "payload");
        if (!bytes) return jose::unexpected(bytes.error());
        out.payload_ = std::move(*bytes);
    } else {
        out.payload_ = to_bytes(payload);
    }
    out.signatures_.push_back(std::move(*sig));
    return out;
}

auto jws::parse_json(std::string_view input, const std::vector<signing_algorithm>& algorithms,
                     const extension_set& understood) -> expected<jws> {
    if (auto r = require_algorithms(algorithms); !r) return jose::unexpected(r.error());
    auto j = internal::parse_json_strict(input, "JWS");
    if (!j) return jose::unexpected(j.error());
    return from_json_value(*j, algorithms, understood, nullptr);
}

auto jws::from_json_value(const json& j, const std::vector<signing_algorithm>& algorithms,
                          const extension_set& understood, const std::span<const uint8_t>* detached)
    -> expected<jws> {
    if (!j.is_object()) return bad_token("JWS JSON serialization must be an object");

    const auto member = [](const json& obj, const char* name) -> const json* {
        auto it = obj.find(name);
        return it == obj.end() ? nullptr : &*it;
    };

    // Both forms: {"protected"?, "header"?, "signature"} per signature.
    std::vector<const json*> entries;
    if (const json* sigs = member(j, "signatures")) {
        if (member(j, "signature") || member(j, "protected") || member(j, "header"))
            return bad_token("JWS JSON mixes general and flattened serialization members");
        if (!sigs->is_array() || sigs->empty())
            return bad_token("JWS \"signatures\" must be a non-empty array");
        for (const auto& s : *sigs) {
            if (!s.is_object()) return bad_token("JWS \"signatures\" entries must be objects");
            entries.push_back(&s);
        }
    } else {
        entries.push_back(&j);
    }

    jws out;
    for (const json* e : entries) {
        const json* prot = member(*e, "protected");
        const json* unprot = member(*e, "header");
        const json* signature = member(*e, "signature");
        if (signature == nullptr || !signature->is_string())
            return bad_token("JWS \"signature\" must be a string");
        if (prot != nullptr && !prot->is_string()) return bad_token("JWS \"protected\" must be a string");

        auto sig = parse_signature(prot ? &prot->get_ref<const std::string&>() : nullptr, unprot,
                                   signature->get_ref<const std::string&>(), algorithms, understood);
        if (!sig) return jose::unexpected(sig.error());

        // RFC 7797 §3: every signature must agree on "b64".
        if (out.signatures_.empty())
            out.b64_ = b64_of(*sig);
        else if (b64_of(*sig) != out.b64_)
            return make_error(errc::invalid_header, "JWS signatures disagree on \"b64\"");
        out.signatures_.push_back(std::move(*sig));
    }

    const json* payload = member(j, "payload");
    if (detached != nullptr) {
        if (payload != nullptr) return bad_token("detached JWS must not have a \"payload\" member");
        out.set_detached_payload(*detached);
        return out;
    }
    if (payload == nullptr) return bad_token("JWS payload is detached; use jws::parse_detached");
    if (!payload->is_string()) return bad_token("JWS \"payload\" must be a string");
    const auto& text = payload->get_ref<const std::string&>();
    out.encoded_payload_ = text;
    if (out.b64_) {
        auto bytes = decode_b64u(text, "payload");
        if (!bytes) return jose::unexpected(bytes.error());
        out.payload_ = std::move(*bytes);
    } else {
        out.payload_ = to_bytes(text);
    }
    return out;
}

auto jws::set_detached_payload(std::span<const uint8_t> payload) -> void {
    payload_.assign(payload.begin(), payload.end());
    encoded_payload_ = b64_ ? base64url::encode(payload) : std::string(as_view(payload));
}

auto jws::parse_detached(std::string_view input, std::span<const uint8_t> payload,
                         const std::vector<signing_algorithm>& algorithms, const extension_set& understood)
    -> expected<jws> {
    if (auto r = require_algorithms(algorithms); !r) return jose::unexpected(r.error());
    if (first_non_space(input) == '{') {
        auto j = internal::parse_json_strict(input, "JWS");
        if (!j) return jose::unexpected(j.error());
        return from_json_value(*j, algorithms, understood, &payload);
    }
    auto parts = parse_compact_parts(input);
    if (!parts) return jose::unexpected(parts.error());
    if (!(*parts)[1].empty()) return bad_token("detached JWS must have an empty payload part");
    auto parsed = parse_compact(input, algorithms, understood);
    if (!parsed) return parsed;
    parsed->set_detached_payload(payload);
    return parsed;
}

// ===========================================================================
// Verifying
// ===========================================================================

auto jws::verify_one(const jws_signature& sig, const jwk& key) const -> expected<void> {
    if (auto r = key.check_algorithm(to_string(sig.alg)); !r) return r;
    if (auto r = key.check_operation("verify"); !r) return r;

    const auto input = signing_input(sig);
    auto ok = key.key_type() == kty::oct ? jose::verify(sig.alg, key.oct(), input, sig.signature)
                                         : jose::verify(sig.alg, key.pkey(), input, sig.signature);
    if (!ok) {
        if (ok.error().code == errc::invalid_signature) return ok;
        return make_error(errc::invalid_signature, "JWS signature is invalid: " + ok.error().message);
    }
    return {};
}

auto jws::verify_one(const jws_signature& sig, opaque_verifier& verifier) const -> expected<void> {
    if (!contains(verifier.algorithms(), sig.alg))
        return make_error(errc::algorithm_mismatch,
                          "the opaque verifier does not support " + std::string(to_string(sig.alg)));
    auto ok = verifier.verify(signing_input(sig), sig.signature, sig.alg);
    if (!ok) {
        if (ok.error().code == errc::invalid_signature || ok.error().code == errc::key_unavailable) return ok;
        return make_error(errc::invalid_signature, "JWS signature is invalid: " + ok.error().message);
    }
    return {};
}

auto jws::verify(const jwk& key) const -> expected<std::vector<uint8_t>> {
    if (signatures_.size() != 1)
        return bad_argument("JWS has " + std::to_string(signatures_.size()) +
                            " signatures; use verify_multi");
    if (auto r = verify_one(signatures_.front(), key); !r) return jose::unexpected(r.error());
    return payload_;
}

auto jws::verify(const jwk_set& keys) const -> expected<std::vector<uint8_t>> {
    if (signatures_.size() != 1)
        return bad_argument("JWS has " + std::to_string(signatures_.size()) +
                            " signatures; use verify_multi");
    const auto& sig = signatures_.front();
    const auto kid = sig.joined.kid();
    if (!kid) return make_error(errc::invalid_key, "JWS has no \"kid\" to select a key from the set");

    const auto candidates = keys.find_all(*kid);
    if (candidates.empty())
        return make_error(errc::invalid_key, "no key in the set has \"kid\":\"" + std::string(*kid) + "\"");

    expected<void> last = make_error(errc::invalid_key, "unreachable");
    for (const jwk& key : candidates) {
        last = verify_one(sig, key);
        if (last) return payload_;
    }
    return jose::unexpected(last.error());
}

auto jws::verify_multi(const jwk& key) const -> expected<verified> {
    bool attempted = false;
    for (size_t i = 0; i < signatures_.size(); ++i) {
        const auto& sig = signatures_[i];
        if (!key.check_algorithm(to_string(sig.alg)) || !key.check_operation("verify")) continue;
        attempted = true;
        if (verify_one(sig, key)) return verified{i, payload_};
    }
    if (!attempted) return make_error(errc::algorithm_mismatch, "the key suits none of the JWS signatures");
    return make_error(errc::invalid_signature, "no JWS signature verified with the key");
}

auto jws::verify(opaque_verifier& verifier) const -> expected<std::vector<uint8_t>> {
    if (signatures_.size() != 1)
        return bad_argument("JWS has " + std::to_string(signatures_.size()) +
                            " signatures; use verify_multi");
    if (auto r = verify_one(signatures_.front(), verifier); !r) return jose::unexpected(r.error());
    return payload_;
}

auto jws::verify_multi(opaque_verifier& verifier) const -> expected<verified> {
    const auto algs = verifier.algorithms();
    bool attempted = false;
    for (size_t i = 0; i < signatures_.size(); ++i) {
        const auto& sig = signatures_[i];
        if (!contains(algs, sig.alg)) continue;
        attempted = true;
        auto r = verify_one(sig, verifier);
        if (r) return verified{i, payload_};
        // The backend being unreachable isn't a verdict on the signature.
        if (r.error().code == errc::key_unavailable) return jose::unexpected(r.error());
    }
    if (!attempted) return make_error(errc::algorithm_mismatch, "the verifier suits none of the JWS signatures");
    return make_error(errc::invalid_signature, "no JWS signature verified with the verifier");
}

// ===========================================================================
// Serializing
// ===========================================================================

namespace {

auto check_compactable(std::span<const jws_signature> sigs) -> expected<void> {
    if (sigs.size() != 1)
        return bad_argument("compact serialization needs exactly one signature, not " +
                            std::to_string(sigs.size()));
    if (!sigs.front().unprotected_header.empty())
        return bad_argument("compact serialization cannot carry an unprotected header");
    if (sigs.front().encoded_protected.empty())
        return bad_argument("compact serialization needs a protected header");
    return {};
}

} // namespace

auto jws::compact() const -> expected<std::string> {
    if (auto r = check_compactable(signatures_); !r) return jose::unexpected(r.error());
    if (!b64_ && encoded_payload_.find('.') != std::string::npos)
        return bad_argument("an unencoded payload containing '.' cannot be compact (RFC 7797 §5.2); "
                            "use compact_detached");
    const auto& sig = signatures_.front();
    return sig.encoded_protected + "." + encoded_payload_ + "." + base64url::encode(sig.signature);
}

auto jws::compact_detached() const -> expected<std::string> {
    if (auto r = check_compactable(signatures_); !r) return jose::unexpected(r.error());
    const auto& sig = signatures_.front();
    return sig.encoded_protected + ".." + base64url::encode(sig.signature);
}

auto jws::to_json(jws_json_format format, bool detached) const -> expected<json> {
    if (format == jws_json_format::flattened && signatures_.size() != 1)
        return bad_argument("flattened JSON serialization needs exactly one signature");

    auto entry = [](const jws_signature& sig) {
        json e = json::object();
        if (!sig.encoded_protected.empty()) e["protected"] = sig.encoded_protected;
        if (!sig.unprotected_header.empty()) e["header"] = sig.unprotected_header.to_json();
        e["signature"] = base64url::encode(sig.signature);
        return e;
    };

    json out = format == jws_json_format::flattened ? entry(signatures_.front()) : json::object();
    if (format == jws_json_format::general) {
        json sigs = json::array();
        for (const auto& sig : signatures_) sigs.push_back(entry(sig));
        out["signatures"] = std::move(sigs);
    }
    if (!detached) {
        if (!b64_ && !internal::is_valid_utf8(encoded_payload_))
            return make_error(errc::serialization_error,
                              "an unencoded payload must be valid UTF-8 to appear in JSON");
        out["payload"] = encoded_payload_;
    }
    return out;
}

auto jws::to_json_string(jws_json_format format, bool detached) const -> expected<std::string> {
    auto j = to_json(format, detached);
    if (!j) return jose::unexpected(j.error());
    return j->dump();
}

} // namespace jose
