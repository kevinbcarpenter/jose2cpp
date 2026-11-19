#include "jose/jwe.hpp"

#include "jose/base64url.hpp"
#include "jose/crypto/aes_gcm_kw.hpp"
#include "jose/crypto/aes_kw.hpp"
#include "jose/crypto/ecdh.hpp"
#include "jose/crypto/encryption.hpp"
#include "jose/crypto/pbes2.hpp"
#include "jose/crypto/rsa.hpp"

#include "internal/codec.hpp"
#include "internal/deflate.hpp"

#include <algorithm>
#include <array>

namespace jose {

namespace {

using json = nlohmann::json;

auto bad_token(std::string message) -> unexpected {
    return make_error(errc::invalid_token, std::move(message));
}

auto bad_argument(std::string message) -> unexpected {
    return make_error(errc::invalid_argument, std::move(message));
}

// Every cryptographic failure while decrypting reports the same error, so
// a key-unwrap failure can't be told apart from a bad tag.
auto decryption_failed() -> unexpected {
    return make_error(errc::decryption_failed, "JWE decryption failed");
}

auto as_view(std::span<const uint8_t> b) -> std::string_view {
    return {reinterpret_cast<const char*>(b.data()), b.size()};
}

auto decode_b64u(std::string_view s, const char* what) -> expected<std::vector<uint8_t>> {
    auto bytes = base64url::decode(s);
    if (!bytes)
        return make_error(errc::invalid_base64, std::string("JWE ") + what + ": " + bytes.error().message);
    return std::vector<uint8_t>(bytes->begin(), bytes->end());
}

auto first_non_space(std::string_view s) -> char {
    for (char c : s)
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') return c;
    return '\0';
}

enum class family { rsa, aes_kw, aes_gcm_kw, ecdh_direct, ecdh_kw, pbes2, dir };

auto family_of(key_algorithm alg) -> family {
    switch (alg) {
    case key_algorithm::RSA1_5:
    case key_algorithm::RSA_OAEP:
    case key_algorithm::RSA_OAEP_256: return family::rsa;
    case key_algorithm::A128KW:
    case key_algorithm::A192KW:
    case key_algorithm::A256KW: return family::aes_kw;
    case key_algorithm::A128GCMKW:
    case key_algorithm::A192GCMKW:
    case key_algorithm::A256GCMKW: return family::aes_gcm_kw;
    case key_algorithm::ECDH_ES: return family::ecdh_direct;
    case key_algorithm::ECDH_ES_A128KW:
    case key_algorithm::ECDH_ES_A192KW:
    case key_algorithm::ECDH_ES_A256KW: return family::ecdh_kw;
    case key_algorithm::PBES2_HS256_A128KW:
    case key_algorithm::PBES2_HS384_A192KW:
    case key_algorithm::PBES2_HS512_A256KW: return family::pbes2;
    case key_algorithm::dir: return family::dir;
    }
    return family::dir; // unreachable
}

// ECDH-ES+AxxxKW -> AxxxKW.
auto ecdh_wrap_alg(key_algorithm alg) -> key_algorithm {
    switch (alg) {
    case key_algorithm::ECDH_ES_A128KW: return key_algorithm::A128KW;
    case key_algorithm::ECDH_ES_A192KW: return key_algorithm::A192KW;
    default: return key_algorithm::A256KW;
    }
}

auto wrap_key_bits(key_algorithm kw) -> size_t {
    switch (kw) {
    case key_algorithm::A128KW: return 128;
    case key_algorithm::A192KW: return 192;
    default: return 256;
    }
}

// RFC 7517 §4.3 key_ops value for using a key with `alg`.
auto operation_for(key_algorithm alg, bool encrypting) -> std::string_view {
    switch (family_of(alg)) {
    case family::ecdh_direct:
    case family::ecdh_kw: return "deriveKey";
    case family::dir: return encrypting ? "encrypt" : "decrypt";
    default: return encrypting ? "wrapKey" : "unwrapKey";
    }
}

// Does `key` suit `alg` (and, for dir, `enc`)?
auto check_key(key_algorithm alg, content_encryption enc, const jwk& key, bool encrypting) -> expected<void> {
    if (alg == key_algorithm::dir) {
        // A direct CEK may be labelled "alg":"dir" or with its "enc" value
        // (RFC 7520 §5.6); either way its size must match "enc".
        if (key.algorithm() == "dir") {
            if (auto r = key.check_algorithm("dir"); !r) return r;
            if (key.oct().size() != cek_byte_size(enc))
                return make_error(errc::invalid_key, std::string(to_string(enc)) + " requires a " +
                                                         std::to_string(cek_byte_size(enc)) + "-octet key");
        } else if (auto r = key.check_algorithm(to_string(enc)); !r) {
            return r;
        }
    } else if (auto r = key.check_algorithm(to_string(alg)); !r) {
        return r;
    }
    return key.check_operation(operation_for(alg, encrypting));
}

// For ECDH-ES, a recipient only suits a key on the same curve as its "epk".
auto epk_matches(key_algorithm alg, const header& h, const jwk& key) -> bool {
    const auto f = family_of(alg);
    if (f != family::ecdh_direct && f != family::ecdh_kw) return true;
    const auto& epk = h.epk();
    return epk && epk->key_type() == key.key_type() && epk->ec_crv() == key.ec_crv() &&
           epk->okp_crv() == key.okp_crv();
}

auto bytes_view(const std::optional<std::vector<uint8_t>>& v) -> std::string_view {
    return v ? as_view(*v) : std::string_view();
}

// Parameters the library sets itself; callers may not supply them.
constexpr std::array<std::string_view, 8> k_library_params{"alg", "enc", "zip", "epk", "iv", "tag", "p2s", "p2c"};

auto check_no_library_params(const header& h, const char* where) -> expected<void> {
    for (auto name : k_library_params)
        if (h.contains(name))
            return bad_argument(std::string("\"") + std::string(name) + "\" in the " + where +
                                " is set by the library");
    return {};
}

} // namespace

// ===========================================================================
// Encrypting
// ===========================================================================

auto jwe::encrypt(std::span<const uint8_t> plaintext, content_encryption enc, const jwe_recipient& recipient,
                  const jwe_encrypt_options& options) -> expected<jwe> {
    return encrypt(plaintext, enc, std::span<const jwe_recipient>(&recipient, 1), options);
}

auto jwe::encrypt(std::string_view plaintext, content_encryption enc, const jwe_recipient& recipient,
                  const jwe_encrypt_options& options) -> expected<jwe> {
    return encrypt(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size()),
                   enc, recipient, options);
}

auto jwe::encrypt(std::span<const uint8_t> plaintext, content_encryption enc,
                  std::span<const jwe_recipient> recipients, const jwe_encrypt_options& options)
    -> expected<jwe> {
    if (recipients.empty()) return bad_argument("JWE needs at least one recipient");
    if (recipients.size() > max_recipients)
        return bad_argument("JWE can have at most " + std::to_string(max_recipients) + " recipients");
    const bool single = recipients.size() == 1;
    for (const auto& r : recipients) {
        const auto f = family_of(r.alg);
        if (!single && (f == family::dir || f == family::ecdh_direct))
            return bad_argument(std::string(to_string(r.alg)) + " can only be used with a single recipient");
    }
    if (auto r = check_no_library_params(options.protected_header, "protected header"); !r)
        return jose::unexpected(r.error());
    if (auto r = check_no_library_params(options.shared_unprotected, "shared unprotected header"); !r)
        return jose::unexpected(r.error());

    // The CEK: random, unless the single recipient determines it.
    secure_bytes cek;
    if (recipients.front().alg == key_algorithm::dir) {
        const auto& key = recipients.front().key;
        if (auto r = check_key(key_algorithm::dir, enc, key, true); !r) return jose::unexpected(r.error());
        cek.assign(key.oct().begin(), key.oct().end());
    } else if (recipients.front().alg != key_algorithm::ECDH_ES) {
        auto random = generate_cek(enc);
        if (!random) return jose::unexpected(random.error());
        cek = std::move(*random);
    }

    // Per-recipient key management.
    std::vector<header> params;
    std::vector<std::vector<uint8_t>> encrypted_keys;
    for (const auto& r : recipients) {
        const auto alg_name = std::string(to_string(r.alg));
        if (auto c = check_key(r.alg, enc, r.key, true); !c) return jose::unexpected(c.error());
        if (auto c = check_no_library_params(r.parameters, "recipient parameters"); !c)
            return jose::unexpected(c.error());

        header p = r.parameters;
        auto set = [&p](std::string name, json value) { return p.set(std::move(name), std::move(value)); };
        if (auto s = set("alg", alg_name); !s) return jose::unexpected(s.error());
        if (options.include_kid && r.key.key_id() && !p.contains("kid") &&
            !options.protected_header.contains("kid") && !options.shared_unprotected.contains("kid"))
            if (auto s = set("kid", *r.key.key_id()); !s) return jose::unexpected(s.error());

        secure_bytes encrypted_key;
        switch (family_of(r.alg)) {
        case family::rsa: {
            auto ek = rsa_encrypt_key(r.alg, r.key.pkey(), cek, options.legacy);
            if (!ek) return jose::unexpected(ek.error());
            encrypted_key = std::move(*ek);
            break;
        }
        case family::aes_kw: {
            auto ek = aes_key_wrap(r.alg, r.key.oct(), cek);
            if (!ek) return jose::unexpected(ek.error());
            encrypted_key = std::move(*ek);
            break;
        }
        case family::aes_gcm_kw: {
            auto w = aes_gcm_key_wrap(r.alg, r.key.oct(), cek);
            if (!w) return jose::unexpected(w.error());
            encrypted_key = std::move(w->encrypted_key);
            if (auto s = set("iv", base64url::encode(w->iv)); !s) return jose::unexpected(s.error());
            if (auto s = set("tag", base64url::encode(w->tag)); !s) return jose::unexpected(s.error());
            break;
        }
        case family::pbes2: {
            auto w = pbes2_key_wrap(r.alg, as_view(r.key.oct()), cek, r.pbes2_count);
            if (!w) return jose::unexpected(w.error());
            encrypted_key = std::move(w->encrypted_key);
            if (auto s = set("p2s", base64url::encode(w->p2s)); !s) return jose::unexpected(s.error());
            if (auto s = set("p2c", w->p2c); !s) return jose::unexpected(s.error());
            break;
        }
        case family::ecdh_direct:
        case family::ecdh_kw: {
            const bool direct = family_of(r.alg) == family::ecdh_direct;
            // RFC 7518 §4.6.2: AlgorithmID is "enc" for direct agreement,
            // "alg" for key wrapping; keydatalen matches.
            const auto kw = ecdh_wrap_alg(r.alg);
            auto agreed = ecdh_derive_key(r.key.pkey(), direct ? to_string(enc) : to_string(r.alg),
                                          bytes_view(p.apu()), bytes_view(p.apv()),
                                          direct ? cek_byte_size(enc) * 8 : wrap_key_bits(kw));
            if (!agreed) return jose::unexpected(agreed.error());
            auto eph = jwk::from_pkey(std::move(agreed->ephemeral_key));
            if (!eph) return jose::unexpected(eph.error());
            auto eph_pub = eph->public_key();
            if (!eph_pub) return jose::unexpected(eph_pub.error());
            auto epk = eph_pub->to_json();
            if (!epk) return jose::unexpected(epk.error());
            if (auto s = set("epk", std::move(*epk)); !s) return jose::unexpected(s.error());
            if (direct) {
                cek = std::move(agreed->derived_key);
            } else {
                auto ek = aes_key_wrap(kw, agreed->derived_key, cek);
                if (!ek) return jose::unexpected(ek.error());
                encrypted_key = std::move(*ek);
            }
            break;
        }
        case family::dir:
            break;
        }
        params.push_back(std::move(p));
        encrypted_keys.emplace_back(encrypted_key.begin(), encrypted_key.end());
    }

    // Headers. With one recipient its parameters join the protected header.
    jwe out;
    out.enc_ = enc;
    header prot = options.protected_header;
    if (auto s = prot.set("enc", to_string(enc)); !s) return jose::unexpected(s.error());
    if (options.compress)
        if (auto s = prot.set("zip", "DEF"); !s) return jose::unexpected(s.error());
    if (single) {
        for (const auto& [name, value] : params.front().to_json().items()) {
            if (prot.contains(name))
                return bad_argument("\"" + name + "\" is set in both the protected header and the recipient");
            if (auto s = prot.set(name, value); !s) return jose::unexpected(s.error());
        }
        params.front() = header{};
    }
    out.protected_ = std::move(prot);
    out.encoded_protected_ = base64url::encode(std::string_view(out.protected_.to_json().dump()));
    out.shared_ = options.shared_unprotected;

    // The producer understands its own critical extensions.
    const auto own = out.protected_.crit();
    const extension_set understood(own.begin(), own.end());
    for (size_t i = 0; i < recipients.size(); ++i)
        if (auto a = out.add_recipient(std::move(params[i]), std::move(encrypted_keys[i]), {recipients[i].alg},
                                       {enc}, understood);
            !a)
            return jose::unexpected(a.error());

    if (!options.aad.empty()) {
        out.aad_ = options.aad;
        out.encoded_aad_ = base64url::encode(options.aad);
    }

    secure_bytes compressed;
    std::span<const uint8_t> content = plaintext;
    if (options.compress) {
        auto c = internal::deflate_raw(plaintext);
        if (!c) return jose::unexpected(c.error());
        compressed = std::move(*c);
        content = compressed;
    }

    auto iv = generate_iv(enc);
    if (!iv) return jose::unexpected(iv.error());
    auto sealed = jose::encrypt(enc, cek, *iv, content, out.authenticated_data());
    if (!sealed) return jose::unexpected(sealed.error());
    out.iv_.assign(iv->begin(), iv->end());
    out.ciphertext_.assign(sealed->ciphertext.begin(), sealed->ciphertext.end());
    out.tag_.assign(sealed->tag.begin(), sealed->tag.end());
    return out;
}

auto jwe::add_recipient(header per_recipient, std::vector<uint8_t> encrypted_key,
                        const std::vector<key_algorithm>& algorithms,
                        const std::vector<content_encryption>& encryptions, const extension_set& understood)
    -> expected<void> {
    auto joined = join_headers(header_context::jwe, protected_, shared_, per_recipient, understood);
    if (!joined) return jose::unexpected(joined.error());

    const auto alg_name = *joined->alg(); // join_headers requires "alg" and "enc"
    auto alg = parse_key_algorithm(alg_name);
    if (!alg)
        return make_error(errc::unsupported_algorithm, "unsupported JWE algorithm \"" + std::string(alg_name) + "\"");
    if (std::find(algorithms.begin(), algorithms.end(), *alg) == algorithms.end())
        return make_error(errc::algorithm_mismatch,
                          "JWE algorithm \"" + std::string(alg_name) + "\" is not in the allowed list");

    const auto enc_name = *joined->enc();
    auto enc = parse_content_encryption(enc_name);
    if (!enc)
        return make_error(errc::unsupported_algorithm,
                          "unsupported JWE content encryption \"" + std::string(enc_name) + "\"");
    if (std::find(encryptions.begin(), encryptions.end(), *enc) == encryptions.end())
        return make_error(errc::algorithm_mismatch,
                          "JWE content encryption \"" + std::string(enc_name) + "\" is not in the allowed list");
    if (recipients_.empty())
        enc_ = *enc;
    else if (*enc != enc_)
        return make_error(errc::invalid_header, "JWE recipients disagree on \"enc\"");

    if (auto zip = joined->zip(); zip && *zip != "DEF")
        return make_error(errc::unsupported_algorithm, "unsupported JWE compression \"" + std::string(*zip) + "\"");

    // RFC 7516 §5.2 step 10.
    const auto f = family_of(*alg);
    if ((f == family::dir || f == family::ecdh_direct) && !encrypted_key.empty())
        return bad_token("JWE encrypted key must be empty for " + std::string(alg_name));

    recipients_.push_back(jwe_recipient_info{
        .alg = *alg,
        .unprotected_header = std::move(per_recipient),
        .joined = std::move(*joined),
        .encrypted_key = std::move(encrypted_key),
    });
    return {};
}

auto jwe::authenticated_data() const -> std::vector<uint8_t> {
    // RFC 7516 §5.1 steps 14-15: ASCII(BASE64URL(protected)) [|| '.' || BASE64URL(aad)]
    std::vector<uint8_t> aad(encoded_protected_.begin(), encoded_protected_.end());
    if (encoded_aad_) {
        aad.push_back('.');
        aad.insert(aad.end(), encoded_aad_->begin(), encoded_aad_->end());
    }
    return aad;
}

// ===========================================================================
// Parsing
// ===========================================================================

namespace {

auto require_algorithms(const std::vector<key_algorithm>& algorithms,
                        const std::vector<content_encryption>& encryptions) -> expected<void> {
    if (algorithms.empty() || encryptions.empty())
        return bad_argument("JWE parsing needs non-empty lists of allowed algorithms and encryptions");
    return {};
}

} // namespace

auto jwe::parse(std::string_view input, const std::vector<key_algorithm>& algorithms,
                const std::vector<content_encryption>& encryptions, const extension_set& understood)
    -> expected<jwe> {
    return first_non_space(input) == '{' ? parse_json(input, algorithms, encryptions, understood)
                                         : parse_compact(input, algorithms, encryptions, understood);
}

auto jwe::parse_compact(std::string_view input, const std::vector<key_algorithm>& algorithms,
                        const std::vector<content_encryption>& encryptions, const extension_set& understood)
    -> expected<jwe> {
    if (auto r = require_algorithms(algorithms, encryptions); !r) return jose::unexpected(r.error());
    input = internal::trim_compact(input);

    std::array<std::string_view, 5> parts;
    size_t start = 0;
    for (size_t i = 0; i < parts.size(); ++i) {
        const size_t dot = input.find('.', start);
        if ((i < parts.size() - 1) == (dot == std::string_view::npos))
            return bad_token("JWE compact serialization must have exactly five parts");
        parts[i] = input.substr(start, i < parts.size() - 1 ? dot - start : std::string_view::npos);
        start = dot + 1;
    }
    if (parts[0].empty()) return bad_token("JWE protected header is empty");

    jwe out;
    auto prot = header::from_base64url(parts[0]);
    if (!prot) return jose::unexpected(prot.error());
    out.protected_ = std::move(*prot);
    out.encoded_protected_ = std::string(parts[0]);

    auto ek = decode_b64u(parts[1], "encrypted key");
    if (!ek) return jose::unexpected(ek.error());
    if (auto r = out.add_recipient({}, std::move(*ek), algorithms, encryptions, understood); !r)
        return jose::unexpected(r.error());

    std::array<std::pair<std::vector<uint8_t>*, const char*>, 3> fields{
        {{&out.iv_, "initialization vector"}, {&out.ciphertext_, "ciphertext"}, {&out.tag_, "tag"}}};
    for (size_t i = 0; i < fields.size(); ++i) {
        auto v = decode_b64u(parts[i + 2], fields[i].second);
        if (!v) return jose::unexpected(v.error());
        *fields[i].first = std::move(*v);
    }

    if (out.iv_.size() != iv_byte_size(out.enc_))
        return make_error(errc::invalid_iv, "JWE initialization vector has the wrong length");
    if (out.tag_.size() != tag_byte_size(out.enc_))
        return make_error(errc::invalid_tag, "JWE authentication tag has the wrong length");
    return out;
}

auto jwe::parse_json(std::string_view input, const std::vector<key_algorithm>& algorithms,
                     const std::vector<content_encryption>& encryptions, const extension_set& understood)
    -> expected<jwe> {
    if (auto r = require_algorithms(algorithms, encryptions); !r) return jose::unexpected(r.error());
    auto j = internal::parse_json_strict(input, "JWE");
    if (!j) return jose::unexpected(j.error());
    return from_json_value(*j, algorithms, encryptions, understood);
}

auto jwe::from_json_value(const json& j, const std::vector<key_algorithm>& algorithms,
                          const std::vector<content_encryption>& encryptions, const extension_set& understood)
    -> expected<jwe> {
    if (!j.is_object()) return bad_token("JWE JSON serialization must be an object");
    const auto member = [](const json& obj, const char* name) -> const json* {
        auto it = obj.find(name);
        return it == obj.end() ? nullptr : &*it;
    };
    const auto string_member = [&](const json& obj, const char* name, bool required)
        -> expected<const std::string*> {
        const json* v = member(obj, name);
        if (v == nullptr) {
            if (required) return bad_token(std::string("JWE is missing \"") + name + "\"");
            return static_cast<const std::string*>(nullptr);
        }
        if (!v->is_string()) return bad_token(std::string("JWE \"") + name + "\" must be a string");
        return &v->get_ref<const std::string&>();
    };
    const auto header_member = [&](const json& obj, const char* name) -> expected<header> {
        const json* v = member(obj, name);
        if (v == nullptr) return header{};
        if (!v->is_object()) return bad_token(std::string("JWE \"") + name + "\" must be a JSON object");
        return header::from_json(*v);
    };

    jwe out;

    auto prot = string_member(j, "protected", false);
    if (!prot) return jose::unexpected(prot.error());
    if (*prot != nullptr) {
        // RFC 7516 §7.2.1: omitted when empty.
        if ((*prot)->empty()) return bad_token("JWE protected header is empty");
        auto h = header::from_base64url(**prot);
        if (!h) return jose::unexpected(h.error());
        out.protected_ = std::move(*h);
        out.encoded_protected_ = **prot;
    }

    auto shared = header_member(j, "unprotected");
    if (!shared) return jose::unexpected(shared.error());
    out.shared_ = std::move(*shared);

    auto aad = string_member(j, "aad", false);
    if (!aad) return jose::unexpected(aad.error());
    if (*aad != nullptr) {
        auto bytes = decode_b64u(**aad, "aad");
        if (!bytes) return jose::unexpected(bytes.error());
        out.aad_ = std::move(*bytes);
        out.encoded_aad_ = **aad;
    }

    // Recipients: {"header"?, "encrypted_key"?} each.
    std::vector<const json*> entries;
    if (const json* recipients = member(j, "recipients")) {
        if (!recipients->is_array() || recipients->empty())
            return bad_token("JWE \"recipients\" must be a non-empty array");
        if (recipients->size() > max_recipients)
            return bad_token("JWE has " + std::to_string(recipients->size()) + " recipients; at most " +
                             std::to_string(max_recipients) + " are accepted");
        // go-jose v4's FullSerialize leaves a copy of the first recipient's
        // "encrypted_key" at the top level of general JSON. That exact copy
        // is ignored (it isn't authenticated and nothing reads it); any
        // other mix of general and flattened members is rejected.
        const json* stray_key = member(j, "encrypted_key");
        const json* first_key = (*recipients)[0].is_object() ? member((*recipients)[0], "encrypted_key") : nullptr;
        const bool go_jose_copy = stray_key && first_key && *stray_key == *first_key;
        if (member(j, "header") || (stray_key && !go_jose_copy))
            return bad_token("JWE JSON mixes general and flattened serialization members");
        for (const auto& r : *recipients) {
            if (!r.is_object()) return bad_token("JWE \"recipients\" entries must be objects");
            entries.push_back(&r);
        }
    } else {
        entries.push_back(&j);
    }
    for (const json* e : entries) {
        auto per = header_member(*e, "header");
        if (!per) return jose::unexpected(per.error());
        auto ek_text = string_member(*e, "encrypted_key", false);
        if (!ek_text) return jose::unexpected(ek_text.error());
        std::vector<uint8_t> ek;
        if (*ek_text != nullptr) {
            auto v = decode_b64u(**ek_text, "encrypted key");
            if (!v) return jose::unexpected(v.error());
            ek = std::move(*v);
        }
        if (auto r = out.add_recipient(std::move(*per), std::move(ek), algorithms, encryptions, understood); !r)
            return jose::unexpected(r.error());
    }

    std::array<std::pair<std::vector<uint8_t>*, const char*>, 3> fields{
        {{&out.iv_, "iv"}, {&out.ciphertext_, "ciphertext"}, {&out.tag_, "tag"}}};
    for (const auto& [field, name] : fields) {
        auto text = string_member(j, name, true);
        if (!text) return jose::unexpected(text.error());
        auto v = decode_b64u(**text, name);
        if (!v) return jose::unexpected(v.error());
        *field = std::move(*v);
    }

    if (out.iv_.size() != iv_byte_size(out.enc_))
        return make_error(errc::invalid_iv, "JWE initialization vector has the wrong length");
    if (out.tag_.size() != tag_byte_size(out.enc_))
        return make_error(errc::invalid_tag, "JWE authentication tag has the wrong length");
    return out;
}

// ===========================================================================
// Decrypting
// ===========================================================================

auto jwe::recover_cek(const jwe_recipient_info& r, const jwk& key, const jwe_decrypt_options& options,
                      pbes2_budget& budget) const -> expected<secure_bytes> {
    // Key selection problems are reported as such; they reveal nothing
    // about the ciphertext.
    if (auto c = check_key(r.alg, enc_, key, false); !c) return jose::unexpected(c.error());
    const auto f = family_of(r.alg);
    if ((f == family::rsa || f == family::ecdh_direct || f == family::ecdh_kw) && !key.is_private())
        return make_error(errc::invalid_key, "decrypting with " + std::string(to_string(r.alg)) +
                                                 " requires a private key");

    const size_t cek_len = cek_byte_size(enc_);
    const auto& h = r.joined;
    expected<secure_bytes> cek = decryption_failed();

    switch (f) {
    case family::rsa:
        cek = rsa_decrypt_key(r.alg, key.pkey(), r.encrypted_key, cek_len, options.legacy);
        if (!cek && cek.error().code == errc::legacy_algorithm_disabled) return cek;
        break;
    case family::aes_kw:
        cek = aes_key_unwrap(r.alg, key.oct(), r.encrypted_key);
        break;
    case family::aes_gcm_kw: {
        const auto iv = h.iv();
        const auto tag = h.tag();
        if (!iv || !tag) return make_error(errc::invalid_header, "AES-GCM key wrap needs \"iv\" and \"tag\"");
        if (iv->size() != 12 || tag->size() != 16)
            return make_error(errc::invalid_header, "AES-GCM key wrap \"iv\" must be 12 octets and \"tag\" 16");
        cek = aes_gcm_key_unwrap(r.alg, key.oct(), r.encrypted_key, *iv, *tag);
        break;
    }
    case family::pbes2: {
        const auto p2s = h.p2s();
        const auto p2c = h.p2c();
        if (!p2s || !p2c) return make_error(errc::invalid_header, "PBES2 needs \"p2s\" and \"p2c\"");
        if (p2s->size() < 8) return make_error(errc::invalid_header, "PBES2 \"p2s\" must be at least 8 octets");
        // Bounds the work an attacker can make us do (see pbes2.hpp).
        if (*p2c < 1000 || *p2c > 1000000)
            return make_error(errc::invalid_header, "PBES2 \"p2c\" must be between 1000 and 1000000");
        // The total across this call's attempts (jwe_decrypt_options).
        if (static_cast<std::uint64_t>(*p2c) > budget.left) {
            budget.exhausted = true;
            return make_error(errc::invalid_header,
                              "PBES2 work limit reached: \"p2c\" " + std::to_string(*p2c) + " is more than the " +
                                  std::to_string(budget.left) + " iterations left of max_pbes2_iterations");
        }
        budget.left -= static_cast<std::uint64_t>(*p2c);
        cek = pbes2_key_unwrap(r.alg, as_view(key.oct()), r.encrypted_key, *p2s, static_cast<int>(*p2c));
        break;
    }
    case family::ecdh_direct:
    case family::ecdh_kw: {
        const auto& epk = h.epk();
        if (!epk) return make_error(errc::invalid_header, "ECDH-ES needs \"epk\"");
        if (!epk_matches(r.alg, h, key)) return make_error(errc::invalid_header, "\"epk\" is not on the key's curve");
        const bool direct = f == family::ecdh_direct;
        const auto kw = ecdh_wrap_alg(r.alg);
        auto agreed = ecdh_derive_key_from_epk(key.pkey(), epk->pkey(),
                                               direct ? to_string(enc_) : to_string(r.alg),
                                               bytes_view(h.apu()), bytes_view(h.apv()),
                                               direct ? cek_len * 8 : wrap_key_bits(kw));
        if (!agreed) return decryption_failed();
        cek = direct ? std::move(agreed) : aes_key_unwrap(kw, *agreed, r.encrypted_key);
        break;
    }
    case family::dir:
        cek = secure_bytes(key.oct().begin(), key.oct().end());
        break;
    }

    if (!cek || cek->size() != cek_len) return decryption_failed();
    return cek;
}

namespace {

// Checks before an opaque decrypter (sync or async) is called.
auto check_opaque_recipient(const std::vector<key_algorithm>& algs, key_algorithm alg,
                            const jwe_decrypt_options& options) -> expected<void> {
    if (std::find(algs.begin(), algs.end(), alg) == algs.end())
        return make_error(errc::algorithm_mismatch,
                          "the opaque decrypter does not support " + std::string(to_string(alg)));
    if (alg == key_algorithm::RSA1_5 && !options.legacy.allow_rsa1_5)
        return make_error(errc::legacy_algorithm_disabled,
                          "RSA1_5 is disabled (padding-oracle risk); set legacy_options::allow_rsa1_5 to opt in");
    return {};
}

// An opaque decrypter's result, normalized (see opaque.hpp).
auto finish_opaque_cek(expected<secure_bytes> cek, content_encryption enc) -> expected<secure_bytes> {
    if (!cek) {
        // An unreachable backend says nothing about the ciphertext.
        if (cek.error().code == errc::key_unavailable) return cek;
        return decryption_failed();
    }
    if (cek->size() != cek_byte_size(enc)) return decryption_failed();
    return cek;
}

} // namespace

auto jwe::recover_cek(const jwe_recipient_info& r, opaque_key_decrypter& decrypter,
                      const jwe_decrypt_options& options) const -> expected<secure_bytes> {
    if (auto c = check_opaque_recipient(decrypter.algorithms(), r.alg, options); !c)
        return jose::unexpected(c.error());
    return finish_opaque_cek(decrypter.decrypt_key(r.encrypted_key, r.alg, enc_, r.joined), enc_);
}

auto jwe::recover_cek_async(const jwe_recipient_info& r, async_opaque_key_decrypter& decrypter,
                            const jwe_decrypt_options& options) const -> task<expected<secure_bytes>> {
    if (auto c = check_opaque_recipient(decrypter.algorithms(), r.alg, options); !c)
        co_return jose::unexpected(c.error());
    co_return finish_opaque_cek(co_await decrypter.decrypt_key(r.encrypted_key, r.alg, enc_, r.joined), enc_);
}

auto jwe::open(const jwe_recipient_info& r, expected<secure_bytes> cek, const jwe_decrypt_options& options) const
    -> expected<secure_bytes> {
    if (!cek) return jose::unexpected(cek.error());

    auto plaintext = jose::decrypt(enc_, *cek, iv_, ciphertext_, authenticated_data(), tag_);
    if (!plaintext) return decryption_failed();

    if (!r.joined.zip()) return plaintext;
    // Authenticated already, so a decompression error is not an oracle.
    const size_t limit = options.max_decompressed_size != 0
                             ? options.max_decompressed_size
                             : std::max<size_t>(250 * 1024, 10 * ciphertext_.size());
    return internal::inflate_raw(*plaintext, limit);
}

auto jwe::decrypt(const jwk& key, const jwe_decrypt_options& options) const -> expected<secure_bytes> {
    if (recipients_.size() != 1)
        return bad_argument("JWE has " + std::to_string(recipients_.size()) + " recipients; use decrypt_multi");
    pbes2_budget budget{options.max_pbes2_iterations};
    return open(recipients_.front(), recover_cek(recipients_.front(), key, options, budget), options);
}

auto jwe::decrypt(const jwk_set& keys, const jwe_decrypt_options& options) const -> expected<secure_bytes> {
    if (recipients_.size() != 1)
        return bad_argument("JWE has " + std::to_string(recipients_.size()) + " recipients; use decrypt_multi");
    const auto& r = recipients_.front();
    const auto kid = r.joined.kid();
    if (!kid) return make_error(errc::invalid_key, "JWE has no \"kid\" to select a key from the set");
    const auto candidates = keys.find_all(*kid);
    if (candidates.empty())
        return make_error(errc::invalid_key, "no key in the set has \"kid\":\"" + std::string(*kid) + "\"");

    expected<secure_bytes> last = decryption_failed();
    pbes2_budget budget{options.max_pbes2_iterations};
    for (const jwk& key : candidates) {
        last = open(r, recover_cek(r, key, options, budget), options);
        if (last || budget.exhausted) return last;
    }
    return last;
}

auto jwe::decrypt_multi(const jwk& key, const jwe_decrypt_options& options) const -> expected<decrypted> {
    bool attempted = false;
    pbes2_budget budget{options.max_pbes2_iterations};
    for (size_t i = 0; i < recipients_.size(); ++i) {
        const auto& r = recipients_[i];
        if (!check_key(r.alg, enc_, key, false) || !epk_matches(r.alg, r.joined, key)) continue;
        attempted = true;
        auto plaintext = open(r, recover_cek(r, key, options, budget), options);
        if (plaintext) return decrypted{i, std::move(*plaintext)};
        // Errors other than a failed decryption (e.g. RSA1_5 without the
        // opt-in) are the caller's to see.
        if (plaintext.error().code != errc::decryption_failed) return jose::unexpected(plaintext.error());
    }
    if (!attempted) return make_error(errc::algorithm_mismatch, "the key suits none of the JWE recipients");
    return decryption_failed();
}

auto jwe::decrypt(opaque_key_decrypter& decrypter, const jwe_decrypt_options& options) const
    -> expected<secure_bytes> {
    if (recipients_.size() != 1)
        return bad_argument("JWE has " + std::to_string(recipients_.size()) + " recipients; use decrypt_multi");
    const auto& r = recipients_.front();
    return open(r, recover_cek(r, decrypter, options), options);
}

auto jwe::decrypt_async(async_opaque_key_decrypter& decrypter, jwe_decrypt_options options) const
    -> task<expected<secure_bytes>> {
    if (recipients_.size() != 1)
        co_return bad_argument("JWE has " + std::to_string(recipients_.size()) + " recipients; use decrypt_multi");
    const auto& r = recipients_.front();
    co_return open(r, co_await recover_cek_async(r, decrypter, options), options);
}

auto jwe::decrypt_multi_async(async_opaque_key_decrypter& decrypter, jwe_decrypt_options options) const
    -> task<expected<decrypted>> {
    const auto algs = decrypter.algorithms();
    bool attempted = false;
    for (size_t i = 0; i < recipients_.size(); ++i) {
        const auto& r = recipients_[i];
        if (std::find(algs.begin(), algs.end(), r.alg) == algs.end()) continue;
        attempted = true;
        auto plaintext = open(r, co_await recover_cek_async(r, decrypter, options), options);
        if (plaintext) co_return decrypted{i, std::move(*plaintext)};
        if (plaintext.error().code != errc::decryption_failed) co_return jose::unexpected(plaintext.error());
    }
    if (!attempted) co_return make_error(errc::algorithm_mismatch, "the decrypter suits none of the JWE recipients");
    co_return decryption_failed();
}

auto jwe::decrypt_multi(opaque_key_decrypter& decrypter, const jwe_decrypt_options& options) const
    -> expected<decrypted> {
    const auto algs = decrypter.algorithms();
    bool attempted = false;
    for (size_t i = 0; i < recipients_.size(); ++i) {
        const auto& r = recipients_[i];
        if (std::find(algs.begin(), algs.end(), r.alg) == algs.end()) continue;
        attempted = true;
        auto plaintext = open(r, recover_cek(r, decrypter, options), options);
        if (plaintext) return decrypted{i, std::move(*plaintext)};
        if (plaintext.error().code != errc::decryption_failed) return jose::unexpected(plaintext.error());
    }
    if (!attempted) return make_error(errc::algorithm_mismatch, "the decrypter suits none of the JWE recipients");
    return decryption_failed();
}

// ===========================================================================
// Serializing
// ===========================================================================

auto jwe::compact() const -> expected<std::string> {
    if (recipients_.size() != 1)
        return bad_argument("compact serialization needs exactly one recipient, not " +
                            std::to_string(recipients_.size()));
    if (!shared_.empty() || !recipients_.front().unprotected_header.empty())
        return bad_argument("compact serialization cannot carry unprotected headers");
    if (encoded_aad_) return bad_argument("compact serialization cannot carry \"aad\"");
    if (encoded_protected_.empty()) return bad_argument("compact serialization needs a protected header");
    return encoded_protected_ + "." + base64url::encode(recipients_.front().encrypted_key) + "." +
           base64url::encode(iv_) + "." + base64url::encode(ciphertext_) + "." + base64url::encode(tag_);
}

auto jwe::to_json(jwe_json_format format) const -> expected<json> {
    if (format == jwe_json_format::flattened && recipients_.size() != 1)
        return bad_argument("flattened JSON serialization needs exactly one recipient");

    auto recipient = [](const jwe_recipient_info& r, json& into) {
        if (!r.unprotected_header.empty()) into["header"] = r.unprotected_header.to_json();
        if (!r.encrypted_key.empty()) into["encrypted_key"] = base64url::encode(r.encrypted_key);
    };

    json out = json::object();
    if (!encoded_protected_.empty()) out["protected"] = encoded_protected_;
    if (!shared_.empty()) out["unprotected"] = shared_.to_json();
    if (encoded_aad_) out["aad"] = *encoded_aad_;
    if (format == jwe_json_format::flattened) {
        recipient(recipients_.front(), out);
    } else {
        json list = json::array();
        for (const auto& r : recipients_) {
            json e = json::object();
            recipient(r, e);
            list.push_back(std::move(e));
        }
        out["recipients"] = std::move(list);
    }
    out["iv"] = base64url::encode(iv_);
    out["ciphertext"] = base64url::encode(ciphertext_);
    out["tag"] = base64url::encode(tag_);
    return out;
}

auto jwe::to_json_string(jwe_json_format format) const -> expected<std::string> {
    auto j = to_json(format);
    if (!j) return jose::unexpected(j.error());
    return j->dump();
}

} // namespace jose
