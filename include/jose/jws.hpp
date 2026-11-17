#pragma once

// JSON Web Signature (RFC 7515) and the unencoded payload option (RFC 7797).
//
// Signing:
//   auto key = jose::jwk::generate_ec(jose::ec_curve::P256).value();
//   auto signed_ = jose::jws::sign(payload, {jose::signing_algorithm::ES256, key});
//   auto token = signed_->compact();                 // or to_json_string()
//
// Verifying: parsing requires the list of algorithms the caller accepts
// (the go-jose v4 pattern), so a token can never choose its own algorithm.
//   auto parsed = jose::jws::parse(token, {jose::signing_algorithm::ES256});
//   auto payload = parsed->verify(public_key);       // expected<std::vector<uint8_t>>
//
// The "none" algorithm is not supported (PLAN.md §7). Keys embedded in a
// token ("jwk", "x5c", "jku") are never used for verification implicitly.

#include "jose/algorithm.hpp"
#include "jose/error.hpp"
#include "jose/header.hpp"
#include "jose/jwk.hpp"

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace jose {

// One signature to produce.
struct jws_signer {
    signing_algorithm alg;
    jwk key; // a private asymmetric key, or an oct key for HS*

    // Extra parameters for this signature ("typ", "cty", application
    // extensions with "crit", ...). "alg" is filled in; if given, it must
    // match `alg`. The unprotected header can only be serialized as JSON.
    header protected_header = {};
    header unprotected_header = {};
};

struct jws_sign_options {
    // false: RFC 7797 unencoded payload. Adds "b64":false and lists "b64"
    // in "crit" for every signature.
    bool b64 = true;
    // Put the signer's public key in the protected "jwk" header.
    bool embed_jwk = false;
    // Put the key's "kid" in the protected header, unless a header part
    // already has one.
    bool include_kid = true;
};

// One signature of a JWS, as signed or parsed.
struct jws_signature {
    signing_algorithm alg;
    header protected_header;
    header unprotected_header;
    header joined; // both parts combined (RFC 7515 §7.2.1)
    std::vector<uint8_t> signature;
    // The protected header exactly as transmitted (part of the signing
    // input); empty if this signature has no protected header.
    std::string encoded_protected;
};

enum class jws_json_format {
    general,   // {"payload", "signatures":[...]}: any number of signatures
    flattened, // {"payload", "protected", "header", "signature"}: exactly one
};

class jws {
public:
    // --- Producing ---

    static auto sign(std::span<const uint8_t> payload, const jws_signer& signer,
                     const jws_sign_options& options = {}) -> expected<jws>;
    static auto sign(std::string_view payload, const jws_signer& signer,
                     const jws_sign_options& options = {}) -> expected<jws>;
    // Several signatures over one payload (JSON serialization only).
    static auto sign(std::span<const uint8_t> payload, std::span<const jws_signer> signers,
                     const jws_sign_options& options = {}) -> expected<jws>;

    // --- Parsing ---
    //
    // `algorithms` must not be empty: every signature's "alg" must be in it
    // (else errc::algorithm_mismatch; "none" and unknown values are
    // errc::unsupported_algorithm). `understood` lists the application's
    // critical header extensions (PLAN.md §Critical Header Extensions).
    // Parsing checks structure and headers only; call verify() next.

    // Compact or JSON, chosen by the first non-whitespace character.
    static auto parse(std::string_view input, const std::vector<signing_algorithm>& algorithms,
                      const extension_set& understood = {}) -> expected<jws>;
    static auto parse_compact(std::string_view input, const std::vector<signing_algorithm>& algorithms,
                              const extension_set& understood = {}) -> expected<jws>;
    static auto parse_json(std::string_view input, const std::vector<signing_algorithm>& algorithms,
                           const extension_set& understood = {}) -> expected<jws>;

    // A JWS with a detached payload (RFC 7515 Appendix F): the compact
    // payload part must be empty, or the JSON "payload" member absent.
    static auto parse_detached(std::string_view input, std::span<const uint8_t> payload,
                               const std::vector<signing_algorithm>& algorithms,
                               const extension_set& understood = {}) -> expected<jws>;

    // --- Verifying ---
    //
    // Each checks that the key suits the signature's "alg" and permits
    // "verify" (jwk::check_algorithm / check_operation), then verifies.
    // A bad signature is errc::invalid_signature.

    // Exactly one signature.
    [[nodiscard]] auto verify(const jwk& key) const -> expected<std::vector<uint8_t>>;
    // Exactly one signature, which must carry a "kid"; every key in the set
    // with that "kid" is tried.
    [[nodiscard]] auto verify(const jwk_set& keys) const -> expected<std::vector<uint8_t>>;

    struct verified {
        size_t index; // which signature verified
        std::vector<uint8_t> payload;
    };
    // Any number of signatures; succeeds on the first that `key` verifies.
    [[nodiscard]] auto verify_multi(const jwk& key) const -> expected<verified>;

    // --- Inspection ---

    [[nodiscard]] auto signatures() const noexcept -> std::span<const jws_signature> { return signatures_; }
    // The payload, NOT verified. Only for choosing a key before verify().
    [[nodiscard]] auto unsafe_payload() const noexcept -> std::span<const uint8_t> { return payload_; }
    // false for RFC 7797 unencoded payloads.
    [[nodiscard]] auto b64() const noexcept -> bool { return b64_; }

    // --- Serializing ---

    // One signature with no unprotected header. With b64=false the
    // payload must not contain '.' (RFC 7797 §5.2); use compact_detached().
    [[nodiscard]] auto compact() const -> expected<std::string>;
    // "<protected>..<signature>": the payload is sent separately.
    [[nodiscard]] auto compact_detached() const -> expected<std::string>;

    // With b64=false the payload must be valid UTF-8 to appear in JSON.
    [[nodiscard]] auto to_json(jws_json_format format = jws_json_format::general,
                               bool detached = false) const -> expected<nlohmann::json>;
    [[nodiscard]] auto to_json_string(jws_json_format format = jws_json_format::general,
                                      bool detached = false) const -> expected<std::string>;

private:
    jws() = default;

    static auto from_json_value(const nlohmann::json& j, const std::vector<signing_algorithm>& algorithms,
                                const extension_set& understood, const std::span<const uint8_t>* detached)
        -> expected<jws>;
    auto set_detached_payload(std::span<const uint8_t> payload) -> void;
    auto signing_input(const jws_signature& sig) const -> std::vector<uint8_t>;
    auto verify_one(const jws_signature& sig, const jwk& key) const -> expected<void>;

    std::vector<jws_signature> signatures_;
    std::vector<uint8_t> payload_;
    // The payload as it appears in the signing input: base64url as
    // transmitted (b64=true) or the raw octets (b64=false).
    std::string encoded_payload_;
    bool b64_ = true;
};

} // namespace jose
