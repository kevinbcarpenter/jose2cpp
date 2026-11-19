#pragma once

/// @file
/// JSON Web Signature (RFC 7515) and the unencoded payload option (RFC 7797).
///
/// Signing:
/// @code{.cpp}
/// auto key = jose::jwk::generate_ec(jose::ec_curve::P256).value();
/// auto signed_ = jose::jws::sign(payload, {jose::signing_algorithm::ES256, key});
/// auto token = signed_->compact();                 // or to_json_string()
/// @endcode
///
/// Verifying: parsing requires the list of algorithms the caller accepts
/// (the go-jose v4 pattern), so a token can never choose its own algorithm.
/// @code{.cpp}
/// auto parsed = jose::jws::parse(token, {jose::signing_algorithm::ES256});
/// auto payload = parsed->verify(public_key);       // expected<std::vector<uint8_t>>
/// @endcode
///
/// The "none" algorithm is not supported (PLAN.md §7). Keys embedded in a
/// token ("jwk", "x5c", "jku") are never used for verification implicitly.

#include "jose/algorithm.hpp"
#include "jose/async.hpp"
#include "jose/error.hpp"
#include "jose/header.hpp"
#include "jose/jwk.hpp"
#include "jose/opaque.hpp"

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace jose {

/// A signing key: a private asymmetric key or an oct key for HS*, an
/// opaque signer (HSM, KMS; opaque.hpp), or an async one (async.hpp, which
/// only jws::sign_async accepts).
using signing_key =
    std::variant<jwk, std::shared_ptr<opaque_signer>, std::shared_ptr<async_opaque_signer>>;

/// One signature to produce.
struct jws_signer {
    signing_algorithm alg; ///< the signature algorithm
    signing_key key;       ///< the key that signs with it

    /// Extra protected parameters for this signature ("typ", "cty",
    /// application extensions with "crit", ...). "alg" is filled in; if
    /// given, it must match `alg`.
    header protected_header = {};
    /// Extra unprotected parameters. They can't include "alg", and a JWS
    /// with any can only be serialized as JSON.
    header unprotected_header = {};
};

/// Options for jws::sign.
struct jws_sign_options {
    /// false: RFC 7797 unencoded payload. Adds "b64":false and lists "b64"
    /// in "crit" for every signature.
    bool b64 = true;
    /// Put the signer's public key in the protected "jwk" header.
    bool embed_jwk = false;
    /// Put the key's "kid" in the protected header, unless a header part
    /// already has one.
    bool include_kid = true;
};

/// One signature of a JWS, as signed or parsed.
struct jws_signature {
    signing_algorithm alg;           ///< the signature's "alg"
    header protected_header;         ///< the integrity-protected part
    header unprotected_header;       ///< the JSON "header" member, if any
    header joined;                   ///< both parts combined (RFC 7515 §7.2.1)
    std::vector<uint8_t> signature;  ///< the signature octets (R || S for ES*)
    /// The protected header exactly as transmitted (part of the signing
    /// input); empty if this signature has no protected header.
    std::string encoded_protected;
};

/// Which JSON serialization jws::to_json writes (RFC 7515 §7.2).
enum class jws_json_format {
    general,   ///< {"payload", "signatures":[...]}: any number of signatures
    flattened, ///< {"payload", "protected", "header", "signature"}: exactly one
};

/// A JWS: a payload and one or more signatures over it. Build one with
/// sign() or parse(); check it with verify().
///
/// Parsing: `algorithms` must not be empty, and every signature's "alg"
/// must be in it (else errc::algorithm_mismatch; "none" and unknown values
/// are errc::unsupported_algorithm). `understood` lists the application's
/// critical header extensions (PLAN.md §Critical Header Extensions).
/// Parsing checks structure and headers only; call verify() next.
///
/// Verifying: each verify function checks that the key suits the
/// signature's "alg" (jwk::check_algorithm) and permits "verify"
/// (jwk::check_operation), then verifies. A bad signature is
/// errc::invalid_signature.
class jws {
public:
    /// The most signatures a JWS may have, when parsed or produced, as
    /// go-jose's MaxSignatures: each one can mean a verification. More is
    /// errc::invalid_token when parsing and errc::invalid_argument when
    /// signing.
    static constexpr std::size_t max_signatures = 32;

    // --- Producing ---

    /// Signs `payload` with one signer. The result can be serialized
    /// compact or as JSON.
    ///@{
    static auto sign(std::span<const uint8_t> payload, const jws_signer& signer,
                     const jws_sign_options& options = {}) -> expected<jws>;
    static auto sign(std::string_view payload, const jws_signer& signer,
                     const jws_sign_options& options = {}) -> expected<jws>;
    ///@}
    /// Several signatures over one payload (JSON serialization only).
    static auto sign(std::span<const uint8_t> payload, std::span<const jws_signer> signers,
                     const jws_sign_options& options = {}) -> expected<jws>;

    /// As sign(), for signers that include an async_opaque_signer (local and
    /// sync opaque signers work too). Signers run one after another. The
    /// arguments are copied into the task, so temporaries are safe.
    ///@{
    static auto sign_async(std::vector<uint8_t> payload, std::vector<jws_signer> signers,
                           jws_sign_options options = {}) -> task<expected<jws>>;
    static auto sign_async(std::span<const uint8_t> payload, const jws_signer& signer,
                           const jws_sign_options& options = {}) -> task<expected<jws>>;
    static auto sign_async(std::string_view payload, const jws_signer& signer,
                           const jws_sign_options& options = {}) -> task<expected<jws>>;
    ///@}

    // --- Parsing (rules in the class description) ---

    /// Compact or JSON, chosen by the first non-whitespace character.
    static auto parse(std::string_view input, const std::vector<signing_algorithm>& algorithms,
                      const extension_set& understood = {}) -> expected<jws>;
    /// Leading and trailing whitespace (space, tab, CR, LF) is ignored, so a
    /// token with a trailing newline parses. Whitespace inside a base64url
    /// part is refused (errc::invalid_base64 when that part is decoded); an
    /// unencoded (b64=false) payload is taken as is, apart from '.'. See
    /// PLAN.md §Compact whitespace for how this differs from go-jose.
    static auto parse_compact(std::string_view input, const std::vector<signing_algorithm>& algorithms,
                              const extension_set& understood = {}) -> expected<jws>;
    /// The general or flattened JSON serialization (RFC 7515 §7.2).
    static auto parse_json(std::string_view input, const std::vector<signing_algorithm>& algorithms,
                           const extension_set& understood = {}) -> expected<jws>;

    /// A JWS with a detached payload (RFC 7515 Appendix F): the compact
    /// payload part must be empty, or the JSON "payload" member absent.
    static auto parse_detached(std::string_view input, std::span<const uint8_t> payload,
                               const std::vector<signing_algorithm>& algorithms,
                               const extension_set& understood = {}) -> expected<jws>;

    // --- Verifying (rules in the class description) ---

    /// Exactly one signature.
    [[nodiscard]] auto verify(const jwk& key) const -> expected<std::vector<uint8_t>>;
    /// Exactly one signature, which must carry a "kid"; every key in the set
    /// with that "kid" is tried.
    [[nodiscard]] auto verify(const jwk_set& keys) const -> expected<std::vector<uint8_t>>;

    /// What verify_multi returns.
    struct verified {
        size_t index;                 ///< which signature verified
        std::vector<uint8_t> payload; ///< the verified payload
    };
    /// Any number of signatures; succeeds on the first that `key` verifies.
    [[nodiscard]] auto verify_multi(const jwk& key) const -> expected<verified>;

    /// With an opaque verifier (opaque.hpp). The signature's "alg" must be
    /// one of verifier.algorithms() (else errc::algorithm_mismatch).
    /// verify() needs exactly one signature; verify_multi() succeeds on the
    /// first signature the verifier accepts.
    ///@{
    [[nodiscard]] auto verify(opaque_verifier& verifier) const -> expected<std::vector<uint8_t>>;
    [[nodiscard]] auto verify_multi(opaque_verifier& verifier) const -> expected<verified>;
    ///@}

    /// With an async opaque verifier (async.hpp). This jws and the verifier
    /// must outlive the returned task. Signatures are tried one after
    /// another, as for the sync versions.
    ///@{
    [[nodiscard]] auto verify_async(async_opaque_verifier& verifier) const -> task<expected<std::vector<uint8_t>>>;
    [[nodiscard]] auto verify_multi_async(async_opaque_verifier& verifier) const -> task<expected<verified>>;
    ///@}

    // --- Inspection ---

    /// The signatures, in order. Never empty.
    [[nodiscard]] auto signatures() const noexcept -> std::span<const jws_signature> { return signatures_; }
    /// The payload, NOT verified. Only for choosing a key before verify().
    [[nodiscard]] auto unsafe_payload() const noexcept -> std::span<const uint8_t> { return payload_; }
    /// false for RFC 7797 unencoded payloads.
    [[nodiscard]] auto b64() const noexcept -> bool { return b64_; }

    // --- Serializing ---

    /// One signature with no unprotected header. With b64=false the
    /// payload must not contain '.' (RFC 7797 §5.2); use compact_detached().
    [[nodiscard]] auto compact() const -> expected<std::string>;
    /// "<protected>..<signature>": the payload is sent separately.
    [[nodiscard]] auto compact_detached() const -> expected<std::string>;

    /// The JSON serialization, as a value or as compact text. Flattened
    /// needs exactly one signature; `detached` leaves out "payload". With
    /// b64=false the payload must be valid UTF-8 to appear in JSON.
    ///@{
    [[nodiscard]] auto to_json(jws_json_format format = jws_json_format::general,
                               bool detached = false) const -> expected<nlohmann::json>;
    [[nodiscard]] auto to_json_string(jws_json_format format = jws_json_format::general,
                                      bool detached = false) const -> expected<std::string>;
    ///@}

private:
    jws() = default;

    static auto from_json_value(const nlohmann::json& j, const std::vector<signing_algorithm>& algorithms,
                                const extension_set& understood, const std::span<const uint8_t>* detached)
        -> expected<jws>;
    auto set_detached_payload(std::span<const uint8_t> payload) -> void;
    auto signing_input(const jws_signature& sig) const -> std::vector<uint8_t>;
    auto verify_one(const jws_signature& sig, const jwk& key) const -> expected<void>;
    auto verify_one(const jws_signature& sig, opaque_verifier& verifier) const -> expected<void>;
    auto verify_one_async(const jws_signature& sig, async_opaque_verifier& verifier) const -> task<expected<void>>;
    /// Starts a JWS over `payload`, before any signature is added.
    static auto unsigned_jws(std::span<const uint8_t> payload, bool b64) -> jws;

    std::vector<jws_signature> signatures_;
    std::vector<uint8_t> payload_;
    /// The payload as it appears in the signing input: base64url as
    /// transmitted (b64=true) or the raw octets (b64=false).
    std::string encoded_payload_;
    bool b64_ = true;
};

} // namespace jose
