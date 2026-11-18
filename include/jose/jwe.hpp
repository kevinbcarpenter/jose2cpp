#pragma once

// JSON Web Encryption (RFC 7516) with the RFC 7518 algorithms.
//
// Encrypting:
//   auto key = jose::jwk::generate_ec(jose::ec_curve::P256).value();
//   auto sealed = jose::jwe::encrypt(plaintext, jose::content_encryption::A256GCM,
//                                    {jose::key_algorithm::ECDH_ES_A256KW, key.public_key().value()});
//   auto token = sealed->compact();                    // or to_json_string()
//
// Decrypting: parsing requires the key-management and content-encryption
// algorithms the caller accepts (the go-jose v4 pattern).
//   auto parsed = jose::jwe::parse(token, {jose::key_algorithm::ECDH_ES_A256KW},
//                                  {jose::content_encryption::A256GCM});
//   auto plaintext = parsed->decrypt(key);             // expected<secure_bytes>
//
// RSA1_5 needs legacy_options{.allow_rsa1_5 = true} on both paths
// (PLAN.md §Legacy Algorithms).

#include "jose/algorithm.hpp"
#include "jose/async.hpp"
#include "jose/error.hpp"
#include "jose/header.hpp"
#include "jose/jwk.hpp"
#include "jose/opaque.hpp"
#include "jose/secure_bytes.hpp"

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace jose {

// One recipient to encrypt to.
struct jwe_recipient {
    key_algorithm alg;
    // RSA*/ECDH-ES*: the recipient's public key (a private key also works).
    // A*KW/A*GCMKW: the key-encryption key. dir: the CEK itself.
    // PBES2*: the password, as an oct key.
    jwk key;
    // Extra per-recipient parameters, e.g. "apu"/"apv" for ECDH-ES. With a
    // single recipient they go in the protected header (so the compact form
    // works); with several, in that recipient's unprotected header.
    header parameters = {};
    // PBES2 iteration count ("p2c"), 1000..1000000.
    int pbes2_count = 310000;
};

struct jwe_encrypt_options {
    // Shared parameters ("typ", "cty", application extensions with "crit").
    header protected_header = {};
    header shared_unprotected = {}; // JSON serializations only
    // RFC 7516 §5.1 step 14: extra authenticated data (JSON only).
    std::vector<uint8_t> aad = {};
    // Compress the plaintext with DEFLATE ("zip":"DEF").
    bool compress = false;
    // Put each recipient key's "kid" in its header, unless one is already set.
    bool include_kid = true;
    legacy_options legacy = {};
};

struct jwe_decrypt_options {
    legacy_options legacy = {};
    // Cap on decompressed ("zip":"DEF") plaintext; 0 means
    // max(250 KiB, 10 x the compressed size), as go-jose v4.
    size_t max_decompressed_size = 0;
    // The PBKDF2 iterations (the "p2c" of each PBES2 recipient) one decrypt
    // call with a jwk or jwk_set may spend in total, across every recipient
    // and key it tries; opaque decrypters do their own unwrap and aren't
    // counted. A token's "p2c" is chosen by whoever made it, so without a
    // total a JSON JWE listing many PBES2 recipients costs a full PBKDF2 run
    // for each. The default is the largest "p2c" accepted (1,000,000): one
    // attempt at that, or three at jose2cpp's default of 310,000, but only
    // one at go-jose's default of 600,000, so raise it if you expect tokens
    // with several PBES2 recipients. 0 refuses PBES2. Running out is
    // errc::invalid_header and ends the call: the remaining recipients
    // aren't tried.
    std::uint64_t max_pbes2_iterations = 1000000;
};

// One recipient of a JWE, as encrypted or parsed.
struct jwe_recipient_info {
    key_algorithm alg;
    header unprotected_header; // the per-recipient "header"
    header joined;             // protected + shared + per-recipient
    std::vector<uint8_t> encrypted_key;
};

enum class jwe_json_format {
    general,   // {"recipients":[...], ...}: any number of recipients
    flattened, // {"header", "encrypted_key", ...}: exactly one
};

class jwe {
public:
    // The most recipients a JWE may have, when parsed or produced, as
    // go-jose's MaxRecipients: each one can mean a key unwrap for the
    // decrypter. More is errc::invalid_token when parsing and
    // errc::invalid_argument when encrypting.
    static constexpr std::size_t max_recipients = 32;

    // --- Producing ---

    static auto encrypt(std::span<const uint8_t> plaintext, content_encryption enc,
                        const jwe_recipient& recipient, const jwe_encrypt_options& options = {})
        -> expected<jwe>;
    static auto encrypt(std::string_view plaintext, content_encryption enc, const jwe_recipient& recipient,
                        const jwe_encrypt_options& options = {}) -> expected<jwe>;
    // Several recipients (JSON serialization only). "dir" and "ECDH-ES"
    // fix the CEK, so they are single-recipient only.
    static auto encrypt(std::span<const uint8_t> plaintext, content_encryption enc,
                        std::span<const jwe_recipient> recipients, const jwe_encrypt_options& options = {})
        -> expected<jwe>;

    // --- Parsing ---
    //
    // Every recipient's "alg" must be in `algorithms` and "enc" in
    // `encryptions` (else errc::algorithm_mismatch; unknown values are
    // errc::unsupported_algorithm). Headers go through join_headers, so
    // "crit" is checked against `understood`. Parsing checks structure;
    // decrypt() does the cryptography.

    // Compact or JSON, chosen by the first non-whitespace character.
    static auto parse(std::string_view input, const std::vector<key_algorithm>& algorithms,
                      const std::vector<content_encryption>& encryptions, const extension_set& understood = {})
        -> expected<jwe>;
    // Leading and trailing whitespace (space, tab, CR, LF) is ignored, so a
    // token with a trailing newline parses. Whitespace inside it is refused
    // (errc::invalid_base64 when that part is decoded). See PLAN.md
    // §Compact whitespace for how this differs from go-jose.
    static auto parse_compact(std::string_view input, const std::vector<key_algorithm>& algorithms,
                              const std::vector<content_encryption>& encryptions,
                              const extension_set& understood = {}) -> expected<jwe>;
    static auto parse_json(std::string_view input, const std::vector<key_algorithm>& algorithms,
                           const std::vector<content_encryption>& encryptions,
                           const extension_set& understood = {}) -> expected<jwe>;

    // --- Decrypting ---
    //
    // The key must suit the recipient's "alg" (jwk::check_algorithm; for
    // "dir", the "enc") and permit the operation (jwk::check_operation:
    // "unwrapKey", "deriveKey" for ECDH-ES, "decrypt" for dir). Any
    // cryptographic failure is errc::decryption_failed.

    // Exactly one recipient.
    [[nodiscard]] auto decrypt(const jwk& key, const jwe_decrypt_options& options = {}) const
        -> expected<secure_bytes>;
    // Exactly one recipient, which must carry a "kid"; every key in the set
    // with that "kid" is tried.
    [[nodiscard]] auto decrypt(const jwk_set& keys, const jwe_decrypt_options& options = {}) const
        -> expected<secure_bytes>;

    struct decrypted {
        size_t index; // which recipient's key worked
        secure_bytes plaintext;
    };
    // Any number of recipients; succeeds with the first one `key` opens.
    [[nodiscard]] auto decrypt_multi(const jwk& key, const jwe_decrypt_options& options = {}) const
        -> expected<decrypted>;

    // With an opaque key decrypter (opaque.hpp). The recipient's "alg"
    // must be one of decrypter.algorithms() (else errc::algorithm_mismatch).
    [[nodiscard]] auto decrypt(opaque_key_decrypter& decrypter, const jwe_decrypt_options& options = {}) const
        -> expected<secure_bytes>;
    [[nodiscard]] auto decrypt_multi(opaque_key_decrypter& decrypter, const jwe_decrypt_options& options = {}) const
        -> expected<decrypted>;

    // With an async opaque key decrypter (async.hpp). This jwe and the
    // decrypter must outlive the returned task; `options` is copied.
    [[nodiscard]] auto decrypt_async(async_opaque_key_decrypter& decrypter, jwe_decrypt_options options = {}) const
        -> task<expected<secure_bytes>>;
    [[nodiscard]] auto decrypt_multi_async(async_opaque_key_decrypter& decrypter,
                                           jwe_decrypt_options options = {}) const -> task<expected<decrypted>>;

    // --- Inspection ---

    [[nodiscard]] auto enc() const noexcept -> content_encryption { return enc_; }
    [[nodiscard]] auto protected_header() const noexcept -> const header& { return protected_; }
    [[nodiscard]] auto shared_unprotected() const noexcept -> const header& { return shared_; }
    [[nodiscard]] auto recipients() const noexcept -> std::span<const jwe_recipient_info> { return recipients_; }
    // The JSON "aad" member, if any.
    [[nodiscard]] auto aad() const noexcept -> std::span<const uint8_t> { return aad_; }

    // --- Serializing ---

    // One recipient, no unprotected headers and no "aad".
    [[nodiscard]] auto compact() const -> expected<std::string>;
    [[nodiscard]] auto to_json(jwe_json_format format = jwe_json_format::general) const
        -> expected<nlohmann::json>;
    [[nodiscard]] auto to_json_string(jwe_json_format format = jwe_json_format::general) const
        -> expected<std::string>;

private:
    jwe() = default;

    static auto from_json_value(const nlohmann::json& j, const std::vector<key_algorithm>& algorithms,
                                const std::vector<content_encryption>& encryptions,
                                const extension_set& understood) -> expected<jwe>;
    // Adds a recipient, validating its headers against the shared parts.
    auto add_recipient(header per_recipient, std::vector<uint8_t> encrypted_key,
                       const std::vector<key_algorithm>& algorithms,
                       const std::vector<content_encryption>& encryptions, const extension_set& understood)
        -> expected<void>;
    auto authenticated_data() const -> std::vector<uint8_t>;
    // What's left of jwe_decrypt_options::max_pbes2_iterations in one call.
    struct pbes2_budget {
        std::uint64_t left;
        bool exhausted = false;
    };
    auto recover_cek(const jwe_recipient_info& r, const jwk& key, const jwe_decrypt_options& options,
                     pbes2_budget& budget) const -> expected<secure_bytes>;
    auto recover_cek(const jwe_recipient_info& r, opaque_key_decrypter& decrypter,
                     const jwe_decrypt_options& options) const -> expected<secure_bytes>;
    auto recover_cek_async(const jwe_recipient_info& r, async_opaque_key_decrypter& decrypter,
                           const jwe_decrypt_options& options) const -> task<expected<secure_bytes>>;
    // Decrypts the content with a recovered CEK (and decompresses it).
    auto open(const jwe_recipient_info& r, expected<secure_bytes> cek, const jwe_decrypt_options& options) const
        -> expected<secure_bytes>;

    content_encryption enc_ = content_encryption::A256GCM;
    header protected_;
    std::string encoded_protected_; // as transmitted; part of the AAD
    header shared_;
    std::vector<jwe_recipient_info> recipients_;
    std::vector<uint8_t> aad_;
    std::optional<std::string> encoded_aad_; // as transmitted, if present
    std::vector<uint8_t> iv_;
    std::vector<uint8_t> ciphertext_;
    std::vector<uint8_t> tag_;
};

} // namespace jose
