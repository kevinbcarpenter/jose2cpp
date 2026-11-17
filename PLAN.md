# jose2cpp Implementation Plan

## Project Goal

A modern C++20 library implementing the JOSE (JSON Object Signing and Encryption) standards at feature parity with go-jose v4. Dependencies: OpenSSL 3.x (crypto), nlohmann/json (serialization), Catch2 (tests).

## RFC Coverage

| RFC | Scope |
|-----|-------|
| 7515 | JWS (JSON Web Signature) |
| 7516 | JWE (JSON Web Encryption) |
| 7517 | JWK (JSON Web Key) |
| 7518 | JWA (JSON Web Algorithms) |
| 7519 | JWT (JSON Web Token) |
| 7638 | JWK Thumbprint |
| 7797 | JWS Unencoded Payload (`b64` header) |
| 8037 | EdDSA (Ed25519) for JOSE |

---

## Directory Structure

```
jose2cpp/
├── CMakeLists.txt
├── vcpkg.json
├── include/
│   └── jose/
│       ├── jose.hpp              # umbrella header
│       ├── base64url.hpp
│       ├── error.hpp             # error types (std::expected based)
│       ├── secure_bytes.hpp      # zeroing allocator + secure_bytes
│       ├── algorithm.hpp         # algorithm enum + registry
│       ├── jwk.hpp               # JWK / JWKSet
│       ├── jws.hpp               # JWS sign/verify/parse
│       ├── jwe.hpp               # JWE encrypt/decrypt/parse
│       ├── jwt.hpp               # JWT builder/parser/validator
│       ├── header.hpp            # JOSE header types
│       ├── async.hpp             # task<T>, async opaque interfaces
│       └── crypto/
│           ├── signing.hpp          # unified sign/verify (all JWS algs)
│           ├── encryption.hpp       # unified encrypt/decrypt (all JWE enc algs)
│           ├── keygen.hpp           # RSA/EC/OKP key generation, random_bytes
│           ├── rsa.hpp
│           ├── ec.hpp
│           ├── eddsa.hpp            # Ed25519 + Ed448
│           ├── hmac.hpp
│           ├── aes_kw.hpp
│           ├── aes_gcm_kw.hpp
│           ├── aes_cbc_hmac.hpp
│           ├── aes_gcm.hpp
│           ├── ecdh.hpp             # incl. X25519/X448 key agreement
│           ├── pbes2.hpp
│           └── openssl_util.hpp  # RAII wrappers, error helpers
│       └── optional/
│           └── jwks_fetcher.hpp  # async JWKS URL fetcher (opt-in)
├── src/
│   ├── base64url.cpp
│   ├── algorithm.cpp
│   ├── jwk.cpp
│   ├── jws.cpp
│   ├── jwe.cpp
│   ├── jwt.cpp
│   ├── header.cpp
│   └── crypto/
│       ├── signing.cpp
│       ├── encryption.cpp
│       ├── keygen.cpp
│       ├── rsa.cpp
│       ├── ec.cpp
│       ├── eddsa.cpp
│       ├── hmac.cpp
│       ├── hmac_util.hpp        # internal shared HMAC helper
│       ├── aes_kw.cpp
│       ├── aes_gcm_kw.cpp
│       ├── aes_cbc_hmac.cpp
│       ├── aes_gcm.cpp
│       ├── ecdh.cpp
│       └── pbes2.cpp
│   └── optional/
│       └── jwks_fetcher.cpp
├── tests/
│   ├── test_base64url.cpp
│   ├── test_jwk.cpp
│   ├── test_jws.cpp
│   ├── test_jwe.cpp
│   ├── test_jwt.cpp
│   ├── test_algorithms.cpp
│   └── vectors/               # RFC test vectors as JSON
├── fuzz/
│   ├── CMakeLists.txt
│   ├── fuzz_jwk.cpp
│   ├── fuzz_jws.cpp
│   ├── fuzz_jwe.cpp
│   ├── fuzz_jwt.cpp
│   ├── fuzz_base64url.cpp
│   └── corpus/
├── benchmarks/
│   └── bench_main.cpp
└── tools/
    └── jose_cli.cpp            # CLI utility (like jose-util)
```

---

## Algorithm Matrix

### JWS Signing (13 algorithms)

| Algorithm | OpenSSL Primitive |
|-----------|-------------------|
| HS256/384/512 | `EVP_MAC` (HMAC) |
| RS256/384/512 | `EVP_PKEY_sign` (PKCS1-v1.5) |
| PS256/384/512 | `EVP_PKEY_sign` (PSS) |
| ES256/384/512 | `EVP_DigestSign` (ECDSA) |
| EdDSA | `EVP_DigestSign` (Ed25519, Ed448) |

### JWE Key Management (17 algorithms)

| Algorithm | OpenSSL Primitive |
|-----------|-------------------|
| RSA1_5 | `EVP_PKEY_encrypt` (PKCS1) — **legacy, gated** (see §Legacy Algorithms) |
| RSA-OAEP / RSA-OAEP-256 | `EVP_PKEY_encrypt` (OAEP) |
| A128KW / A192KW / A256KW | `EVP_CIPHER` (AES wrap) |
| dir | Direct key use |
| ECDH-ES / ECDH-ES+A*KW | `EVP_PKEY_derive` + Concat KDF (P-256/384/521, X25519, X448) |
| A128GCMKW / A192GCMKW / A256GCMKW | `EVP_CIPHER` (AES-GCM) |
| PBES2-HS*+A*KW | `PKCS5_PBKDF2_HMAC` + AES wrap |

### JWE Content Encryption (6 algorithms)

| Algorithm | OpenSSL Primitive |
|-----------|-------------------|
| A128CBC-HS256 / A192CBC-HS384 / A256CBC-HS512 | `EVP_CIPHER` (AES-CBC) + `EVP_MAC` (HMAC) |
| A128GCM / A192GCM / A256GCM | `EVP_CIPHER` (AES-GCM) |

---

## Core Design Decisions

### 1. Error Handling: `jose::expected<T>` (`std::expected`-compatible)

No exceptions. Every fallible operation returns `jose::expected<T>` — an alias for `std::expected<T, jose::error>` when built as C++23, or the vendored single-header [expected-lite](https://github.com/martinmoene/expected-lite) polyfill on C++20 (`std::expected` itself is C++23-only). The selection is pinned at CMake configure time (`JOSE_USE_STD_EXPECTED`) and exported to consumers. This is both safer for crypto code (no exception-safety bugs around key material) and more performant.

```cpp
namespace jose {
  enum class errc {
    invalid_token, invalid_signature, invalid_key,
    algorithm_mismatch, expired, not_yet_valid,
    missing_claim, decryption_failed, unsupported_algorithm,
    invalid_header, serialization_error, key_too_short,
    // ...
  };
  struct error {
    errc code;
    std::string message;
  };
}
```

### 2. Memory Safety: `secure_bytes`

Key material lives in `secure_bytes` — a vector with a custom allocator that zeros memory on deallocation and, when the application opts in, allocates from OpenSSL's mlock'ed secure heap (see §Secure Memory). All crypto intermediates use this type.

```cpp
template<typename T>
struct secure_allocator {
  T* allocate(size_t n);                    // secure heap if initialised, else normal heap
  void deallocate(T* p, size_t n) noexcept; // CRYPTO_secure_clear_free: cleanse + free
};
using secure_bytes = std::vector<uint8_t, secure_allocator<uint8_t>>;
```

### 3. OpenSSL RAII Wrappers

Every OpenSSL resource gets a unique_ptr with custom deleter:

```cpp
using evp_pkey_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using evp_md_ctx_ptr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using evp_cipher_ctx_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
```

### 4. Algorithm Registry Pattern

Type-safe enums with compile-time validation, runtime lookup by string:

```cpp
enum class signing_algorithm {
  HS256, HS384, HS512, RS256, RS384, RS512,
  ES256, ES384, ES512, PS256, PS384, PS512, EdDSA
};

enum class key_algorithm {
  RSA1_5, RSA_OAEP, RSA_OAEP_256,
  A128KW, A192KW, A256KW,
  dir,
  ECDH_ES, ECDH_ES_A128KW, ECDH_ES_A192KW, ECDH_ES_A256KW,
  A128GCMKW, A192GCMKW, A256GCMKW,
  PBES2_HS256_A128KW, PBES2_HS384_A192KW, PBES2_HS512_A256KW
};

enum class content_encryption {
  A128CBC_HS256, A192CBC_HS384, A256CBC_HS512,
  A128GCM, A192GCM, A256GCM
};
```

### 5. Key Abstraction

```cpp
class jwk {
public:
  // Factory methods
  static auto from_json(std::string_view json) -> expected<jwk, error>;
  static auto from_pem(std::string_view pem) -> expected<jwk, error>;
  static auto generate_rsa(int bits) -> expected<jwk, error>;
  static auto generate_ec(ec_curve curve) -> expected<jwk, error>;
  static auto from_pkey(evp_pkey_ptr key) -> expected<jwk, error>;
  static auto from_oct(std::span<const uint8_t> key) -> expected<jwk, error>;
  static auto generate_oct(size_t bytes) -> expected<jwk, error>;
  static auto generate_okp(okp_curve crv) -> expected<jwk, error>; // Ed25519/Ed448/X25519/X448

  auto to_json() const -> expected<nlohmann::json, error>;  // fails only if OpenSSL export fails
  auto public_key() const -> expected<jwk, error>;
  auto thumbprint(hash_algorithm h = hash_algorithm::SHA256) const -> expected<std::vector<uint8_t>, error>;
  auto pkey() const -> EVP_PKEY*;                   // nullptr for oct
  auto oct() const -> std::span<const uint8_t>;     // empty for asymmetric keys
  auto is_public() const -> bool;
  auto key_type() const -> kty;
  auto key_id() const -> std::optional<std::string>;
  auto algorithm() const -> std::optional<std::string>;
  // ...
};

class jwk_set {
public:
  static auto from_json(std::string_view json) -> expected<jwk_set, error>;
  auto find(std::string_view kid) const -> std::optional<std::reference_wrapper<const jwk>>;
  auto find_all(std::string_view kid) const -> std::vector<std::reference_wrapper<const jwk>>;
  auto keys() const -> std::span<const jwk>;
  auto skipped() const -> std::span<const error>;  // members ignored per RFC 7517 §5
  // ...
};
```

### 6. Builder/Parser Pattern (JWT)

```cpp
// Building
auto token = jwt::signed_token(signer)
    .claims(standard_claims)
    .claims(custom_claims)
    .serialize();

// Parsing with mandatory algorithm allowlist (go-jose v4 security pattern)
auto parsed = jwt::parse_signed(token_string, {signing_algorithm::RS256});
auto claims = parsed.and_then([&](auto& t) { return t.verify(key); })
                     .and_then([&](auto& t) { return t.claims<my_claims>(); });

// Validation
jose::expected_claims expected{
    .issuer = "https://auth.example.com",
    .audience = "my-api",
    .time = std::chrono::system_clock::now()
};
auto result = claims.validate(expected);
```

### 7. `none` Algorithm

Deliberately **not supported**, matching go-jose. This is a security decision — unsigned tokens are a well-known attack vector.

### 8. Async Coroutine Support (Targeted)

Core crypto operations (sign, verify, encrypt, decrypt) remain synchronous — they're CPU-bound microsecond operations where coroutine frame overhead would be pure waste. Async support is applied only where it matters: I/O-bound extension points.

**`task<T>` — lightweight coroutine return type (header-only, no external dependency):**

```cpp
namespace jose {
  template<typename T>
  class task {
    // Lazy coroutine: suspends immediately, resumes when co_awaited.
    // Single-consumer, move-only. No allocator overhead beyond
    // the compiler-generated coroutine frame.
  };
}
```

**Dual opaque interfaces — sync (default) and async (opt-in):**

```cpp
// Synchronous — covers local keys, software HSMs, most use cases
struct opaque_signer {
  virtual ~opaque_signer() = default;
  virtual auto public_key() const -> jwk = 0;
  virtual auto algorithms() const -> std::span<const signing_algorithm> = 0;
  virtual auto sign(std::span<const uint8_t> payload)
    -> expected<secure_bytes, error> = 0;
};

struct opaque_verifier {
  virtual ~opaque_verifier() = default;
  virtual auto verify(std::span<const uint8_t> payload,
                      std::span<const uint8_t> signature)
    -> expected<void, error> = 0;
};

struct opaque_key_decrypter {
  virtual ~opaque_key_decrypter() = default;
  virtual auto decrypt_key(std::span<const uint8_t> encrypted_key,
                           key_algorithm alg)
    -> expected<secure_bytes, error> = 0;
};

// Async variants — for cloud KMS (AWS KMS, GCP, Azure Key Vault), network HSMs
struct async_opaque_signer {
  virtual ~async_opaque_signer() = default;
  virtual auto public_key() const -> jwk = 0;
  virtual auto algorithms() const -> std::span<const signing_algorithm> = 0;
  virtual auto sign(std::span<const uint8_t> payload)
    -> task<expected<secure_bytes, error>> = 0;
};

struct async_opaque_key_decrypter {
  virtual ~async_opaque_key_decrypter() = default;
  virtual auto decrypt_key(std::span<const uint8_t> encrypted_key,
                           key_algorithm alg)
    -> task<expected<secure_bytes, error>> = 0;
};
```

**JWS/JWE accept both:** The signer/encrypter constructors are overloaded — pass a sync interface and you get a sync API, pass an async interface and you get `task<expected<...>>` returns. No runtime polymorphism penalty when using the sync path.

**Optional JWKS URL fetcher (async, opt-in component):**

```cpp
namespace jose::optional {
  struct jwks_fetcher_config {
    std::string url;
    std::chrono::seconds refresh_interval{300};
    std::chrono::seconds timeout{10};
    size_t max_cache_size{100};
  };

  // Users provide their own HTTP backend via this interface
  struct http_client {
    virtual auto get(std::string_view url)
      -> task<expected<std::string, error>> = 0;
    virtual ~http_client() = default;
  };

  class jwks_fetcher {
  public:
    jwks_fetcher(jwks_fetcher_config config,
                 std::unique_ptr<http_client> client);
    auto fetch() -> task<expected<jwk_set, error>>;
    auto get_cached() const -> std::optional<std::reference_wrapper<const jwk_set>>;
  };
}
```

This avoids baking in an HTTP dependency (no curl, no Boost.Beast in core) while giving users a clean integration point. The fetcher handles caching, TTL-based refresh, and thread-safe key rotation.

---

## Phased Implementation

### Phase 1: Foundation + JWA (Weeks 1-3) — ✅ complete

The crypto layer and core utilities. Everything else builds on this.

Known-answer tests: `tests/vectors/*.json` (38 cases from RFC 3394, 7515, 7517, 7518, 7520, 8032, 8037), extracted from the RFC texts by `tests/vectors/generator/gen_vectors.py` and run by `tests/test_vectors.cpp`. RSA-OAEP-256 has no published vector and is covered by round-trip tests only.

**Deliverables:**
1. Build system (CMake + vcpkg manifest for OpenSSL, nlohmann/json, Catch2)
2. `base64url` encode/decode (no padding, URL-safe alphabet)
3. `secure_vector` and OpenSSL RAII wrappers
4. `error` types with `std::expected`
5. Algorithm enums and string conversion registry
6. All signing primitives: HMAC, RSA (PKCS1 + PSS), ECDSA, EdDSA (Ed25519 + Ed448)
7. All content encryption: AES-CBC-HMAC, AES-GCM
8. All key management: RSA-OAEP, AES-KW, AES-GCM-KW, ECDH-ES (+Concat KDF, X25519, X448), PBES2, direct
9. RSA1_5 behind the `jose::legacy_options{.allow_rsa1_5 = true}` opt-in (see §Legacy Algorithms)
10. Tests against RFC test vectors for every algorithm

**Risk:** ECDH-ES Concat KDF is not directly exposed by OpenSSL — we'll need a manual implementation using `EVP_PKEY_derive` for the shared secret and then a custom Concat KDF (it's just SHA-256 based, straightforward).

### Phase 2: JWK + JWS + JWE (Weeks 4-6)

Wire the crypto primitives into the JOSE object model.

**Deliverables:**
1. ✅ `jwk` — parse/serialize all key types (RSA, EC, OKP, oct), X.509 chain, thumbprint
2. ✅ `jwk` key validation on import (see §Key Validation)
3. ✅ `jwk_set` — parse/serialize, kid lookup
4. ✅ JOSE header parsing with `crit` extension allowlist (see §Critical Header Extensions)
5. `jws` — sign, verify; compact, flattened JSON, and general JSON serializations; detached payload; multi-signature
6. `jwe` — encrypt, decrypt; compact, flattened JSON, and general JSON serializations; multi-recipient; DEFLATE compression
7. Unencoded payload option (RFC 7797, `b64` header)
8. Opaque signer/verifier/decrypter interfaces — both sync and async variants
9. `task<T>` coroutine return type (header-only, zero-dependency)
10. Async-aware JWS/JWE overloads that accept `async_opaque_signer` / `async_opaque_key_decrypter`
11. Interop tests: generate test vectors with go-jose (Go toolchain in CI), consume in jose2cpp and vice versa; vectors checked into `tests/vectors/`

### Phase 3: JWT + Polish (Weeks 7-8)

High-level JWT API and production readiness.

**Deliverables:**
1. `jwt` builder — signed, encrypted, signed-then-encrypted (nested)
2. `jwt` parser — mandatory algorithm allowlists
3. Standard claims struct with `NumericDate` (chrono-based)
4. `Audience` type (single string or array, flexible parse)
5. Claim validation with leeway
6. Signed-then-encrypted JWT (`cty: "JWT"` handling)
7. Optional async JWKS URL fetcher with pluggable HTTP backend, caching, TTL refresh
8. CLI tool (`jose-cli`) — sign, verify, encrypt, decrypt, generate-key
9. Fuzz targets (libFuzzer): `jwk::from_json`, `jws::parse`, `jwe::parse`, `jwt::parse_signed` (see §Fuzz Testing)
10. API documentation (Doxygen)
11. Benchmarks vs. go-jose (sign/verify throughput, parse latency)

---

## Performance Strategy

1. **Zero-copy parsing** — `std::string_view` for token parts during parse; only allocate for validated output
2. **EVP API only** — no deprecated low-level OpenSSL calls; EVP is hardware-accelerated where available (AES-NI, SHA extensions)
3. **Avoid redundant allocations** — pre-size buffers based on algorithm output sizes
4. **`std::expected` over exceptions** — no exception overhead on error paths
5. **Header-only option** — consider offering a header-only mode for the non-crypto parts (serialization, claims)
6. **Thread safety** — all operations are stateless; keys are immutable after construction. `jwks_fetcher` uses `atomic<shared_ptr<jwk_set>>` swap for lock-free concurrent reads during key rotation

---

## Build System

```cmake
cmake_minimum_required(VERSION 3.20)
project(jose2cpp VERSION 0.1.0 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL 3.0 REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(Catch2 3 REQUIRED)

add_library(jose
    src/base64url.cpp
    src/algorithm.cpp
    src/jwk.cpp
    src/jws.cpp
    src/jwe.cpp
    src/jwt.cpp
    src/header.cpp
    src/crypto/rsa.cpp
    src/crypto/ec.cpp
    src/crypto/eddsa.cpp
    src/crypto/x25519_x448.cpp
    src/crypto/hmac.cpp
    src/crypto/aes_kw.cpp
    src/crypto/aes_gcm_kw.cpp
    src/crypto/aes_cbc_hmac.cpp
    src/crypto/aes_gcm.cpp
    src/crypto/ecdh.cpp
    src/crypto/pbes2.cpp
    src/crypto/openssl_util.cpp
)
target_link_libraries(jose PUBLIC OpenSSL::SSL OpenSSL::Crypto nlohmann_json::nlohmann_json)
target_include_directories(jose PUBLIC include)
```

---

## Resolved Design Decisions

1. **Ed448 / X25519 / X448** — Full support. Ed25519 + Ed448 for EdDSA signing, X25519 + X448 for ECDH-ES key agreement. Competitive advantage over go-jose. OpenSSL 3.x has native support. Scoped into Phase 1 (crypto primitives) and Phase 2 (JWK OKP key type with crv=X25519/X448/Ed448).
2. **JWKS fetching** — Yes, as an optional async component with pluggable HTTP backend. Not in core, no HTTP dependency in the main library.
3. **Namespace** — `jose::` (clean, matches the standard).
4. **Minimum OpenSSL version** — 3.0+ only. 1.1.1 is EOL.
5. **CMake install/pkg-config** — Yes, ship as a proper CMake package with `find_package(jose)` from day one.
6. **Async/coroutine support** — Targeted: core crypto stays synchronous, async applied only to opaque signer/decrypter interfaces (for KMS/HSM) and the optional JWKS fetcher. Custom `task<T>` type, no external coroutine library dependency.

---

## Legacy Algorithms

`RSA1_5` (RSAES-PKCS1-v1_5 key encryption) is vulnerable to Bleichenbacher-style padding oracle attacks. It is implemented for backward compatibility with existing token ecosystems but **disabled by default**.

To use RSA1_5, callers must explicitly opt in:

```cpp
// Opt-in at the point of use — no global state
auto opts = jose::legacy_options{ .allow_rsa1_5 = true };
auto result = jwe::decrypt(token, key, opts);
```

The encrypt path also requires the flag — the library will not produce RSA1_5-encrypted tokens without explicit acknowledgment. This mirrors the pattern used by go-jose's `decrypter.Options`.

At the primitive level this is `jose::rsa_encrypt_key` / `jose::rsa_decrypt_key`, which take `legacy_options` and refuse RSA1_5 with `errc::legacy_algorithm_disabled` by default. Even with the opt-in, `rsa_decrypt_key` never reports an RSA1_5 padding failure: it returns a random CEK of the expected length, selected in constant time, so a tampered key fails later at the authentication tag like any other bad token (RFC 7516 §11.5 Bleichenbacher countermeasure, as in go-jose).

---

## Critical Header Extensions (`crit`)

RFC 7515 §4.1.11: if a JWS/JWE header contains `"crit": ["x-custom-nonce"]`, the recipient must understand every listed extension or reject the token.

**Design: allowlist at parse time** (matching go-jose's approach).

Parse functions accept an optional set of known extension names. If `crit` lists anything not in that set, parsing fails with `errc::unrecognized_critical_extension`.

```cpp
// Parser knows about "x-audit-id" but nothing else
auto known = std::set<std::string>{"x-audit-id"};
auto result = jws::parse(token, {signing_algorithm::RS256}, known);

// If token has crit: ["x-audit-id"] → OK, caller reads the value from headers
// If token has crit: ["x-audit-id", "x-unknown"] → errc::unrecognized_critical_extension
```

The library handles all standard registered headers internally. The allowlist is only for application-defined extensions. Default (empty set) means any `crit` extension causes rejection — safe by default.

Implementation (Phase 2, `jose/header.hpp`):

- **`jose::header`** is one header JSON object (protected, shared unprotected, or per-signature/recipient). Built by `header::parse` / `from_json` / `from_base64url`; every registered parameter present is type-checked up front, so the typed accessors (`alg()`, `kid()`, `epk()`, `p2c()`, `crit()`, `b64()`, ...) never fail. Unregistered parameters are kept verbatim and read with `get(name)`. `set()` re-validates and leaves the header unchanged on failure.
- **Duplicate member names are rejected** (`errc::serialization_error`) in any object, nested ones included. RFC 7515 §4 / 7516 §4 / 7517 §4 allow either rejecting or keeping the last value; rejecting removes any chance of two parsers disagreeing about which `alg` a token has. `jwk::from_json` and `jwk_set::from_json` use the same strict parser.
- **Registered parameter checks**: strings for `alg enc zip kid typ cty jku x5u`; base64url for `apu apv iv tag p2s x5t x5t#S256` (`x5t` 20 octets, `x5t#S256` 32); `jwk`/`epk` must be valid *public* asymmetric JWKs; `x5c` must be DER certificates, with `x5t`/`x5t#S256` matching the leaf; `p2c` a positive integer (the PBES2 code enforces its own upper bound); `b64` a boolean.
- **`crit` structure** (RFC 7515 §4.1.11): a non-empty array of unique, non-empty strings, none of which is a parameter defined by RFC 7515/7516/7518 (`is_registered_header_parameter`). `b64` is not "registered" in that sense — RFC 7797 requires it to be listed.
- **`join_headers(ctx, protected, shared, per_recipient, understood)`** combines the parts for one signature/recipient (RFC 7515 §7.2.1, RFC 7516 §7.2.1) and enforces the cross-part rules, all `errc::invalid_header` except the last:
  - parameter names must be disjoint across parts;
  - `crit` must be protected; for JWS so must `b64` (RFC 7797 §3), for JWE `zip` (RFC 7516 §4.1.3);
  - `alg` is required, and `enc` for JWE;
  - JWS `b64` must be listed in `crit` (RFC 7797 §6);
  - each name in `crit` must be present **in the protected header** — stricter than RFC 7515 requires, but a critical value the attacker could change or strip isn't worth honouring;
  - each name in `crit` must be understood — by the library (`b64`, JWS only) or via the caller's `extension_set` — else `errc::unrecognized_critical_extension`.

---

## Key Validation

All key import paths (`jwk::from_json`, `jwk::from_pem`, `jwk::from_pkey`, and the `generate_*` factories) perform validation:

- **RSA**: reject keys below 2048 bits. Verify `n`, `e`, `d`, `p`, `q` consistency via `EVP_PKEY_check`.
- **EC**: validate that the public point lies on the declared curve (P-256, P-384, P-521). Reject points at infinity. Uses `EC_KEY_check_key` / `EVP_PKEY_public_check`.
- **OKP** (Ed25519, Ed448, X25519, X448): validate key length matches curve requirements.
- **oct**: reject keys shorter than the minimum required by their declared algorithm (e.g., HS256 requires ≥32 bytes).

Invalid keys fail at import with `errc::invalid_key` and a descriptive message. There is no way to construct a `jwk` holding invalid key material — validation is mandatory, not opt-in.

Implementation details (Phase 2):

- **RSA private keys** must include `p` and `q` (as go-jose requires); `dp`/`dq`/`qi` are computed when absent. Multi-prime keys (`oth`) are rejected as unsupported. Consistency is checked with `EVP_PKEY_check`.
- **EC / OKP** coordinates, `d`, and `x` must be exactly the curve size (RFC 7518 §6.2, RFC 8037); OKP `x` must equal the public key derived from `d`. Curves other than P-256/384/521, Ed25519/Ed448, X25519/X448 are `errc::unsupported_algorithm`.
- **`alg`** must suit the key when it is a registered value: e.g. `ES256` only on P-256, `RS*`/`PS*` only on RSA, `HS256` only on an oct key of ≥ 32 octets (`errc::key_too_short`), `A128KW`/`A128GCM` only on a 16-octet oct key. Unregistered values are allowed (RFC 7517 §4.4). Mismatches are `errc::algorithm_mismatch`.
- **`use` / `key_ops`**: `key_ops` may not repeat values, and must agree with `use` when `use` is `sig` or `enc` (RFC 7517 §4.3).
- **`x5c`**: every entry must be a DER certificate (standard base64); the leaf's public key must match the JWK's key; `x5t` / `x5t#S256`, if present, must match the leaf. Chains are *not* path-validated — that is the application's trust decision, as in go-jose.
- **JWK Sets** follow RFC 7517 §5: members that are invalid or use an unsupported `kty`/`crv` are skipped rather than failing the whole set; their errors are available from `jwk_set::skipped()`.
- **PEM** import accepts PKCS#8, SubjectPublicKeyInfo, PKCS#1 and SEC1 keys, and certificates (a chain becomes `x5c`, leaf first). Encrypted PEM is rejected; no passphrase prompt is ever installed.

---

## Secure Memory (`mlock` Behavior)

`secure_allocator` does not call `mlock` per allocation: page locks don't nest, so unlocking one freed vector would silently unlock any other secret sharing its page. Instead it uses OpenSSL's secure heap — a single mlock'ed, guard-paged arena (also excluded from core dumps where the OS supports it) — which the application reserves once at startup:

```cpp
auto status = jose::init_secure_heap(1 << 16);  // 64 KiB arena
// status: secure_heap_status::locked, ::not_locked (mlock failed), or an error
```

Behavior:

- **Opt-in.** Without `init_secure_heap`, `secure_bytes` uses the normal heap. Key material is still zeroed on free (`OPENSSL_cleanse`) but may be paged to swap.
- **mlock failure is not fatal.** If the arena can't be locked (e.g. `ulimit -l`, typically 64 KiB on Linux), `init_secure_heap` returns `secure_heap_status::not_locked`; the arena still works, guard-paged and zeroed.
- **Silent fallback when full.** If the arena is exhausted, allocation falls back to the normal heap (still zeroed on free) and no OpenSSL error is left on the queue. Size the arena for the number of live keys; OpenSSL's DRBG also keeps its seed state there.
- `init_secure_heap` can only succeed once per process (it's OpenSSL global state). Applications with strict requirements should also raise `ulimit -l` or use `mlockall`.

---

## Fuzz Testing

Fuzz targets using libFuzzer, integrated into the CMake build via `-DJOSE_FUZZ=ON`:

**Targets:**
- `fuzz_jwk_from_json` — arbitrary JSON → `jwk::from_json`
- `fuzz_jws_parse` — arbitrary bytes → `jws::parse` (with all algorithms allowed)
- `fuzz_jwe_parse` — arbitrary bytes → `jwe::parse`
- `fuzz_jwt_parse` — arbitrary bytes → `jwt::parse_signed`
- `fuzz_base64url` — round-trip: decode arbitrary bytes, encode result, verify match

**Structure:**
```
fuzz/
├── CMakeLists.txt
├── fuzz_jwk.cpp
├── fuzz_jws.cpp
├── fuzz_jwe.cpp
├── fuzz_jwt.cpp
├── fuzz_base64url.cpp
└── corpus/              # seed inputs from RFC test vectors
```

Fuzz targets must never crash, throw, or leak on any input. `std::expected` error returns are the expected failure mode. Any abort, ASAN violation, or undefined behavior is a bug.
