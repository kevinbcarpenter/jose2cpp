# jose2cpp Implementation Plan

## Project Goal

A modern C++20 library implementing the JOSE (JSON Object Signing and Encryption) standards at feature parity with go-jose v4. Dependencies: OpenSSL 3.x (crypto), nlohmann/json (serialization), zlib (JWE DEFLATE, private), Catch2 (tests).

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
│       ├── task.hpp              # task<T>, sync_wait (header-only)
│       ├── async.hpp             # async opaque interfaces
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
5. ✅ `jws` — sign, verify; compact, flattened JSON, and general JSON serializations; detached payload; multi-signature (see §JWS)
6. ✅ `jwe` — encrypt, decrypt; compact, flattened JSON, and general JSON serializations; multi-recipient; DEFLATE compression (see §JWE)
7. ✅ Unencoded payload option (RFC 7797, `b64` header)
8. ✅ Opaque signer/verifier/decrypter interfaces — sync variants (see §Opaque Keys); async variants in item 10
9. ✅ `task<T>` coroutine return type (header-only, zero-dependency; see §task)
10. ✅ Async-aware JWS/JWE overloads that accept `async_opaque_signer` / `async_opaque_key_decrypter` (see §Async Opaque Keys)
11. ✅ Interop tests: generate test vectors with go-jose (Go toolchain in CI), consume in jose2cpp and vice versa; vectors checked into `tests/vectors/` (see §go-jose Interop)

### Phase 3: JWT + Polish (Weeks 7-8)

High-level JWT API and production readiness.

**Deliverables:**
1. ✅ `jwt` builder — signed, encrypted, signed-then-encrypted (nested) (see §JWT)
2. ✅ `jwt` parser — mandatory algorithm allowlists (see §JWT)
3. ✅ Standard claims struct with `NumericDate` (chrono-based) (see §JWT)
4. ✅ `Audience` type (single string or array, flexible parse) (see §JWT)
5. ✅ Claim validation with leeway (see §JWT)
6. ✅ Signed-then-encrypted JWT (`cty: "JWT"` handling) on the parse side; building nested tokens is item 1 (see §JWT)
7. Optional async JWKS URL fetcher with pluggable HTTP backend, caching, TTL refresh
8. CLI tool (`jose-cli`) — sign, verify, encrypt, decrypt, generate-key
9. Fuzz targets (libFuzzer): `jwk::from_json`, `jws::parse`, `jwe::parse`, `jwt::parse_signed` (see §Fuzz Testing)
10. API documentation (Doxygen)
11. Benchmarks vs. go-jose (sign/verify throughput, parse latency)
12. ✅ Async opaque keys for JWT: build with an `async_opaque_signer` and parse with `async_opaque_verifier` / `async_opaque_key_decrypter` (`claims_async`, `nested_jwt::decrypt_async`), reusing the allowlists and `understood` given at parse time so a caller can't widen them on a second call. (see §Async Opaque Keys)

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
find_package(ZLIB REQUIRED)
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

## JWS

Implementation (Phase 2, `jose/jws.hpp`), following go-jose v4:

- **Parsing needs an algorithm allowlist.** `jws::parse(input, algorithms, understood)` auto-detects compact vs JSON; `parse_compact`, `parse_json` and `parse_detached` are explicit. Every signature's `alg` must be in the (non-empty) list, so a token can't choose its own algorithm; `none` and unknown values are `errc::unsupported_algorithm`. Headers go through `join_headers` (so `crit`, disjointness and `b64` rules apply), and the JSON is parsed strictly (duplicate members rejected).
- **Verification** checks the key before using it: `jwk::check_algorithm` (type, curve, HMAC length, the key's own `alg`) and `jwk::check_operation("verify")` (`use` / `key_ops`). `verify(jwk)` needs exactly one signature, `verify(jwk_set)` selects candidates by the header `kid` (required) and tries each, `verify_multi(jwk)` returns the index of the first signature the key verifies. Keys embedded in the token (`jwk`, `x5c`, `jku`) are never used implicitly.
- **Signing** takes `jws_signer`s (alg, private jwk or oct key, optional protected/unprotected headers) and `jws_sign_options` (`b64`, `embed_jwk`, `include_kid`, default on). The protected header is serialized with nlohmann's sorted keys and no whitespace.
- **Signing input is built from the parts as transmitted** (protected header and payload strings), never from re-encoded values, so a parsed JWS re-serializes byte-for-byte.
- **RFC 7797**: with `b64=false` the payload is raw in the signing input; `b64` must be protected, listed in `crit`, and identical across signatures. `compact()` refuses a payload containing `.` (use `compact_detached()`); JSON output requires the payload to be valid UTF-8.
- **Vectors**: `tests/vectors/jws.json` holds 17 cases / 31 serializations (RFC 7515 App. A.1–A.4, A.6, A.7; RFC 7520 §4.1–4.8 incl. detached, unprotected-only and multi-signature; RFC 7797 §4.1–4.2; RFC 8037 A.4). Each is parsed, verified, tampered, and re-serialized exactly; deterministic ones are re-signed and match byte-for-byte when the header encoding coincides.

---

## JWE

Implementation (Phase 2, `jose/jwe.hpp`), following go-jose v4:

- **Parsing needs two allowlists**: key-management algorithms and content encryptions. Every recipient's `alg` and the (common) `enc` must be in them; `zip` may only be `DEF`. Headers go through `join_headers` (`zip` protected, parts disjoint, `crit` allowlist). The IV and tag lengths must match `enc` (`errc::invalid_iv` / `invalid_tag`), and `dir` / `ECDH-ES` recipients must have an empty encrypted key (RFC 7516 §5.2 step 10).
- **Decryption** checks the key first — `jwk::check_algorithm` (for `dir`, against `enc`, since RFC 7520 labels CEKs with their `enc` value), `jwk::check_operation` (`unwrapKey`, `deriveKey` for ECDH-ES, `decrypt` for `dir`), a private key for RSA/ECDH, and an `epk` on the key's curve. Those are reported as key errors. **Every cryptographic failure** (key unwrap, ECDH, wrong CEK length, tag) is the same `errc::decryption_failed` with the same message, so failures can't be told apart; with RSA1_5 the constant-time random-CEK countermeasure makes padding failures surface as tag failures too.
- `decrypt(jwk)` needs one recipient, `decrypt(jwk_set)` selects by `kid`, `decrypt_multi(jwk)` tries each recipient the key suits and returns its index. Plaintext is returned as `secure_bytes`.
- **PBES2 on decrypt**: `p2c` must be in [1000, 1 000 000] and `p2s` at least 8 octets (`errc::invalid_header`), bounding attacker-chosen work.
- **DEFLATE** (`zip:"DEF"`, raw RFC 1951 via zlib, a private dependency) is applied after decryption, so a malformed stream isn't an oracle. Output is capped at max(250 KiB, 10 × ciphertext) by default (go-jose v4's bound), configurable via `jwe_decrypt_options::max_decompressed_size`.
- **Encryption** takes `jwe_recipient`s (alg, key, extra parameters such as `apu`/`apv`, PBES2 count) and `jwe_encrypt_options` (shared protected / unprotected headers, JSON `aad`, `compress`, `include_kid`, `legacy`). With one recipient, its parameters (`alg`, `kid`, `epk`, `iv`/`tag`, `p2s`/`p2c`) go in the protected header so the compact form works; with several they go in per-recipient headers. `dir` and `ECDH-ES` fix the CEK and are single-recipient only. Library-owned parameters (`alg enc zip epk iv tag p2s p2c`) can't be supplied by the caller.
- **AAD is built from the transmitted strings** (protected header, `aad`), so a parsed JWE re-serializes byte-for-byte.
- **Vectors**: `tests/vectors/jwe.json` — 18 cases / 37 serializations (RFC 7520 §5.1–5.13: RSA1_5, RSA-OAEP, PBES2, ECDH-ES(+KW), dir, AES-GCM-KW, AES-KW, compression, AAD, shared unprotected headers, multiple recipients; RFC 7516 App. A.1–A.5). Each is parsed, decrypted with every recipient's key, re-serialized exactly, and tampered. RFC 7520 §5.5/§5.6 label a JSON object without `recipients` "general"; it is parsed (correctly) as flattened.

---

## Opaque Keys

Implementation notes for Phase 2 item 8 (`include/jose/opaque.hpp`), following go-jose v4's `OpaqueSigner` / `OpaqueVerifier` / `OpaqueKeyDecrypter`:

- **Three interfaces.** `opaque_signer` (`public_key()`, `algorithms()`, `sign(signing_input, alg)`), `opaque_verifier` (`algorithms()`, `verify(signing_input, signature, alg)`), `opaque_key_decrypter` (`algorithms()`, `decrypt_key(encrypted_key, alg, enc, joined_header)`). Every interface states its algorithms, and the library never passes it anything else (`errc::algorithm_mismatch`); `verify_multi` / `decrypt_multi` skip signatures and recipients it can't handle. The decrypter gets the recipient's full joined header because ECDH-ES needs `epk`/`apu`/`apv`, AES-GCM-KW `iv`/`tag`, and PBES2 `p2s`/`p2c` (go-jose passes the header too).
- **Plugging in.** `jws_signer::key` is a `signing_key = std::variant<jwk, std::shared_ptr<opaque_signer>>`, so opaque and local signers mix in one multi-signature JWS. Verifiers and decrypters are passed by reference to `jws::verify` / `verify_multi` and `jwe::decrypt` / `decrypt_multi`. `public_key()` is called only when `include_kid` or `embed_jwk` needs it.
- **Errors.** A new `errc::key_unavailable` reports backend failures (network, permissions, device offline) and is passed through unchanged. Any other verifier error becomes `errc::invalid_signature`; any other decrypter error, and a CEK of the wrong length, becomes the uniform `errc::decryption_failed` (go-jose maps everything to `ErrCryptoFailure`; passing outages through keeps them debuggable without opening an oracle on the token's contents). Signer errors pass through: signing input isn't attacker-controlled.
- **Signature-size check.** An `ES*` signature from an opaque signer must be exactly R || S (64/96/132 octets); a DER signature, which most HSMs and KMSs return, is caught with a message saying so.
- **RSA1_5** still needs `legacy_options::allow_rsa1_5`, checked before the decrypter is called. The constant-time countermeasure can't be applied inside someone else's code, so the interface documents that the decrypter must not reveal padding failures.
- **No opaque key encrypter.** Encryption uses public keys (or a CEK/KEK the caller already holds), so there is no KMS case for it yet; go-jose's `OpaqueKeyEncrypter` can't be implemented outside its package either.

## task

Implementation notes for Phase 2 item 9 (`include/jose/task.hpp`, header-only, standard library only):

- **`task<T>`** is lazy (the body runs when first awaited), move-only and single-consumer (`co_await` moves the result out). `T` may be `void` or any non-reference object type, including ones without a default constructor such as `expected<jwk>`; results live in a union. Discarding an unawaited task destroys its frame without running it.
- **No scheduler.** A task runs on the thread that awaits it, and the awaiter resumes on whichever thread the task finishes on. Executors, thread pools and cancellation belong to the application's async framework; `task` only has to compose with it, and any awaitable can be `co_await`ed inside one.
- **Constant stack for loops without symmetric transfer.** Symmetric transfer relies on the compiler emitting a tail call, which GCC doesn't do at `-O0` or under ASan: a loop of a million synchronous `co_await`s overflowed the stack there. Instead the awaiter resumes the task directly and an atomic flag (set by both sides at the hand-off; acq_rel) decides who continues, as in pre-symmetric-transfer cppcoro: a task that completed synchronously returns into `await_suspend`, which declines to suspend. Cost: one atomic exchange per `co_await`. Recursion through `co_await` uses stack like ordinary recursion.
- **`sync_wait(task)`** drives a task from non-coroutine code, blocking on a mutex/condition variable until it finishes on any thread, and returns the value or rethrows. (A mutex rather than `std::binary_semaphore` / `atomic::wait`, which need macOS 11+ in libc++.)
- **Exceptions** escaping a task body are rethrown by `co_await` / `sync_wait`. With `-fno-exceptions` the header compiles and `unhandled_exception` terminates.
- **Verified** with Apple Clang 21 (`-O0`, `-O2`, ASan+UBSan, TSan, `-fno-exceptions`) and GCC 16 (`-O0`, `-O2`, ASan+UBSan, `-fno-exceptions`), including resumption from another thread. GCC 10 would need `-fcoroutines`; GCC 11+ enables coroutines with `-std=c++20`.

## Async Opaque Keys

Implementation notes for Phase 2 item 10 (`include/jose/async.hpp`):

- **Interfaces** mirror opaque.hpp with `task<expected<...>>` results: `async_opaque_signer` (`public_key()` is async too, since fetching it from a KMS is a network call), `async_opaque_verifier` (not in the original sketch; added for parity, e.g. KMS-held HMAC keys) and `async_opaque_key_decrypter`. `algorithms()` stays synchronous metadata. The same error and algorithm rules apply.
- **Named `*_async` entry points**, not overloads returning a different type: `jws::sign_async`, `jws::verify_async` / `verify_multi_async`, `jwe::decrypt_async` / `decrypt_multi_async`. `signing_key` gains a third alternative, `std::shared_ptr<async_opaque_signer>`, so one `sign_async` call mixes local, sync opaque and async signers (run in order). The synchronous `sign` refuses an async signer with a message pointing at `sign_async`.
- **Lifetimes.** `task` is lazy, so a coroutine's reference parameters can dangle before it runs. `sign_async` therefore takes its payload, signers and options by value (the span / string_view overloads are plain functions that copy before creating the task). The member functions `verify_async` / `decrypt_async` use `*this` and the verifier/decrypter by reference, so those must outlive the task (documented; copying a JWE's ciphertext per call would be the alternative). Spans passed to the interfaces stay valid until their task finishes; implementations that hand work to another thread must copy.
- **Shared code.** Header construction (`build_signature`), the opaque pre-checks, signature-size check, verifier/decrypter result normalization and content decryption (`jwe::open`) are shared by the sync and async paths, so they can't drift apart.
- **Tests** use test doubles whose operations really suspend and resume on another thread. The whole suite also passes under ASan+UBSan and TSan.
- **JWT** (Phase 3 item 12): `signed_builder` and `nested_builder` have `token_async()` / `serialize_async()`; `signed_jwt::claims_async(async_opaque_verifier&)`, `encrypted_jwt::claims_async(async_opaque_key_decrypter&, options)` and `nested_jwt::decrypt_async(async_opaque_key_decrypter&, options)`. `encrypted_builder` has no async form, since a JWE is encrypted to a public or local key and there's no opaque encrypter. Unlike the JWS/JWE member functions, these copy the builder's state or the parsed token into the task (JWTs are small), so a temporary builder or a parsed token that goes away before the task runs is fine; only the verifier or decrypter passed by reference must outlive it. `nested_jwt::decrypt_async` copies the signature allowlist and `understood` given to `parse_signed_and_encrypted`, so the inner JWS is held to them exactly as `decrypt()` holds it. Builder checks (`b64`, `cty`, claims errors) are shared with the sync builders and come back from the task without calling the signer. The sync `token()` / `serialize()` refuse an async signer with a message naming `serialize_async()`. Tested with the suspending doubles, including a nested JWT built and read through KMS keys in one coroutine, and that `understood` and the decrypt options reach the async paths; clean under ASan+UBSan (with `detect_container_overflow=0`, needed for Catch2's filter parsing against the uninstrumented system libc++) and TSan.

## go-jose Interop

Implementation notes for Phase 2 item 11 (details and the vector format in `tests/interop/README.md`):

- **Harness.** `tests/interop/go` (go-jose v4.1.9, pinned by `go.mod`/`go.sum`) generates and verifies; `jose_interop_gen` generates the jose2cpp side; `test_interop.cpp` verifies. Both directions cover all 13 JWS algorithms and 17 key-management × 6 content encryptions, compact and JSON, plus ECDH-ES on P-384/P-521, DEFLATE, PBES2 at each producer's default count, JSON `aad`, multi-signature and five-recipient JWE: 14 JWS + 112 JWE vectors each way. jose2cpp also re-serializes go-jose's tokens (compact byte-for-byte, JSON by value). Ed448 and X25519/X448 ECDH aren't covered: go-jose lacks them.
- **Checked-in vectors** (`tests/vectors/interop/`) run in the normal suite with no Go needed. `-DJOSE_INTEROP_GO=ON` adds ctest fixtures that generate fresh vectors on both sides and cross-check them, and an `interop_vectors` target that refreshes the checked-in files.
- **Known incompatibilities are tested, not skipped.** A `jws_incompatible` list holds vectors the other library must reject; if one starts being accepted, the test fails so it can be moved.
- **Findings:**
  - *RFC 7797 `b64=false`*: go-jose base64url-encodes the payload in the serialized token (and decodes it on parse) while signing it raw, contrary to RFC 7797 §3/§5. jose2cpp keeps the RFC behaviour (its §4 vectors pass); the two can't exchange unencoded-payload tokens.
  - *Stray top-level `encrypted_key`*: go-jose's general JWE JSON repeats the first recipient's `encrypted_key` at the top level. jose2cpp used to reject that as mixed general/flattened, so it couldn't read any multi-recipient go-jose JWE. It now ignores exactly that copy (it isn't authenticated and nothing reads it); any other mix is still rejected.
  - *Compact JWE with AAD*: go-jose's `CompactSerialize` silently drops `aad`, yielding an undecryptable token; jose2cpp's `compact()` refuses.
- **CI**: `.github/workflows/ci.yml` builds and tests on Ubuntu 24.04 with Go installed and `JOSE_INTEROP_GO=ON`.

## JWT

Implementation notes for Phase 3 (`include/jose/jwt.hpp`, namespace `jose::jwt`).

- **Builders** (item 1): `jwt::signed_token(signer)`, `jwt::encrypted_token(enc, recipient)` and `jwt::signed_and_encrypted(signer, enc, recipient)`, like go-jose's `jwt.Signed` / `Encrypted` / `SignedAndEncrypted`. `claims()` takes a `nlohmann::json` object or anything nlohmann can serialize to one (a struct with `to_json`), and can be called repeatedly; `token()` returns the `jws` / `jwe`, `serialize()` the compact form. The first error in a chain is kept and reported at the end, so a chain needs one check.
- **Claim names given twice are an error.** go-jose merges claim sets and keeps the last value, which lets a private-claims struct silently replace `exp` or `sub`; jose2cpp refuses instead. Also errors (`errc::serialization_error`), anywhere in the claim tree: strings that aren't valid UTF-8, NaN and infinity (nlohmann would write `null`, turning an overflowed `exp` into a token that never expires; go-jose's `json.Marshal` fails too), discarded values (nlohmann writes `<discarded>`, which isn't JSON) and binary values. Claims that aren't a JSON object are `errc::invalid_argument`.
- **Error order.** An error in the builder's options (`b64=false`, a nested token's conflicting `cty`) is reported before a claims error, since the options were given first.
- **Lifetimes.** `claims()` on a temporary builder returns the builder by value, so `auto& b = jwt::signed_token(s).claims(c);` doesn't compile instead of dangling.
- **Key-management algorithms: the split rule.** An encrypted-only JWT has no signature, so anyone who can encrypt to the recipient can mint one: with RSA or ECDH-ES that's anyone holding the public key, and PBES2 rests on a password. Encrypted-only JWTs therefore accept only `dir`, `A*KW` and `A*GCMKW`; the others are `errc::invalid_argument` in `jwt::encrypted_token` and when listed in a `jwt::parse_encrypted` allowlist (checked against the list itself, so a misconfigured service fails on its first token, whatever that token uses). The check is an allowlist of the seven symmetric algorithms, so a key algorithm added later is refused until someone decides otherwise. go-jose enforces the limit only when parsing; its `jwt.Encrypted` builder doesn't, so it can emit encrypted-only JWTs that neither library parses. A nested JWT is authenticated by its inner signature, so it may use any key-management algorithm, including RSA-OAEP and ECDH-ES as OIDC encrypted ID tokens do. go-jose v4.1.9 applies the encrypted-only restriction to nested JWTs as well (in its code and tests; its docs don't mention it), so it can't read jose2cpp's nested JWTs that use RSA, ECDH-ES or PBES2 outside. The interop suite keeps such tokens in a `jwt_incompatible` list and checks that go-jose still rejects them, with that specific error.
- **Parsing** (item 2): `jwt::parse_signed(token, algs)`, `jwt::parse_encrypted(token, key_algs, encs)` and `jwt::parse_signed_and_encrypted(token, key_algs, encs, sig_algs)`, like go-jose's `ParseSigned` / `ParseEncrypted` / `ParseSignedAndEncrypted`. Compact form only; every allowlist is mandatory. `signed_jwt::claims(key | jwk_set | opaque_verifier&)` verifies and then returns the claims; `encrypted_jwt::claims(...)` decrypts; `nested_jwt::decrypt(...)` returns the inner `signed_jwt`. `unsafe_claims()` exists for choosing a key before verifying. Claims must be a JSON object, parsed strictly (duplicate members rejected); `jwt::decode<T>` converts them with `from_json`, reporting a type mismatch (any `nlohmann::json` exception) as `errc::invalid_token`; other exceptions from the caller's own `from_json` pass through. A nested JWT's JWE must carry `cty` "JWT", compared case-insensitively as media types are (go-jose upper-cases too); `parse_encrypted` points a token with that `cty` at `parse_signed_and_encrypted`. A JWS with `b64=false` isn't a JWT. Validating `exp`, `aud` and friends is items 3–5.
- **Nested parsing** (item 6; the API landed with item 2): `parse_signed_and_encrypted` checks the JWE and its `cty` before anything is decrypted, and `nested_jwt::decrypt(key | jwk_set | opaque_key_decrypter&)` decrypts and then parses the plaintext with `parse_signed` and the signature algorithms given up front. As in go-jose's `NestedJSONWebToken.Decrypt`, the plaintext must be one compact JWS. The bare claims, a JSON-serialized JWS, a `b64=false` JWS, an empty plaintext, and a second nested JWE inside (RFC 7519 §7.2 step 8 allows nesting again; neither library does) are refused after decryption with `parse_signed`'s error for the same string, never `decryption_failed`. A compressed (`"zip":"DEF"`) JWE works, and `jwe_decrypt_options::max_decompressed_size` applies. The one `understood` set given to `parse_signed_and_encrypted` covers critical extensions on both the JWE and the JWS inside. The interop suite has a compressed nested JWT each way, requires at least one per file, and checks the `zip` header is really there.
  - Whitespace: see §Compact whitespace. A nested JWS with a trailing newline is read; one with a line break inside is refused (go-jose's JWT parser accepts that one). `cty` must be "JWT" in any case; `"application/jwt"` is refused, by go-jose too.
  - The claims leave `secure_bytes` once parsed: the decrypted JWS and the claims JSON are ordinary strings, not wiped on release. Encryption keeps them confidential in transit, not in the recipient's memory.
- **Registered claims** (items 3–4, `include/jose/jwt_claims.hpp`): `jwt::registered_claims` (`issuer`, `subject`, `audience`, `expiry`, `not_before`, `issued_at`, `id`), `jwt::numeric_date` and `jwt::audience`, like go-jose's `Claims`, `NumericDate` and `Audience`. They convert through nlohmann `to_json` / `from_json`, so they go straight into the builder's `claims()`, come back through `jwt::decode<T>`, and work as members of an application's own claims struct. Absent claims are `std::nullopt` (an empty `audience`) and are omitted when writing. Two differences from go-jose: an empty string is kept as present, and a registered claim set to `null` is malformed, where go-jose reads `null` as absent for every registered claim except `aud` (so `"exp": null` would mean "never expires"). Private claims are ignored by `registered_claims`.
  - `numeric_date` wraps `std::chrono::sys_seconds`. It's written as an integer. When read, a fraction truncates toward zero, as in go-jose, and anything at or beyond ±2^62 seconds is refused (go-jose's bound), so adding a leeway or lifetime to a parsed date can't overflow and turn a future `nbf` into a past one. Dates the caller constructs aren't range-checked; the header says to keep them within the bound. go-jose parses every NumericDate as a double first, so integers just below 2^62 round up to it and are refused there, and integers above 2^53 lose precision; jose2cpp reads integers exactly. Those dates are millions of years out, so the difference is noted rather than copied.
  - `audience` reads one string or an array of strings and writes a single value as a string, several as an array, as go-jose does. `contains()` is exact and case-sensitive (RFC 7519 §4.1.3).
  - A malformed registered claim (`"exp":"tomorrow"`, `"aud":[1]`) is `errc::invalid_token` from `jwt::decode`, with the claim named. Called directly, `from_json` throws a `nlohmann::json::exception`, as nlohmann conversions do.
- **Validation** (item 5): `registered_claims::validate(expected_claims, leeway = default_leeway)`, like go-jose's `Claims.ValidateWithLeeway` / `Expected`. `expected_claims` has optional `issuer`, `subject`, `id`, an `any_audience` that must intersect `aud`, and an optional `time` (unset means now); `default_leeway` is go-jose's one minute. Checks run in go-jose's order (iss, sub, jti, aud, nbf, exp, iat) and the first failure is returned: `errc::missing_claim` for an expected claim that's absent, `errc::invalid_claim` (new) for one that doesn't match, `errc::not_yet_valid` for `nbf` and for `iat` in the future, `errc::expired`. A leeway of 2^62 seconds or more either way is `errc::invalid_argument`. The only arithmetic is `time ± leeway` (the dates are only compared), and `system_clock`'s range is far below 2^62 seconds, so that bound keeps it from overflowing whatever the dates hold. The time is floored to a second before comparing, which gives the exact answer because the dates and the leeway are whole seconds.
  - As in go-jose, `aud` is only checked when `any_audience` is set and absent time claims aren't required. RFC 7519 §4.1.3 says a recipient must reject a token whose `aud` doesn't name it. Decided to keep go-jose's behaviour: rejecting any token with `aud` when `any_audience` is unset would make `aud` effectively required, and a caller who forgot to set it would see valid tokens start failing. The header and README tell callers to set `any_audience` whenever tokens carry one.
  - Differences from go-jose: a token is expired at exactly `exp` + leeway (RFC 7519 §4.1.4, "on or after"), where go-jose still accepts it; and an empty-string expectation is checked, where go-jose reads `""` as "don't check".
  - Interop: go-jose generates 40 validation cases (`jwt_validation` in `gojose.json`) with its own answers, covering each claim, the check order (iat after nbf and exp included), the second and microsecond either side of `nbf` and `exp`, default and negative leeway, `iat` in the future and times before the epoch, including one that only passes if the time is floored rather than truncated. jose2cpp must give the same answer for each, except the three cases at the instant of expiry, which are listed and must still differ.
- **Headers.** `"typ":"JWT"` is set on every token unless the caller sets `typ` in any header part. go-jose leaves `typ` to the caller. RFC 7519 §5.1 recommends "JWT" for generic tokens; RFC 8725 §3.11 recommends an application-specific type (e.g. `at+jwt`) where one exists, which the caller can still set. A nested token's JWE gets `"cty":"JWT"` (RFC 7519 §5.2); go-jose makes the caller set it and fails otherwise, jose2cpp sets it and refuses a different value. JWTs are compact with a base64url payload, so `b64=false` is refused.

## Compact whitespace

`jws::parse_compact` and `jwe::parse_compact` (and everything built on them: `parse`, `parse_detached`, every `jwt::parse_*`) ignore leading and trailing whitespace (space, tab, CR, LF, the set JSON allows around the JSON serializations), so a token read from a file, an environment variable or a hand-copied header parses. Whitespace inside a base64url part is refused: `errc::invalid_base64` with a message naming whitespace, once that part is decoded (an earlier check, such as the algorithm allowlist, can fail first). An unencoded (`b64=false`) JWS payload is taken as is, apart from `.`, as RFC 7797 §5.2 allows; it's signed, so it can't be respelled. Unicode whitespace other than those four (NBSP and so on) isn't trimmed.

go-jose v4.1.9 isn't consistent itself. Its deprecated generic `jose.ParseSigned`, `ParseDetached` and `ParseEncrypted` strip all Unicode whitespace anywhere (`stripWhitespace`). Its `ParseSignedCompact` and `ParseEncryptedCompact`, which the whole `jwt` package uses, strip nothing, but Go's base64 decoder skips CR and LF anywhere; so for a go-jose JWT a line break anywhere is accepted and a space or tab anywhere, even at the ends, is refused. Against that, jose2cpp accepts a trailing space or tab that go-jose's JWT parser refuses, and refuses a line break inside the token that go-jose accepts.

jose2cpp doesn't accept whitespace inside the token because RFC 7515 §2 and RFC 7516 §2 define compact parts as base64url "without the inclusion of any line breaks, whitespace, or other additional characters", and because it gives one token many spellings. A service that keeps a revocation list or replay cache keyed on the raw token string can then be dodged by changing the spelling. Even `compact()` of the parsed token isn't a safe key: ECDSA signatures are malleable (`(r, n-s)` verifies whenever `(r, s)` does, and OpenSSL accepts high-S), so an ES256 token has two valid signatures. Such lists should key on `jti`, or on the signing input (protected header and payload), not on the token.

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
