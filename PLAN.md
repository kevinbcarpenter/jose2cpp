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
│   ├── fuzz_common.hpp      # algorithms, keys, check()
│   ├── fuzz_base64url.cpp
│   ├── fuzz_jwk.cpp
│   ├── fuzz_jws.cpp
│   ├── fuzz_jwe.cpp
│   ├── fuzz_jwt.cpp
│   ├── fuzz_inflate.cpp
│   ├── replay_main.cpp      # main() where there's no libFuzzer
│   ├── make_corpus.py       # seeds from tests/vectors
│   └── corpus/
├── benchmarks/
│   ├── bench_main.cpp       # jose_bench
│   ├── go/main.go           # the same cases with go-jose
│   ├── compare.py           # runs both, prints the table
│   └── keys.json            # keys both sides use
└── tools/
    ├── cli.hpp / cli.cpp       # jose-cli's commands (tested in-process)
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

This avoids baking in an HTTP dependency (no curl, no Boost.Beast in core) while giving users a clean integration point. The fetcher handles caching, TTL-based refresh, and thread-safe key rotation. (The sketch above is the original plan; §JWKS Fetcher has what was built and why it differs.)

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
7. ✅ Optional async JWKS URL fetcher with pluggable HTTP backend, caching, TTL refresh (see §JWKS Fetcher)
8. ✅ CLI tool (`jose-cli`): sign, verify, encrypt, decrypt, expand, generate-key (see §CLI)
9. ✅ Fuzz targets (libFuzzer): `jwk::from_json`, `jws::parse`, `jwe::parse`, the `jwt::parse_*` and registered claims, base64url, DEFLATE inflation (see §Fuzz Testing)
10. ✅ API documentation (Doxygen) (see §API Documentation)
11. ✅ Benchmarks vs. go-jose (sign/verify throughput, parse latency) (see §Benchmarks)
12. ✅ Async opaque keys for JWT: build with an `async_opaque_signer` and parse with `async_opaque_verifier` / `async_opaque_key_decrypter` (`claims_async`, `nested_jwt::decrypt_async`), reusing the allowlists and `understood` given at parse time so a caller can't widen them on a second call. (see §Async Opaque Keys)

---

## Performance Strategy

1. **Zero-copy parsing** — `std::string_view` for token parts during parse; only allocate for validated output
2. **EVP API only** — no deprecated low-level OpenSSL calls; EVP is hardware-accelerated where available (AES-NI, SHA extensions)
3. **Avoid redundant allocations** — pre-size buffers based on algorithm output sizes
4. **`std::expected` over exceptions** — no exception overhead on error paths
5. **Header-only option** — consider offering a header-only mode for the non-crypto parts (serialization, claims)
6. **Thread safety** — all operations are stateless; keys are immutable after construction. `jwks_fetcher` swaps in each new set as a `shared_ptr<const jwk_set>` under a mutex held only for the swap or a pointer copy (libc++ has no `atomic<shared_ptr>`), so a set a caller holds stays valid through rotation

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
- **PBES2 on decrypt**: `p2c` must be in [1000, 1 000 000] and `p2s` at least 8 octets (`errc::invalid_header`), bounding attacker-chosen work per recipient. On top of that, `jwe_decrypt_options::max_pbes2_iterations` (default 1 000 000) caps the total `p2c` one decrypt call spends across every recipient and key it tries (`decrypt_multi`'s recipients, `decrypt(jwk_set)`'s candidate keys). Before it, a JSON JWE with many PBES2 recipients cost a full PBKDF2 run each (20 at `p2c` 1 000 000 took 3.6 s in the CLI review). Running out is `errc::invalid_header` and ends the call, so a token can make a decrypter run PBKDF2 at the largest `p2c` once. Three recipients at jose2cpp's own default of 310 000 still fit, but only one at go-jose's default of 600 000 (`symmetric.go` `defaultP2C`), so a caller expecting go-jose tokens with several PBES2 recipients raises the budget; the header and README say so. 0 refuses PBES2. go-jose has no such total (only the per-recipient 1 000 000 and its recipient cap). Opaque decrypters do their own key unwrap and aren't counted.
- **At most 32 recipients** (`jwe::max_recipients`, go-jose's `MaxRecipients`): more is `errc::invalid_token` when parsing JSON and `errc::invalid_argument` when encrypting, so jose2cpp never makes a JWE that it or go-jose would refuse. Likewise `jws::max_signatures` = 32 (go-jose's `MaxSignatures`) for JWS, in `sign`, `sign_async` and JSON parsing. Tests in `tests/test_limits.cpp`.
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

## JWKS Fetcher

Implementation notes for Phase 3 item 7 (`include/jose/optional/jwks_fetcher.hpp`, `src/optional/jwks_fetcher.cpp`). go-jose has no fetcher, so there's nothing to match; the closest Go code is `jwx`'s `jwk.Cache` and `keyfunc`.

- **Opt-in by include.** It's compiled into `jose` (it needs nothing beyond what the library already links) but not included by `jose.hpp`. No HTTP library: callers implement `http_client::get(http_request) -> task<expected<http_response>>`. The request carries the URL, `timeout` and `max_response_bytes`, so a transport can enforce both; the fetcher re-checks the size but can't enforce a timeout without a timer. The request is passed by value, because `task` is lazy and a reference could dangle.
- **API, changed from the sketch.** `keys()`, `keys_for(kid)`, `refresh()` and `cached()`, each returning `shared_ptr<const jwk_set>`. The sketch's `get_cached()` returned a `reference_wrapper`, which would dangle the moment a refresh swapped the set. `keys_for` exists because a token's `kid` missing from the set is the usual sign of rotation. `max_cache_size` became `max_keys` (the most entries in `"keys"`), since there's one URL and one set to cache. An invalid config, or a null client, comes back from every call as `errc::invalid_argument` instead of from the constructor, as builder errors do.
- **When it fetches.** `keys()` fetches when the set is `refresh_interval` old (300 s) or missing; `keys_for` also fetches once when the `kid` isn't found; `refresh()` fetches on request. Every fetch is subject to `min_refresh_interval` (30 s, at most `refresh_interval`) since the last one started, success or not, so made-up `kid`s and a dead endpoint both get at most one request per interval. Single flight: callers that need a fetch while one is running wait for it (a waiter list resumed in order by whichever thread finishes the fetch), so `http_client` never sees two requests at once. `keys()` with a set still within `max_stale` never waits for another caller's fetch; it returns that set. (It does wait for a fetch it starts itself.)
- **Failures.** The old set is kept and served until it's `refresh_interval + max_stale` old (`max_stale` 3600 s), then callers get the last error. This trades availability against how long a withdrawn key stays trusted; `max_stale = 0` turns it off. Status other than 200 is `errc::key_unavailable`; a body that's too large, isn't strict JSON (duplicate members refused), has more than `max_keys` entries, or leaves no public key is `errc::invalid_key`; `http_client` errors pass through. The age of a set counts from when its fetch started.
- **Only public keys.** `oct` keys are dropped (a symmetric key at a public URL lets anyone sign; with HS* in a caller's allowlist that would be a forgery), private keys are reduced to `public_key()`, and keys `jwk_set::from_json` skips are dropped. The dropped keys' reasons aren't exposed.
- **HTTPS.** The URL must be `https://` (case-insensitive) unless `allow_http`; certificate checking is the transport's job and the header says so. HTTP caching headers are ignored.
- **Abandoned fetches.** The fetch is started and its guard created in one critical section, so nothing can throw in between and leave `in_flight` set. If `http_client` throws, the fetch is ended in a `catch` and the exception rethrown to the caller that started it; if the fetching task is destroyed while suspended, the guard's destructor ends it. Either way waiters get what `keys()` would without a fetch (the old set within `max_stale`, else `errc::key_unavailable`), the error is recorded and throttling applies. A waiting task that's destroyed takes itself off the list; waiters are released one at a time and only those of the fetch that finished, so a continuation that destroys another waiter or starts the next fetch is safe. Destroying a waiting task from another thread while a fetch is finishing isn't (no coroutine can be destroyed while someone else resumes it), and the header says so. The header also tells `http_client` authors that `get()`'s task may be destroyed mid-request and that `get()` can be re-entered from the previous completion. `refresh()` returns the old set rather than the error when a fetch fails within `max_stale`.
- **Durations** are limited to ten years so ages and sums can't overflow the clock's nanoseconds. A `clock` function in the config replaces `steady_clock::now` in tests.
- **Tests** (`tests/test_jwks_fetcher.cpp`): config checks, caching and throttling against a fake clock, every response rule, max_stale edges to the nanosecond, rate-limited `keys_for` with 100 forged `kid`s, single flight with parked requests (cold start, failure, stale set, abandoned fetch, an exception before and after suspending, waiter order, a destroyed waiter, and a waiter whose continuation starts the next fetch while the first's waiters are still being released), a JWT verified through the fetcher across a rotation, and eight threads mixing calls against a client that finishes each request on a new thread. Clean under ASan+UBSan and TSan.

## CLI

Implementation notes for Phase 3 item 8 (`tools/`, built with `-DJOSE_BUILD_CLI=ON` as `jose-cli`).

- **Modelled on go-jose's `jose-util`** (v4.1.9): the same commands (`sign`, `verify`, `encrypt`, `decrypt`, `expand`, `generate-key`) and flags (`--key`, `--alg`, `--enc`, `--in`, `--out`, `--full`, `--format`, `--use`, `--size`, `--kid`), accepted as `-flag` or `--flag`, with the value next or after `=`, boolean values in `strconv.ParseBool`'s spellings and `--` ending the flags, as Go's `flag` package does. Differences that can break a `jose-util` command line: a single-valued flag given twice is an error (Go keeps the last), and so is a positional argument (Go stops parsing there and `jose-util` ignores the rest); both are in the README. An empty `--kid` means the thumbprint, as in `jose-util`. Keys load as PEM, DER (PKCS#8, PKCS#1 private and public, SEC 1, SubjectPublicKeyInfo, X.509) or JWK, as `jose-util`'s do. DER is decoded per key type (RSA, EC, Ed25519, Ed448, X25519, X448) because an untyped OpenSSL decode reads a PKCS#1 RSA public key as DH parameters; trailing bytes after the DER are refused, and the OpenSSL error queue is restored afterwards; `--full` and `expand` write the flattened JSON form for one signature or recipient, which is what go-jose's `FullSerialize` writes, and `expand` of a JWS is byte-for-byte the same.
- **The key is the allowlist.** `jose-util` passes every algorithm to the parser and lets the token choose. Without `--alg`, `jose-cli` also parses with every algorithm, but `jws::verify*` and `jwe::decrypt*` check the key against each signature's or recipient's `alg` (`jwk::check_algorithm`) before using it, so only algorithms the key suits can succeed: an RSA key never verifies an HS256 token. Parsing with the full list rather than the key's own list lets a JSON JWS or JWE through whose other signatures or recipients use other algorithms. If the key suits no algorithm at all, the command fails before reading input. `--alg` / `--enc` (repeatable or comma-separated) make an explicit allowlist, and then the library's rule applies: every signature or recipient must use a listed algorithm. With a JWK Set, each key is tried against every signature or recipient (`verify_multi` / `decrypt_multi`), so a set works with multi-signature and multi-recipient JSON too.
- **Beyond `jose-util`:** JWK Sets for `verify`/`decrypt`; `--alg` defaulting to the key's `alg`; `encrypt --zip`; RSA1_5 behind `--allow-legacy` on both sides; multi-signature/multi-recipient JSON input (first signature or recipient the key opens); `generate-key` for symmetric algorithms (`dir` sized by `--enc` or `--size`) and, with `--crv`, Ed448/X25519/X448 (`jose-util` makes only RSA, P-curves and Ed25519). `expand` works out JWS or JWE from the number of parts (or, for JSON input, which it accepts as `jose-util` does, from `ciphertext`) where `jose-util` assumes JWE. PBES2 isn't offered by `generate-key` (a password isn't generated), and the CLI has no password flag; a PBES2 key is an oct JWK holding the password.
- **Files.** `generate-key` writes `jwk-USE-KID-priv.json` (0400) and, for asymmetric keys, `-pub.json` (0444), created with `O_EXCL` so nothing is overwritten and the private file is never briefly readable by others. On Windows it's `_wsopen_s` with `_O_EXCL` and read-only, which doesn't restrict who can read it (the file inherits the folder's ACL); the README says so. Both names are checked first with `symlink_status` (a dangling symlink counts as taken), the private file is written first, a later failure removes what was written, and the paths are printed only when all are written. `decrypt --out` creates a new file 0600 (an existing file keeps its mode); other `--out` files get 0666 less the umask (`jose-util` uses 0644). `--out` follows symlinks, as `jose-util` does. A `kid` keeps only `[A-Za-z0-9._-]` in the file name (others become `_`, and a leading `.` gets a `_`), so `--kid ../x` can't leave the directory; the `kid` inside the key is unchanged. The default `kid` is the unpadded base64url RFC 7638 thumbprint (go-jose pads it).
- **Input.** Files are read with stdio and `ferror`, since a `filebuf` reports a read error (a directory, a failing device) as end of file; a directory is refused by name. A failed read is exit 1, never an empty payload. Exceptions (a path that can't be converted on Windows, out of memory) are caught in `run()` and reported as exit 1.
- **Key material in memory.** Key file contents and the generated private JWK's JSON are wiped (`OPENSSL_cleanse`) when the command finishes, and the key file buffer is sized up front so it isn't copied while growing. Best effort: copies made inside the JSON and PEM parsers aren't reached.
- **Output.** Tokens are followed by a newline (`jose-util` writes none except after `expand`); parsing trims it. Payloads and plaintexts are written exactly. Exit status 0, 1 when the operation fails, 2 for a bad command line. Windows: stdin and stdout are switched to binary.
- **PBES2 cost.** The review found that a JSON JWE with many PBES2 recipients cost the decrypter a full PBKDF2 run each (20 recipients at `p2c` 1,000,000 took 3.6 s), which the CLI's default "every algorithm" list exposed for a password key. Fixed in the library: at most 32 recipients, and a total PBKDF2 budget per decrypt call (§JWE). The CLI makes one `decrypt_multi` call per key in its key file, each with its own budget, so a JWK Set of k password keys allows k times the budget; the key file is the operator's, so the multiplier isn't the attacker's to choose.
- **Tests.** `tests/test_cli.cpp` runs the commands in-process (`jose::cli::run` with string streams): usage errors and Go's flag spellings; private keys as PKCS#8, PKCS#1 and SEC 1 in PEM and DER, public keys as SPKI, PKCS#1 and X.509 in PEM and DER, and trailing DER bytes; JWK Sets with single- and multi-signature/recipient tokens; allowlists, an RSA public key used as an HMAC secret, bad signatures and wrong keys; a directory as input; RSA1_5; PBES2; `--zip`/`--full`; `decrypt --out` permissions; `expand` against `jose-util`'s own test vector and of JSON input; `generate-key` for each key family and most algorithms, its file permissions under any umask, an empty `--kid`, a dangling symlink in the way, refusals, and a `kid` that tries to escape. The `cli.usage_error` ctest checks for exit status 2 exactly. With `-DJOSE_INTEROP_GO=ON`, ctest builds `jose-util` from the pinned module and `tests/interop/cli_interop.cmake` crosses the two tools: six signature algorithms and five encryption pairs in both directions, with keys from both tools' `generate-key`, `--full` and `--zip`, and `expand` compared byte for byte.

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

Phase 3 item 9. libFuzzer targets in `fuzz/`, built with `-DJOSE_FUZZ=ON`.

- **Targets** (each also checks invariants, and aborts when one breaks):
  - `fuzz_base64url`: `decode` then `encode` gives back the input (strict decoding accepts one spelling only), and `encode` then `decode` gives back the bytes.
  - `fuzz_jwk`: `jwk::from_json`, `jwk_set::from_json`, and `jwk::from_pem` when the input contains `-----BEGIN` (OpenSSL's decoder setup costs about 1 ms a call, which held the whole target to about 1K executions a second). A parsed key serializes and parses again with the same type, privacy and thumbprint, and its public half has the same thumbprint; `check_algorithm` / `check_operation` run for every algorithm and operation.
  - `fuzz_jws`: `jws::parse` with every algorithm allowed, and `parse_detached`. A parsed JWS re-serializes (JSON and, where it can, compact) to one that parses to the same payload, algorithms, protected headers and signatures, and serializing that gives exactly the same text again; `verify_multi` runs with a key of every kind, and `verify` with all of them as a JWK Set.
  - `fuzz_jwe`: `jwe::parse` with every algorithm and encryption allowed. The same round trips, with the text-identical second serialization covering the headers, `aad`, `iv`, ciphertext and `tag`, then `decrypt_multi` with every key and `decrypt` with the set, RSA1_5 enabled and `max_pbes2_iterations` lowered to 20,000 so a high `p2c` doesn't slow the fuzzer.
  - `fuzz_jwt`: `parse_signed`, `parse_encrypted`, `parse_signed_and_encrypted` and their `claims` / `decrypt`; the unverified claims, and the input itself read as JSON, go through `jwt::decode<registered_claims>`, `validate` at extreme times and leeways, and a JSON round trip that must give back the same claims.
  - `fuzz_inflate`: `internal::inflate_raw` with a 1 MiB cap and with caps of 0, 1 and 100: output never exceeds the cap, and what inflates deflates and inflates back unchanged. The library only inflates after a JWE authenticates, which forged tokens never reach, so the inflater gets its own target.
- **Keys** (`fuzz/fuzz_common.hpp`, `fuzz/fuzz_keys.inc`): one of every kind (RSA 2048, P-256/384/521, Ed25519, Ed448, X25519, X448, oct 16-64 octets, a password), fixed JWKs generated once with `jose-cli generate-key` (with `alg` and `use` removed), so a crash reproduces in another process. RSA1_5 decryption still uses a random fallback CEK by design (oracle protection), so that one path isn't deterministic. Fuzzed tokens won't verify or decrypt, but everything up to the cryptography runs, plus the key checks.
- **Build.** `JOSE_FUZZ` probes for `-fsanitize=fuzzer`. With it, the library is compiled with `-fsanitize=fuzzer-no-link` for coverage and carries it as a public link option, so the tests and CLI link the coverage runtime with any `JOSE_FUZZ_SANITIZERS`, empty included (they used to fail with an undefined `__sancov_lowest_stack` when the sanitizers were empty); the targets compile and link with `-fsanitize=fuzzer`. Without it (Apple clang, GCC), each target links `fuzz/replay_main.cpp` and runs the files or directories it's given once. The whole build gets `JOSE_FUZZ_SANITIZERS` (default `address,undefined`, no recovery) and `-UNDEBUG -D_GLIBCXX_ASSERTIONS`, so expected-lite's assert on dereferencing an error and libstdc++'s checks stay on in any build type (clang 18 with libstdc++ 13 picks expected-lite, since clang 18 doesn't advertise the concepts level libstdc++'s `<expected>` wants). MSVC is refused with a message. Replay tests have a 900 s timeout: GCC at `-O0` takes about 90 s on the JWE corpus. ctest replays the corpus either way (`-runs=0` with libFuzzer, so the checked-in corpus isn't written to).
- **Corpus.** `fuzz/corpus/<target>/`, 902 seeds (about 330 KB): 889 written by `fuzz/make_corpus.py` from the RFC vectors and both directions of the go-jose interop vectors, plus hand-made claims at the date limits and raw DEFLATE streams (whole and truncated), and 13 PEM keys and certificates for `fuzz_jwk` made once with `openssl`. Seeds are named by SHA-1 so rerunning the script adds only new ones. The checked-in corpus is seeds only; units found by fuzzing aren't merged back, to keep the repository small and the seeds reproducible.
- **CI.** A `fuzz` job on Ubuntu 24.04 with clang 18 builds the targets, replays the corpus, fuzzes each target for 60 s on a scratch copy of its corpus (every target runs even if one fails; the step fails at the end), symbolizes ASan traces with `llvm-symbolizer`, and uploads any crashing input as an artifact.
- **First run** (clang 18 in an `ubuntu:24.04` container on an M-series Mac, two minutes per target, ASan+UBSan): no crashes, leaks, timeouts or broken invariants. Executions: base64url 15.1M, jwk 140K, jws 3.9M, jwe 2.8M, jwt 5.7M, inflate 14.0M.
- **Found in review: deep JSON.** A JWS or JWE JSON with an unprotected header nested about 20,000 levels (about 40 KB) overflowed the stack under ASan: `header::from_json` copies the value, and nlohmann's copy and serialization recurse. libFuzzer never got there, because `max_len` follows the largest seed (about 4 KB). Fixed in `internal::parse_json_strict`, which every library parse goes through: nesting more than 128 levels below the top is `errc::serialization_error`. Regression tests in `tests/test_limits.cpp` (each kind of token, a JWK, a JWK Set, JWT claims, and the 128/129 boundary); with the limit lifted they crash under ASan.

Fuzz targets must never crash, throw, or leak on any input. `std::expected` error returns are the expected failure mode. Any abort, ASAN violation, or undefined behavior is a bug.

## API Documentation

Phase 3 item 10. Doxygen, configured by `docs/Doxyfile`, with `docs/mainpage.md` as the front page.

- **Scope.** Every header under `include/jose` except `detail/` (the vendored expected-lite); `jose::detail` and `jose::*::detail` are excluded too. Private members aren't extracted. The README isn't used as the main page: its `#heading` links and relative links to other files don't resolve in Doxygen, and the README is written for GitHub.
- **Comments.** The headers already explained themselves in `//` comments, so those became `///` (blocks above a declaration), `///<` (after a member) and `@file` (each file's opening block); indented examples became `@code` blocks and the two error tables became Markdown tables. Comments inside function bodies and section dividers (`// --- Parsing ---`) were left as they were; the parsing and verifying rules that used to sit under the dividers in jws.hpp and jwe.hpp moved into the class descriptions, so they appear in the reference. Overload sets share one comment through `///@{ ... ///@}` with `DISTRIBUTE_GROUP_DOC`. The rest got new comments: the 278 symbols Doxygen reported as undocumented, plus the `errc` values and the namespaces, each checked against the implementation (the `errc` values against where each is returned, for instance).
- **Warnings are errors in CI.** `WARN_IF_UNDOCUMENTED` is on, and a `docs` job on Ubuntu 24.04 (Doxygen 1.9.8, the oldest version tested) builds with `WARN_AS_ERROR = FAIL_ON_WARNINGS` and uploads the HTML as an artifact. Doxygen only warns about free functions in files that have an `@file` block, so every header has one. Doxygen 1.18 (Homebrew) is also warning-free.
- **CMake.** `-DJOSE_BUILD_DOCS=ON` adds a `jose_docs` target (named so it can't clash with a parent project's `docs`) that writes a Doxyfile into the build directory (`@INCLUDE` of `docs/Doxyfile`, the output directory, `PROJECT_NUMBER` from `project(VERSION)`) and runs Doxygen from the source directory. `-DJOSE_DOCS_WARN_AS_ERROR=ON` sets `FAIL_ON_WARNINGS`. It's off by default, since a newer Doxygen may warn about things this one doesn't.
- **Not done.** The reference isn't published (GitHub Pages or similar); that's a decision for the repository owner. Examples in the comments aren't compiled.

---

## Benchmarks

Phase 3 item 11. `benchmarks/` holds a C++ runner (`jose_bench`), a go-jose v4 runner (`benchmarks/go`) and `compare.py`, which runs them in turn and prints a table. The results and how to read them are in `benchmarks/README.md`.

- **Same work on both sides.** 40 cases: JWS sign and verify for HS256, RS256, PS256, ES256/384/512 and EdDSA, JWE encrypt and decrypt for dir, A256KW, RSA-OAEP-256 and ECDH-ES (with and without A256KW), JWT sign and verify, parse-only JWS and JWE, JWK parsing, and 64 KiB payloads for HS256 and A256GCM. Each case is the public API as an application calls it, serialization and parsing included. Both read the keys from `benchmarks/keys.json` and use the same 222-byte claims payload, and each checks its round trip before timing, so a case can't quietly measure an error path.
- **Same timing loop.** No Google Benchmark or `testing.B`: each runner warms up for a quarter of a sample, sizes a batch to fill a sample (200 ms by default), times five batches and reports the median and the fastest. Writing it twice, about 40 lines each, keeps the two methods the same. `compare.py` alternates the sides (two rounds by default) and keeps each case's best median, so background load on one round doesn't decide a row.
- **Builds.** `-DJOSE_BUILD_BENCH=ON` adds `jose_bench`, and CMake warns when the build type isn't optimized (only a status line when tests are on, as in CI); the binary reports `"optimized"` too. The `bench` and `bench-macos` presets are Release builds with only the library and `jose_bench`. ctest runs every case once (`bench.smoke`, plus `bench.go_smoke` with `JOSE_INTEROP_GO=ON`), so CI keeps both runners building and their round trips passing. CI doesn't record timings: shared runners are too noisy for them to mean anything.
- **Found and fixed.** base64url, which every token goes through. Encoding appended one character at a time (a libc++ library call each); decoding first scanned the whole input for whitespace, so whitespace is reported ahead of any other error, and then branched on every character. A 64 KiB JWE took 203 µs to encrypt and 155 µs to decrypt, against go-jose's 47 µs and 43 µs. Now encoding writes into a presized buffer, decoding works four characters at a time from pre-shifted tables, and the whitespace scan runs only after a decode has failed (whitespace is outside the alphabet, so an input with any always fails, and the error is the same as before). The JWE now takes 31 µs and 30 µs. A test checks the codec against a bit-at-a-time reference for every length up to 200, an invalid character at every position in inputs up to 12 characters, every final character of 2- and 3-character tails, and whitespace winning over the other errors.
- **Found and fixed: ECDH-ES `"epk"`.** Encrypting took 84 µs against go-jose's 35 µs, mostly outside the key agreement: the ephemeral key got a full `EVP_PKEY_check`, a DER round trip for its public half, and three validations of the same `"epk"` (when it was set, again when the single-recipient merge called `header::set`, which re-parses the whole header on each call, and again in `join_headers`); decrypting validated it twice. Now `header::from_json_reusing` (private; used by `set`, `join_headers` and the merge) copies an already-parsed `"jwk"`, `"epk"` or `"x5c"` from a header it was built from when the JSON is identical, `jwk::ephemeral_public_json` writes the `"epk"` JSON straight from the ephemeral key without checks (the header validates it once), and EC `"x"`/`"y"` are read from the encoded point in one call rather than two affine conversions. Encrypt is 46 µs and decrypt 35 µs (1.3 and 1.2 times go-jose). OpenSSL 3.0 and 3.6 always encode the point uncompressed; the fallback to the two coordinate parameters is there for any version that doesn't. Tests cover re-validation of a replaced, erased-and-reset or broken key, and EC serialization whatever the point conversion form (the fixed RFC vectors check the encoded-point path byte for byte; neither OpenSSL version in use reaches the fallback). One visible change: for a single JWE recipient, a parameter set in both the protected header and the recipient is now reported (`errc::invalid_argument`) before an `x5c`/`x5t` mismatch across the two, where before the order depended on which name sorted first. Either way the input is refused.
- **Found and left as it is.** RSA `jwk` import takes 1.5 ms (public) and 19 ms (private) because of the §Key Validation checks (`EVP_PKEY_check` runs the SP 800-56B checks, primality tests included); go-jose checks size, exponent and `p*q == n` but no primality, and takes microseconds. Measured and explained in `benchmarks/README.md`.
