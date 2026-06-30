# jose-pp Implementation Plan

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
jose-pp/
├── CMakeLists.txt
├── vcpkg.json
├── include/
│   └── jose/
│       ├── jose.hpp              # umbrella header
│       ├── base64url.hpp
│       ├── error.hpp             # error types (std::expected based)
│       ├── algorithm.hpp         # algorithm enum + registry
│       ├── jwk.hpp               # JWK / JWKSet
│       ├── jws.hpp               # JWS sign/verify/parse
│       ├── jwe.hpp               # JWE encrypt/decrypt/parse
│       ├── jwt.hpp               # JWT builder/parser/validator
│       ├── header.hpp            # JOSE header types
│       ├── async.hpp             # task<T>, async opaque interfaces
│       └── crypto/
│           ├── rsa.hpp
│           ├── ec.hpp
│           ├── eddsa.hpp
│           ├── hmac.hpp
│           ├── aes_kw.hpp
│           ├── aes_gcm_kw.hpp
│           ├── aes_cbc_hmac.hpp
│           ├── aes_gcm.hpp
│           ├── ecdh.hpp
│           ├── pbes2.hpp
│           └── openssl_util.hpp  # RAII wrappers, secure_vector
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
│       ├── rsa.cpp
│       ├── ec.cpp
│       ├── eddsa.cpp
│       ├── hmac.cpp
│       ├── aes_kw.cpp
│       ├── aes_gcm_kw.cpp
│       ├── aes_cbc_hmac.cpp
│       ├── aes_gcm.cpp
│       ├── ecdh.cpp
│       ├── pbes2.cpp
│       └── openssl_util.cpp
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
| EdDSA | `EVP_DigestSign` (Ed25519) |

### JWE Key Management (17 algorithms)

| Algorithm | OpenSSL Primitive |
|-----------|-------------------|
| RSA1_5 | `EVP_PKEY_encrypt` (PKCS1) |
| RSA-OAEP / RSA-OAEP-256 | `EVP_PKEY_encrypt` (OAEP) |
| A128KW / A192KW / A256KW | `EVP_CIPHER` (AES wrap) |
| dir | Direct key use |
| ECDH-ES / ECDH-ES+A*KW | `EVP_PKEY_derive` + Concat KDF |
| A128GCMKW / A192GCMKW / A256GCMKW | `EVP_CIPHER` (AES-GCM) |
| PBES2-HS*+A*KW | `PKCS5_PBKDF2_HMAC` + AES wrap |

### JWE Content Encryption (6 algorithms)

| Algorithm | OpenSSL Primitive |
|-----------|-------------------|
| A128CBC-HS256 / A192CBC-HS384 / A256CBC-HS512 | `EVP_CIPHER` (AES-CBC) + `EVP_MAC` (HMAC) |
| A128GCM / A192GCM / A256GCM | `EVP_CIPHER` (AES-GCM) |

---

## Core Design Decisions

### 1. Error Handling: `std::expected<T, jose::error>`

No exceptions. Every fallible operation returns `std::expected`. This is both safer for crypto code (no exception-safety bugs around key material) and more performant.

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

### 2. Memory Safety: `secure_vector<uint8_t>`

Key material lives in `secure_vector` — a custom allocator that zeros memory on deallocation and optionally calls `mlock`. All crypto intermediates use this type.

```cpp
template<typename T>
struct secure_allocator {
  void deallocate(T* p, size_t n) noexcept {
    OPENSSL_cleanse(p, n * sizeof(T));
    std::allocator<T>{}.deallocate(p, n);
  }
  // ...
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
  static auto generate_oct(size_t bytes) -> expected<jwk, error>;
  static auto generate_okp() -> expected<jwk, error>; // Ed25519

  auto to_json() const -> nlohmann::json;
  auto public_key() const -> expected<jwk, error>;
  auto thumbprint(hash_algorithm h = hash_algorithm::SHA256) const -> expected<std::string, error>;
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
  auto keys() const -> std::span<const jwk>;
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

### Phase 1: Foundation + JWA (Weeks 1-3)

The crypto layer and core utilities. Everything else builds on this.

**Deliverables:**
1. Build system (CMake + vcpkg manifest for OpenSSL, nlohmann/json, Catch2)
2. `base64url` encode/decode (no padding, URL-safe alphabet)
3. `secure_vector` and OpenSSL RAII wrappers
4. `error` types with `std::expected`
5. Algorithm enums and string conversion registry
6. All signing primitives: HMAC, RSA (PKCS1 + PSS), ECDSA, EdDSA
7. All content encryption: AES-CBC-HMAC, AES-GCM
8. All key management: RSA-OAEP, AES-KW, AES-GCM-KW, ECDH-ES (+Concat KDF), PBES2, direct
9. Tests against RFC test vectors for every algorithm

**Risk:** ECDH-ES Concat KDF is not directly exposed by OpenSSL — we'll need a manual implementation using `EVP_PKEY_derive` for the shared secret and then a custom Concat KDF (it's just SHA-256 based, straightforward).

### Phase 2: JWK + JWS + JWE (Weeks 4-6)

Wire the crypto primitives into the JOSE object model.

**Deliverables:**
1. `jwk` — parse/serialize all key types (RSA, EC, OKP, oct), X.509 chain, thumbprint
2. `jwk_set` — parse/serialize, kid lookup
3. JOSE header parsing with `crit` validation
4. `jws` — sign, verify, compact/JSON/detached serialization, multi-signature
5. `jwe` — encrypt, decrypt, compact/JSON serialization, multi-recipient, DEFLATE compression
6. Unencoded payload option (RFC 7797, `b64` header)
7. Opaque signer/verifier/decrypter interfaces — both sync and async variants
8. `task<T>` coroutine return type (header-only, zero-dependency)
9. Async-aware JWS/JWE overloads that accept `async_opaque_signer` / `async_opaque_key_decrypter`
10. Interop tests: produce tokens with go-jose, consume in jose-pp and vice versa

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
9. API documentation (Doxygen)
10. Benchmarks vs. go-jose (sign/verify throughput, parse latency)

---

## Performance Strategy

1. **Zero-copy parsing** — `std::string_view` for token parts during parse; only allocate for validated output
2. **EVP API only** — no deprecated low-level OpenSSL calls; EVP is hardware-accelerated where available (AES-NI, SHA extensions)
3. **Avoid redundant allocations** — pre-size buffers based on algorithm output sizes
4. **`std::expected` over exceptions** — no exception overhead on error paths
5. **Header-only option** — consider offering a header-only mode for the non-crypto parts (serialization, claims)
6. **Thread safety** — all operations are stateless; keys are immutable after construction

---

## Build System

```cmake
cmake_minimum_required(VERSION 3.20)
project(jose-pp VERSION 0.1.0 LANGUAGES CXX)
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

1. **Ed448 / X25519 / X448** — Yes, add X25519 for ECDH-ES at minimum. Competitive advantage over go-jose. OpenSSL 3.x has native support.
2. **JWKS fetching** — Yes, as an optional async component with pluggable HTTP backend. Not in core, no HTTP dependency in the main library.
3. **Namespace** — `jose::` (clean, matches the standard).
4. **Minimum OpenSSL version** — 3.0+ only. 1.1.1 is EOL.
5. **CMake install/pkg-config** — Yes, ship as a proper CMake package with `find_package(jose)` from day one.
6. **Async/coroutine support** — Targeted: core crypto stays synchronous, async applied only to opaque signer/decrypter interfaces (for KMS/HSM) and the optional JWKS fetcher. Custom `task<T>` type, no external coroutine library dependency.
