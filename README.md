# jose2cpp

C++ variation of the Go Jose library.

A modern C++20 JOSE (JSON Object Signing and Encryption) library.

## Quick start

Include the umbrella header and use the unified entry points — `sign`/`verify`
for all 13 JWS algorithms and `encrypt`/`decrypt` for all 6 JWE content
encryption algorithms. Every fallible call returns `jose::expected<T>`
(no exceptions); key material lives in `jose::secure_bytes`, which zeroes
memory on free.

```cpp
#include <jose/jose.hpp>

// --- Signing (dispatches on the algorithm: HMAC, RSA, ECDSA, EdDSA) ---
auto key = jose::generate_ec_key(jose::ec_curve::P256).value();
auto payload = std::span<const uint8_t>{...};

auto sig = jose::sign(jose::signing_algorithm::ES256, key.get(), payload);
if (!sig) { /* sig.error().code, sig.error().message */ }

auto ok = jose::verify(jose::signing_algorithm::ES256, key.get(), payload, *sig);

// HMAC uses a symmetric key (a byte span) instead of an EVP_PKEY:
auto oct = jose::random_bytes(32).value();
auto mac = jose::sign(jose::signing_algorithm::HS256, oct, payload);

// --- Authenticated encryption (AES-CBC-HMAC or AES-GCM) ---
auto enc = jose::content_encryption::A256GCM;
auto cek = jose::generate_cek(enc).value();
auto iv  = jose::generate_iv(enc).value();

auto sealed = jose::encrypt(enc, cek, iv, plaintext, aad);
auto opened = jose::decrypt(enc, cek, iv, sealed->ciphertext, aad, sealed->tag);
```

Key generation covers all JOSE key types: `generate_rsa_key(bits)` (≥ 2048
enforced), `generate_ec_key(P256|P384|P521)`, `generate_okp_key(Ed25519|Ed448|X25519|X448)`,
and `random_bytes(n)` for oct keys.

### Keys (JWK)

`jose::jwk` parses, validates, and serializes JSON Web Keys (RFC 7517) of every
type, including OKP keys (RFC 8037) and X.509 chains (`x5c`). A `jwk` can only
hold a valid key: RSA keys under 2048 bits, EC points off their curve,
mismatched private/public halves, and an `alg` that doesn't suit the key are
all rejected at import.

```cpp
auto key = jose::jwk::from_json(R"({"kty":"EC","crv":"P-256","x":"...","y":"...","d":"..."})");
if (!key) { /* key.error().code == errc::invalid_key, ... */ }

auto sig = jose::sign(jose::signing_algorithm::ES256, key->pkey(), payload);

auto pub = key->public_key();                 // strip private members
auto kid = jose::base64url::encode(key->thumbprint().value());  // RFC 7638
auto text = pub->to_json_string();            // publishable JWK

auto from_pem = jose::jwk::from_pem(pem_text);  // keys or certificate chains
auto fresh = jose::jwk::generate_ec(jose::ec_curve::P256);

auto set = jose::jwk_set::from_json(jwks_json);  // {"keys":[...]}
if (auto k = set->find("my-kid")) { /* k->get().pkey() */ }
```

### Signing (JWS)

`jose::jws` signs and verifies in the compact, flattened JSON and general JSON
serializations, with detached payloads, multiple signatures, and RFC 7797
unencoded payloads. Parsing always takes the list of algorithms you accept:

```cpp
auto key = jose::jwk::generate_ec(jose::ec_curve::P256).value();
auto signed_ = jose::jws::sign(payload, {jose::signing_algorithm::ES256, key});
auto token = signed_->compact();          // or to_json_string(), compact_detached()

auto parsed = jose::jws::parse(*token, {jose::signing_algorithm::ES256});
auto verified = parsed->verify(key.public_key().value());   // the payload, if valid
auto by_kid = parsed->verify(jwks);       // pick keys from a jwk_set by "kid"
```

### Encryption (JWE)

`jose::jwe` encrypts and decrypts with every RFC 7518 key-management
algorithm and content encryption, in all three serializations, with multiple
recipients and optional DEFLATE compression. Parsing takes the algorithms
you accept; every cryptographic failure is the same `errc::decryption_failed`:

```cpp
auto key = jose::jwk::generate_ec(jose::ec_curve::P256).value();
auto sealed = jose::jwe::encrypt(plaintext, jose::content_encryption::A256GCM,
                                 {jose::key_algorithm::ECDH_ES_A256KW, key.public_key().value()});
auto token = sealed->compact();

auto parsed = jose::jwe::parse(*token, {jose::key_algorithm::ECDH_ES_A256KW},
                               {jose::content_encryption::A256GCM});
auto opened = parsed->decrypt(key);    // expected<secure_bytes>
```

### HSMs and key services (opaque keys)

When the key lives in an HSM, a PKCS#11 token or a cloud KMS, implement
`jose::opaque_signer`, `jose::opaque_verifier` or
`jose::opaque_key_decrypter` (`jose/opaque.hpp`) and hand it to JWS or JWE
in place of a `jwk`:

```cpp
struct kms_signer final : jose::opaque_signer {
    auto public_key() const -> jose::expected<jose::jwk> override;   // for "kid" / "jwk"
    auto algorithms() const -> std::vector<jose::signing_algorithm> override;
    auto sign(std::span<const uint8_t> signing_input, jose::signing_algorithm alg)
        -> jose::expected<std::vector<uint8_t>> override;           // ES*: R || S, not DER
};

auto signed_ = jose::jws::sign(payload, {jose::signing_algorithm::ES256,
                                         std::make_shared<kms_signer>()});
auto payload = parsed_jws->verify(my_verifier);       // opaque_verifier&
auto plaintext = parsed_jwe->decrypt(my_decrypter);   // opaque_key_decrypter&
```

Algorithms outside the object's `algorithms()` are never passed to it. Report
backend outages as `errc::key_unavailable`, which is passed through; any other
verifier error becomes `errc::invalid_signature`, and any other decrypter
error the uniform `errc::decryption_failed`.

### JOSE headers

`jose::header` parses and type-checks a JOSE header; `jose::join_headers`
combines protected and unprotected parts and enforces `crit`. Critical
extensions are rejected unless the caller lists them as understood:

```cpp
auto prot = jose::header::from_base64url(encoded_protected_header);
auto joined = jose::join_headers(jose::header_context::jws, *prot, {}, {}, {"x-audit-id"});
if (!joined) { /* errc::unrecognized_critical_extension, errc::invalid_header, ... */ }
auto alg = joined->alg();                  // std::optional<std::string_view>
auto audit = joined->get("x-audit-id");    // extension value, or nullptr
```

Header and JWK parsing reject JSON with duplicate member names.

Lower-level primitives are available from the individual `jose/crypto/*.hpp`
headers: AES key wrap, AES-GCM key wrap, RSA-OAEP / RSA-OAEP-256 key
encryption (`rsa_encrypt_key` / `rsa_decrypt_key`), ECDH-ES + Concat KDF,
PBES2, and base64url. The legacy `RSA1_5` algorithm is refused unless the
caller passes `jose::legacy_options{.allow_rsa1_5 = true}`.

To keep key material out of swap, reserve OpenSSL's mlock'ed secure heap once
at startup; `secure_bytes` then allocates from it, falling back to the normal
heap (still zeroed on free) if it fills up:

```cpp
jose::init_secure_heap(1 << 16);  // 64 KiB; returns locked / not_locked / error
```

Every algorithm is checked against the published RFC test vectors in
[tests/vectors](tests/vectors) (RFC 3394, 7515, 7516, 7517, 7518, 7520, 7797, 8032, 8037).

## Building

jose2cpp needs a C++20 compiler, CMake ≥ 3.21, and four dependencies:

| Dependency     | Version   |
| -------------- | --------- |
| OpenSSL        | ≥ 3.0     |
| nlohmann-json  | any recent |
| zlib           | any (macOS SDK and most distros ship it) |
| Catch2         | ≥ 3.0 (tests only) |

There are two supported ways to get the dependencies. Use **vcpkg** for reproducible,
pinned versions across machines and CI (recommended for anything beyond local dev);
use **system packages** for the quickest local setup.

### Option A — vcpkg (cross-platform, recommended)

Works identically on macOS and Ubuntu and pins the exact versions from
[vcpkg.json](vcpkg.json), so you avoid distro version skew (notably Catch2 on Ubuntu 22.04).

1. Install vcpkg and set `VCPKG_ROOT`:
   ```sh
   git clone https://github.com/microsoft/vcpkg "$HOME/vcpkg"
   "$HOME/vcpkg/bootstrap-vcpkg.sh"
   export VCPKG_ROOT="$HOME/vcpkg"   # add to your shell profile
   ```
   On Ubuntu, also install the build prerequisites:
   ```sh
   sudo apt install cmake ninja-build g++ curl zip unzip tar pkg-config
   ```
   On macOS: `brew install cmake ninja` (and Xcode command line tools).

2. Configure, build, and test (vcpkg fetches the deps automatically):
   ```sh
   cmake --preset vcpkg
   cmake --build --preset vcpkg
   ctest --preset vcpkg
   ```

### Option B — system packages

**macOS (Homebrew):**
```sh
brew install nlohmann-json openssl@3 catch2 cmake ninja
cmake --preset system-macos
cmake --build --preset system-macos
ctest --preset system-macos
```
The `system-macos` preset points CMake at Homebrew's keg-only `openssl@3`. It assumes
Apple Silicon (`/opt/homebrew`); on an Intel Mac, override with
`-DOPENSSL_ROOT_DIR=/usr/local/opt/openssl@3`.

**Ubuntu 24.04:**
```sh
sudo apt install nlohmann-json3-dev libssl-dev zlib1g-dev catch2 cmake ninja-build g++
cmake --preset system
cmake --build --preset system
ctest --preset system
```

**Ubuntu 22.04:** apt ships Catch2 **v2**, but the tests require Catch2 ≥ 3. Either
build without tests:
```sh
sudo apt install nlohmann-json3-dev libssl-dev zlib1g-dev cmake ninja-build g++
cmake --preset system -DJOSE_BUILD_TESTS=OFF
cmake --build --preset system
```
or use the **vcpkg** option above to get Catch2 3.x. OpenSSL 3 and nlohmann-json from
22.04's apt are new enough.

### Build options

| Option              | Default | Description                          |
| ------------------- | ------- | ------------------------------------ |
| `JOSE_BUILD_TESTS`  | `ON`    | Build the Catch2 test suite          |
| `JOSE_BUILD_BENCH`  | `OFF`   | Build benchmarks                     |
| `JOSE_BUILD_CLI`    | `OFF`   | Build the CLI tool                   |
| `JOSE_FUZZ`         | `OFF`   | Build fuzz targets (needs libFuzzer) |
| `JOSE_USE_STD_EXPECTED` | `AUTO` | `jose::expected` implementation: `AUTO` probes for C++23 `std::expected` and falls back to the vendored [expected-lite](https://github.com/martinmoene/expected-lite) on C++20; `ON`/`OFF` force one. The choice is exported as a public compile definition so consumers always match the library build. |
