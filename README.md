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

Lower-level primitives (AES key wrap, ECDH-ES + Concat KDF, PBES2,
base64url) are available from the individual `jose/crypto/*.hpp` headers.

## Building

jose2cpp needs a C++20 compiler, CMake ≥ 3.21, and three dependencies:

| Dependency     | Version   |
| -------------- | --------- |
| OpenSSL        | ≥ 3.0     |
| nlohmann-json  | any recent |
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
sudo apt install nlohmann-json3-dev libssl-dev catch2 cmake ninja-build g++
cmake --preset system
cmake --build --preset system
ctest --preset system
```

**Ubuntu 22.04:** apt ships Catch2 **v2**, but the tests require Catch2 ≥ 3. Either
build without tests:
```sh
sudo apt install nlohmann-json3-dev libssl-dev cmake ninja-build g++
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
