# jose2cpp

A C++20 take on the Go JOSE library. jose2cpp does JSON Object Signing and
Encryption (JWS, JWE, JWK and JWT) on top of OpenSSL 3,
and it follows go-jose v4's rules: parsing always takes the algorithms you
accept, and a key embedded in a token is never trusted on its own.

## Quick start

Include the umbrella header and use the unified entry points: `sign`/`verify`
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

A token decides how much work it asks for, so there are limits. A JWE can
have at most 32 recipients and a JWS at most 32 signatures, the same caps
go-jose uses. PBES2 is the expensive one: each recipient's `p2c` is a PBKDF2
iteration count, capped at 1,000,000, and on top of that one decrypt call
spends at most `jwe_decrypt_options::max_pbes2_iterations` (1,000,000 by
default) across every recipient and key it tries. So a JSON JWE listing a
pile of PBES2 recipients costs you at most 1,000,000 iterations in total,
about one maximum-cost run, not one run per recipient. That fits three
recipients at our default `p2c` of 310,000 but only one at go-jose's 600,000,
so raise it if you expect tokens with several PBES2 recipients, or set it to 0
if you never use PBES2. JSON anywhere in a token, key or claims set can be
nested at most 128 levels deep, because a few tens of KB of brackets would
otherwise overflow the stack.

Compact tokens, signed or encrypted, can have whitespace at either end, so
one read from a file with a trailing newline still parses. Whitespace inside
the token is an error, because the RFCs don't allow it and it would let the
same token be written many ways. (go-jose's JWT parser accepts line breaks
anywhere and refuses spaces anywhere; details in PLAN.md.) If you keep a
revocation list or replay cache, key it on `jti` or the signed content, not
on the token string: even a re-serialized token isn't unique, because an
ECDSA signature has two valid forms.

### Tokens (JWT)

`jose::jwt` builds signed, encrypted and nested (signed then encrypted) JWTs.
Claims can be a JSON object or your own struct with a `to_json`, and you can
call `claims()` as many times as you like. Giving the same claim name twice is
an error, because silently letting one claim set overwrite another's `exp` is
exactly the kind of bug you don't want in a token.

```cpp
auto token = jose::jwt::signed_token({jose::signing_algorithm::ES256, key})
                 .claims({{"iss", "https://auth.example.com"}, {"sub", "kevin"}})
                 .claims(my_private_claims)
                 .serialize();                    // compact JWS, "typ":"JWT"

auto sealed = jose::jwt::signed_and_encrypted(
                  {jose::signing_algorithm::EdDSA, signing_key},
                  jose::content_encryption::A256GCM,
                  {jose::key_algorithm::ECDH_ES_A256KW, their_public_key})
                  .claims(claims)
                  .serialize();                   // JWE with "cty":"JWT" around the JWS
```

Any error along the chain comes back from `serialize()` (or `token()`, which
gives you the `jws` / `jwe` itself), so one check covers the whole thing.

Parsing works the same way as JWS and JWE: you list the algorithms you accept,
and you only get the claims after the signature checks out or the JWE opens.

```cpp
auto parsed = jose::jwt::parse_signed(token, {jose::signing_algorithm::ES256});
auto claims = parsed->claims(public_key);              // nlohmann::json, verified
auto mine   = jose::jwt::decode<my_claims>(*claims);   // via your from_json

auto nested = jose::jwt::parse_signed_and_encrypted(sealed,
                  {jose::key_algorithm::ECDH_ES_A256KW}, {jose::content_encryption::A256GCM},
                  {jose::signing_algorithm::EdDSA});
auto inner  = nested->decrypt(my_private_key);         // the signed JWT inside
auto verified = inner->claims(their_signing_key);
```

For the registered claims there's `jwt::registered_claims`, with
`jwt::numeric_date` (a `std::chrono` time in whole seconds) and
`jwt::audience` (one string or a list). They work in the builder, in
`decode`, and inside your own claims structs:

```cpp
jose::jwt::registered_claims standard{
    .issuer = "https://auth.example.com",
    .subject = "kevin",
    .audience = {"api"},
    .expiry = jose::jwt::numeric_date::now() + std::chrono::minutes(15),
};
auto token = jose::jwt::signed_token(signer).claims(standard).claims(my_private_claims).serialize();

auto back = jose::jwt::decode<jose::jwt::registered_claims>(*verified);
if (!back) return back.error();  // a malformed claim, e.g. "exp":"tomorrow"
auto ok = back->validate({.issuer = "https://auth.example.com", .any_audience = {"api"}});
```

`validate` works like go-jose's `Claims.Validate`. It checks `iss`, `sub`,
`jti` and `aud` against what you ask for and `nbf`, `exp` and `iat` against
the current time (or `.time`), with a minute of leeway by default. Pass a
second argument to change that: `validate(want, 0s)`, or a negative leeway on
the client side to ask "will the server still take this?". It reports the
first failure as `errc::missing_claim`, `invalid_claim`, `not_yet_valid` or
`expired`.

Two things it doesn't do, same as go-jose. It doesn't check `aud` unless you
set `any_audience`, even though RFC 7519 says a service should reject a token
whose `aud` doesn't name it. Doing that by default would make `aud` required
the moment a token carries one, and a service that forgot to set
`any_audience` would start turning away good tokens. So set it whenever your
tokens carry an audience. It also doesn't require `exp`, so a token without
one never expires; if yours should always have one, check for it. We differ
from go-jose in two places. At exactly the `exp` second the token is expired,
because RFC 7519 says "on or after"; go-jose still takes it at that instant.
And an empty string you ask for is checked like any other value, so
`.issuer = ""` means "iss must be empty". go-jose reads `""` as "don't check";
leave the field unset for that.

A badly formed claim, like `"exp":"tomorrow"` or `"exp":null`, is an error
rather than "no expiry". That one matters: a parser that shrugs off a bad
`exp` hands out tokens that never expire.

One rule to know about. A JWT that's only encrypted has no signature, so
anyone who can encrypt to you can make one. With RSA or ECDH-ES that's anyone
holding your public key, and PBES2 is only as good as the password. So
encrypted-only JWTs are limited to `dir`, AES key wrap and AES-GCM key wrap,
both when you build one and when you parse one. go-jose's parser has the same
limit, but its builder doesn't, so go-jose will happily make an encrypted-only
JWT that neither library will accept. Nested JWTs are signed inside, so they can use any key
algorithm, RSA-OAEP and ECDH-ES included, which is what OIDC encrypted ID
tokens need. That's where we part ways with go-jose: it refuses those for
nested JWTs too, so a go-jose service can't read a jose2cpp nested JWT that
uses RSA or ECDH-ES outside. Details in [tests/interop](tests/interop/README.md).

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

For keys behind a network service, `jose/async.hpp` has coroutine versions
(`async_opaque_signer`, `async_opaque_verifier`, `async_opaque_key_decrypter`)
used through `jws::sign_async`, `jws::verify_async` and `jwe::decrypt_async`:

```cpp
auto signed_ = co_await jose::jws::sign_async(payload, {jose::signing_algorithm::ES256,
                                                       std::make_shared<my_async_kms_signer>()});
auto plaintext = co_await parsed_jwe->decrypt_async(my_async_kms_decrypter);
```

JWTs work the same way. The builders have `token_async()` and
`serialize_async()`, and the parsed tokens have `claims_async()` and, for
nested JWTs, `decrypt_async()`:

```cpp
auto token = co_await jose::jwt::signed_token({jose::signing_algorithm::ES256, kms_signer})
                 .claims(claims)
                 .serialize_async();

auto parsed = jose::jwt::parse_signed_and_encrypted(*token, key_algs, encs, sig_algs);
auto inner = co_await parsed->decrypt_async(kms_decrypter);   // still held to sig_algs
auto verified = co_await inner->claims_async(kms_verifier);
```

The tasks copy the builder or the parsed token, so either can go away before
the task runs. Only the verifier or decrypter you pass by reference has to
outlive it. The sync `serialize()` refuses an async signer and tells you to
use `serialize_async()`.

### Keys from a JWKS URL

Most identity providers publish their signing keys as a JWK Set at a URL, and
`jose::optional::jwks_fetcher` (`jose/optional/jwks_fetcher.hpp`) keeps a copy
of it cached and refreshed for you. It isn't in `jose.hpp`, and it doesn't pull
in an HTTP library. You write the transport, a single `get()`, on top of
whatever client you already have:

```cpp
struct my_http final : jose::optional::http_client {
    auto get(jose::optional::http_request request)
        -> jose::task<jose::expected<jose::optional::http_response>> override;
        // GET request.url over TLS; honour request.timeout and request.max_response_bytes
};

jose::optional::jwks_fetcher fetcher({.url = "https://auth.example.com/.well-known/jwks.json"},
                                     std::make_unique<my_http>());

auto parsed = jose::jwt::parse_signed(token, {jose::signing_algorithm::RS256});
auto kid = parsed->header().kid();
auto keys = co_await fetcher.keys_for(std::string(*kid));
auto claims = parsed->claims(**keys);
```

`keys()` serves the cached set until it's `refresh_interval` old (five minutes
by default). `keys_for(kid)` also fetches when no key has that `kid`, which is
how a key the provider just rotated in gets picked up. Fetches start at most
once per `min_refresh_interval` (30 seconds) no matter who asks, so a flood of
tokens with made-up `kid`s can't turn into a flood of requests to your
provider. While a fetch is running, other callers that need one wait for it
instead of starting their own.

When a fetch fails, the old set is still served for `max_stale` (an hour)
past `refresh_interval`, and after that callers get the error. A key the
provider has withdrawn is still accepted during that hour, so keep `max_stale`
as short as your provider's uptime lets you. Only public keys are kept:
symmetric keys are dropped, because anyone who can read the URL could sign
with them, and a private key is cut down to its public half. URLs have to be
`https://` unless you set `allow_http`, and your `http_client` has to check
certificates, because the keys are only as good as the connection that
brought them.

### Command line

`jose-cli` does from a shell what the library does from code. It takes the
same commands and flags as go-jose's `jose-util`, so a `jose-util` command
line usually works unchanged; the exceptions are at the end of this section.
Build it with `-DJOSE_BUILD_CLI=ON`.

```sh
jose-cli generate-key --use sig --alg ES256 --kid demo     # writes jwk-sig-demo-{priv,pub}.json
echo "hello" | jose-cli sign --key jwk-sig-demo-priv.json | jose-cli verify --key jwk-sig-demo-pub.json

jose-cli encrypt --key public.pem --alg RSA-OAEP --enc A128GCM --in plain.txt --out token.jwe
jose-cli decrypt --key private.pem --in token.jwe

jose-cli expand < token.jws                                # compact to JSON, nothing checked
```

The commands are `sign`, `verify`, `encrypt`, `decrypt`, `expand` and
`generate-key`, and `jose-cli COMMAND --help` lists each one's flags. Keys can
be PEM, DER or JWK, as with `jose-util`, and `verify` and `decrypt` also take a
JWK Set and try each key in it. A few things go past `jose-util`:

- `verify` and `decrypt` only succeed with algorithms the key can actually be
  used with, so an RSA key never verifies an HS256 token. `--alg` (and `--enc`
  for `decrypt`) limits it to the algorithms you list.
- `--alg` defaults to the key's own `alg`, and `encrypt --zip` compresses.
- `generate-key` also makes symmetric keys (HS*, A*KW, A*GCMKW, `dir`) and,
  with `--crv`, Ed448, X25519 and X448 keys. It never overwrites a file, and
  on Linux and macOS the private key file is readable only by you. On Windows
  it's only marked read-only and gets the folder's permissions, so put it
  somewhere private.
- RSA1_5 needs `--allow-legacy` on both `encrypt` and `decrypt`.

Tokens come out with a trailing newline; payloads and plaintexts come out
exactly as they went in. `decrypt --out` creates a new file readable only by
you (on Linux and macOS). The exit status is 0 on success, 1 when the
operation fails (a bad signature, the wrong key, an unreadable file) and 2 for
a bad command line.

Where a `jose-util` command line won't work as is: giving a flag like `--key`
twice is an error rather than "the last one wins", an argument that isn't a
flag is an error rather than ignored, and `generate-key` swaps characters
other than letters, digits, `.`, `-` and `_` in a `--kid` for `_` in the file
names (the key's `kid` itself is kept).
With `-DJOSE_INTEROP_GO=ON`, ctest also builds go-jose's `jose-util` and
checks that each tool reads what the other writes.

### Coroutines (`jose::task`)

`jose/task.hpp` is a small header-only coroutine type for the I/O-bound
extension points (async HSM/KMS signers and decrypters, JWKS fetching). It is
lazy, move-only and has no scheduler of its own, so it composes with whatever
event loop the application uses; `sync_wait` runs one from plain code:

```cpp
auto fetch_key(kms_client& kms) -> jose::task<jose::expected<jose::jwk>> {
    auto pem = co_await kms.get_public_key();   // any awaitable
    co_return jose::jwk::from_pem(pem);
}

auto key = jose::sync_wait(fetch_key(kms));      // blocks until done
```

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
Interoperability with [go-jose](https://github.com/go-jose/go-jose) v4 is
tested in both directions: each library verifies and decrypts tokens the other
produced, for every algorithm both support. See
[tests/interop](tests/interop/README.md), including the known differences.

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

### Option A: vcpkg (cross-platform, recommended)

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

### Option B: system packages

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
| `JOSE_BUILD_BENCH`  | `OFF`   | Build `jose_bench` (see [Benchmarks](#benchmarks)) |
| `JOSE_BUILD_CLI`    | `OFF`   | Build `jose-cli` (see [Command line](#command-line)) |
| `JOSE_FUZZ`         | `OFF`   | Build the fuzz targets (see [Fuzzing](#fuzzing)) |
| `JOSE_BUILD_DOCS`   | `OFF`   | Add a `jose_docs` target that builds the API reference (see [API reference](#api-reference)) |
| `JOSE_DOCS_WARN_AS_ERROR` | `OFF` | Make the `jose_docs` target fail on any Doxygen warning |
| `JOSE_INTEROP_GO`   | `OFF`   | Add live go-jose interop tests to ctest (needs Go; see [tests/interop](tests/interop/README.md)) |
| `JOSE_USE_STD_EXPECTED` | `AUTO` | `jose::expected` implementation: `AUTO` probes for C++23 `std::expected` and falls back to the vendored [expected-lite](https://github.com/martinmoene/expected-lite) on C++20; `ON`/`OFF` force one. The choice is exported as a public compile definition so consumers always match the library build. |

### API reference

Every public header is documented for Doxygen (tested with 1.9.8 and 1.18).
From the repository root:

```sh
mkdir -p build/docs                # Doxygen won't create both levels itself
doxygen docs/Doxyfile              # writes build/docs/html/index.html
```

or configure with `-DJOSE_BUILD_DOCS=ON` and run `cmake --build <dir> --target jose_docs`,
which writes to `<dir>/docs/html` and stamps the version. The vendored
expected-lite and the `detail` namespaces are left out. CI builds the
reference on every run and fails on any warning, so an undocumented public
function or a broken reference doesn't get merged. The built pages are kept
as a build artifact for two weeks.

### Benchmarks

`benchmarks/` runs the same 40 cases through jose2cpp and go-jose v4 (same
keys, payloads and timing loop) and prints them side by side:

```sh
cmake --preset bench-macos && cmake --build --preset bench-macos    # bench on Linux
python3 benchmarks/compare.py --jose-bench build/bench-macos/benchmarks/jose_bench
```

On an M5 Max, jose2cpp is 2.4 to 2.5 times faster for RSA signing and
RSA-OAEP decryption and 1.1 to 3.5 times faster for ECDSA. For the small
HMAC and AES tokens it's up to 1.4 µs behind go-jose when producing one and
up to 3.0 µs ahead when verifying or decrypting. It's slower for EdDSA (Go's Ed25519 is
faster than OpenSSL's here), for ECDH-ES (about 1.3 times), and
for importing keys: an RSA private key takes 19 ms because every import is
validated. The full table, what each case covers
and how to read it are in [benchmarks/README.md](benchmarks/README.md).

### Fuzzing

`-DJOSE_FUZZ=ON` builds six fuzz targets in `fuzz/`: base64url, JWK
parsing, JWS and JWE parsing (then verifying and decrypting with keys of
every kind), the JWT parsers with the registered claims, and the DEFLATE
inflater that JWE compression uses. Each one checks invariants as well as
crashes: a parsed token re-serializes to one that parses the same and
serializes to exactly the same text again, decoded base64url encodes back to
the same text, inflated output never goes past its cap. The whole build,
library included, gets ASan and UBSan (`JOSE_FUZZ_SANITIZERS`), with
assertions on whatever the build type.

With clang and libFuzzer the targets are real fuzzers. Run one on a scratch
copy of its corpus so the checked-in seeds stay as they are:

```sh
cmake -S . -B build-fuzz -G Ninja -DCMAKE_CXX_COMPILER=clang++ -DJOSE_FUZZ=ON -DJOSE_BUILD_TESTS=OFF
cmake --build build-fuzz
cp -r fuzz/corpus/jws /tmp/jws && build-fuzz/fuzz/fuzz_jws -max_total_time=300 /tmp/jws
```

Apple's clang and GCC don't ship libFuzzer, so there the targets are built
to replay the files they're given instead, which is still a regression test
under the sanitizers. MSVC isn't supported. Either way `ctest` replays the corpus. The seeds come
from the RFC and go-jose test vectors (`python3 -I fuzz/make_corpus.py`
writes them), and CI fuzzes every target for a minute whenever it runs (pull
requests and pushes to `main` and `develop`).

