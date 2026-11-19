# Benchmarks

`jose_bench` (C++) and `go/` (go-jose v4) run the same 40 cases on the same
keys and payloads with the same timing loop, and `compare.py` puts the
results side by side. This is PLAN.md Phase 3 item 11; §Benchmarks there
says why it's built this way.

## Running

```sh
cmake --preset bench-macos          # or: bench (Linux), both Release with jose_bench only
cmake --build --preset bench-macos
python3 benchmarks/compare.py --jose-bench build/bench-macos/benchmarks/jose_bench
```

That builds the Go runner first (so compiling isn't timed), then takes turns:
jose2cpp, go-jose, twice by default (`--rounds`). Each case keeps its best
median across the rounds. A full run takes about two minutes per round.
`--filter jws.` runs a subset, `--save run.jsonl` keeps the raw numbers, and
`--cpp-json`/`--go-json` compare saved runs without running anything.

Either side runs on its own too:

```sh
build/bench-macos/benchmarks/jose_bench --filter ES256
cd benchmarks/go && go run . --filter ES256
```

Both print one JSON object per line. `--quick` runs every case once without
timing; ctest does that for both sides (`bench.smoke`, and `bench.go_smoke`
with `JOSE_INTEROP_GO=ON`) so the benchmarks keep building and keep
measuring the success path.

Close other work before a run. A browser or a build on another core moves
the numbers by more than some of the differences below.

## What a case measures

Each case is one call sequence as an application writes it, including
serialization and parsing:

| case | jose2cpp | go-jose |
|------|----------|---------|
| `jws.sign/<alg>` | `jws::sign` + `compact()` | `Signer.Sign` + `CompactSerialize` |
| `jws.verify/<alg>` | `jws::parse_compact` + `verify` | `ParseSignedCompact` + `Verify` |
| `jws.parse/ES256` | `jws::parse_compact` | `ParseSignedCompact` |
| `jwe.encrypt/<alg>/<enc>` | `jwe::encrypt` + `compact()` | `Encrypter.Encrypt` + `CompactSerialize` |
| `jwe.decrypt/<alg>/<enc>` | `jwe::parse_compact` + `decrypt` | `ParseEncryptedCompact` + `Decrypt` |
| `jwe.parse/A256KW/A256GCM` | `jwe::parse_compact` | `ParseEncryptedCompact` |
| `jwt.sign/<alg>` | `jwt::signed_token(...).claims(...).serialize()` | `jwt.Signed(...).Claims(...).Serialize()` |
| `jwt.verify/<alg>` | `jwt::parse_signed` + `claims` + `decode<registered_claims>` + `validate` | `jwt.ParseSigned` + `Claims` (registered and a map) + `ValidateWithLeeway` |
| `jwk.parse/<key>` | `jwk::from_json` | `JSONWebKey.UnmarshalJSON` |

The payload is a 222-byte JSON claims set; the `-64KiB` cases use 64 KiB
of binary data. Keys are in `keys.json` (RSA 2048, P-256/384/521, Ed25519
and 32-octet oct keys), made once with go-jose and used only here. go-jose
builds its `Signer` or `Encrypter` once, outside the timing, as an
application would; jose2cpp has no such object, so its per-call setup is
inside the timing.

The timing is wall clock on one thread. Go's garbage collector runs on the
other cores (GOMAXPROCS is left at the core count), so collection work from
the allocation-heavy cases (JWT verification, key parsing, the 64 KiB
payloads) isn't all counted against go-jose. On a server busy on every core
it would be. jose2cpp frees and zeroes its buffers inline, so it pays for
them in the timing. `GOMAXPROCS=1 python3 benchmarks/compare.py ...` charges
the collector to go-jose too.

## Results

Apple M5 Max, macOS 27.3, 2026-11-18. jose2cpp built Release with Apple
clang 21 against Homebrew's OpenSSL 3.6.4; go-jose v4.1.9 on Go 1.26.2
(GOMAXPROCS 18). Run with `--rounds 3`: the median time per operation, best
of three rounds. The last column is go-jose's time divided by jose2cpp's, so
above 1 means jose2cpp is faster.

| case | jose2cpp | go-jose | go-jose ÷ jose2cpp |
|------|---------:|--------:|-------------------:|
| jws.sign/HS256 | 1.4 µs | 1.5 µs | 1.02 |
| jws.verify/HS256 | 1.6 µs | 2.1 µs | 1.32 |
| jws.sign/RS256 | 299.0 µs | 746.3 µs | 2.50 |
| jws.verify/RS256 | 9.8 µs | 21.5 µs | 2.19 |
| jws.sign/PS256 | 300.9 µs | 752.7 µs | 2.50 |
| jws.verify/PS256 | 10.8 µs | 21.9 µs | 2.02 |
| jws.sign/ES256 | 11.9 µs | 15.0 µs | 1.26 |
| jws.verify/ES256 | 31.3 µs | 33.7 µs | 1.08 |
| jws.sign/ES384 | 90.2 µs | 100.3 µs | 1.11 |
| jws.verify/ES384 | 190.0 µs | 294.3 µs | 1.55 |
| jws.sign/ES512 | 121.4 µs | 239.7 µs | 1.97 |
| jws.verify/ES512 | 216.1 µs | 756.9 µs | 3.50 |
| jws.sign/EdDSA | 16.5 µs | 13.4 µs | 0.81 |
| jws.verify/EdDSA | 38.2 µs | 27.6 µs | 0.72 |
| jws.sign/HS256-64KiB | 45.6 µs | 94.9 µs | 2.08 |
| jws.verify/HS256-64KiB | 47.5 µs | 85.5 µs | 1.80 |
| jws.parse/ES256 | 912 ns | 1.0 µs | 1.10 |
| jwe.encrypt/dir/A256GCM | 2.4 µs | 1.8 µs | 0.74 |
| jwe.decrypt/dir/A256GCM | 1.6 µs | 2.9 µs | 1.79 |
| jwe.encrypt/dir/A128CBC-HS256 | 3.0 µs | 2.2 µs | 0.74 |
| jwe.decrypt/dir/A128CBC-HS256 | 2.2 µs | 3.4 µs | 1.54 |
| jwe.encrypt/A256KW/A256GCM | 3.8 µs | 2.5 µs | 0.65 |
| jwe.decrypt/A256KW/A256GCM | 2.9 µs | 3.4 µs | 1.17 |
| jwe.encrypt/RSA-OAEP-256/A256GCM | 12.2 µs | 22.4 µs | 1.84 |
| jwe.decrypt/RSA-OAEP-256/A256GCM | 303.4 µs | 735.9 µs | 2.43 |
| jwe.encrypt/ECDH-ES/A256GCM | 83.9 µs | 34.7 µs | 0.41 |
| jwe.decrypt/ECDH-ES/A256GCM | 40.3 µs | 29.6 µs | 0.74 |
| jwe.encrypt/ECDH-ES+A256KW/A256GCM | 85.6 µs | 35.4 µs | 0.41 |
| jwe.decrypt/ECDH-ES+A256KW/A256GCM | 41.7 µs | 30.3 µs | 0.73 |
| jwe.encrypt/dir/A256GCM-64KiB | 31.2 µs | 46.0 µs | 1.48 |
| jwe.decrypt/dir/A256GCM-64KiB | 29.8 µs | 42.4 µs | 1.42 |
| jwe.parse/A256KW/A256GCM | 1.2 µs | 2.0 µs | 1.62 |
| jwt.sign/HS256 | 3.1 µs | 3.0 µs | 0.98 |
| jwt.verify/HS256 | 3.3 µs | 6.4 µs | 1.92 |
| jwt.sign/ES256 | 13.7 µs | 16.7 µs | 1.22 |
| jwt.verify/ES256 | 33.3 µs | 38.6 µs | 1.16 |
| jwk.parse/RSA-2048-public | 1.51 ms | 2.4 µs | 0.00 |
| jwk.parse/RSA-2048-private | 18.79 ms | 115.1 µs | 0.01 |
| jwk.parse/EC-P256-public | 6.7 µs | 1.4 µs | 0.21 |
| jwk.parse/EC-P256-private | 10.9 µs | 1.9 µs | 0.17 |

## Reading them

Most of the asymmetric rows compare OpenSSL with Go's crypto packages more
than they compare the two JOSE layers. OpenSSL pulls ahead on RSA
private-key operations (2.4 to 2.5 times) and P-521 (2 to 3.5 times), and by
1.1 to 1.6 times on P-256 and P-384. Go's Ed25519 is faster than OpenSSL's on
this machine.

The small symmetric cases are where the JOSE layer shows. Producing a token
costs jose2cpp up to 1.3 µs more than go-jose (`jwe.encrypt/A256KW`: 3.8 µs
against 2.5 µs), mostly because go-jose's `Signer` and `Encrypter` do their
setup once and jose2cpp does it per call. Parsing and checking one costs
jose2cpp less, up to 3.1 µs less for `jwt.verify/HS256` (3.3 µs against
6.4 µs).

Two rows stand out. The proportions below come from macOS `sample`
profiles of `jose_bench` running one case.

- **`jwk.parse` for RSA: 1.5 ms public, 19 ms private.** jose2cpp validates
  every key it imports (PLAN.md §Key Validation) with OpenSSL's
  `EVP_PKEY_public_check` / `EVP_PKEY_check`, which for RSA run the SP
  800-56B checks, primality tests included. go-jose checks an RSA key's size
  and exponent and, for a private key, that `p*q == n` and
  `rsa.PrivateKey.Validate` passes, but runs no primality tests. A key is
  normally parsed once and used many times, and the JWKS fetcher parses a set
  only when it refreshes, so this is a cost per key, not per token. EC keys
  take 5 to 9 µs longer than in go-jose: about a third of jose2cpp's time is
  the key check and more than a third is OpenSSL building the key from its
  parameters (`EVP_PKEY_fromdata`).
- **ECDH-ES encryption is about 2.4 times slower.** Generating the ephemeral
  key and deriving the shared secret take about a third of the time, roughly
  what go-jose spends in total. Most of the rest goes into writing the
  ephemeral key into the `"epk"` header: it's wrapped in a validated `jwk`,
  turned into its public half through a DER round trip, serialized, and then
  validated again as the header is checked. Decryption pays the second half
  of that (parsing and checking `"epk"`) and is about 1.4 times slower.

Running these found one plain slowdown, in base64url, which every token goes
through. Encoding appended one character at a time, which with libc++ is a
library call per character. Decoding first scanned the whole input for
whitespace, so it could report whitespace ahead of any other error, and
that scan also went one character at a time; then it branched on every
character. A 64 KiB
JWE took 203 µs to encrypt and 155 µs to decrypt (go-jose: 47 µs and 43 µs).
Now encoding writes into a presized buffer, decoding works four characters
at a time from pre-shifted tables, and the whitespace scan only runs once a
decode has already failed (whitespace is outside the alphabet, so it always
fails). The same JWE takes 31 µs and 30 µs, and every small token got about
half a microsecond cheaper.
