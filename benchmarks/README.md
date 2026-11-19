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
(GOMAXPROCS 18), after the ECDH-ES change described below. Run with
`--rounds 3`: the median time per operation, best
of three rounds. The last column is go-jose's time divided by jose2cpp's, so
above 1 means jose2cpp is faster.

| case | jose2cpp | go-jose | go-jose ÷ jose2cpp |
|------|---------:|--------:|-------------------:|
| jws.sign/HS256 | 1.4 µs | 1.5 µs | 1.00 |
| jws.verify/HS256 | 1.6 µs | 2.1 µs | 1.31 |
| jws.sign/RS256 | 304.4 µs | 750.4 µs | 2.47 |
| jws.verify/RS256 | 10.0 µs | 21.4 µs | 2.14 |
| jws.sign/PS256 | 305.6 µs | 755.7 µs | 2.47 |
| jws.verify/PS256 | 11.0 µs | 21.9 µs | 1.99 |
| jws.sign/ES256 | 12.0 µs | 15.0 µs | 1.25 |
| jws.verify/ES256 | 31.9 µs | 34.0 µs | 1.07 |
| jws.sign/ES384 | 91.8 µs | 101.0 µs | 1.10 |
| jws.verify/ES384 | 193.6 µs | 297.6 µs | 1.54 |
| jws.sign/ES512 | 121.4 µs | 242.2 µs | 2.00 |
| jws.verify/ES512 | 215.8 µs | 763.9 µs | 3.54 |
| jws.sign/EdDSA | 16.7 µs | 13.5 µs | 0.81 |
| jws.verify/EdDSA | 38.9 µs | 27.6 µs | 0.71 |
| jws.sign/HS256-64KiB | 45.4 µs | 96.3 µs | 2.12 |
| jws.verify/HS256-64KiB | 47.6 µs | 86.2 µs | 1.81 |
| jws.parse/ES256 | 920 ns | 1.0 µs | 1.09 |
| jwe.encrypt/dir/A256GCM | 2.4 µs | 1.8 µs | 0.74 |
| jwe.decrypt/dir/A256GCM | 1.6 µs | 2.9 µs | 1.78 |
| jwe.encrypt/dir/A128CBC-HS256 | 3.0 µs | 2.2 µs | 0.73 |
| jwe.decrypt/dir/A128CBC-HS256 | 2.2 µs | 3.4 µs | 1.52 |
| jwe.encrypt/A256KW/A256GCM | 3.8 µs | 2.4 µs | 0.64 |
| jwe.decrypt/A256KW/A256GCM | 3.0 µs | 3.5 µs | 1.16 |
| jwe.encrypt/RSA-OAEP-256/A256GCM | 12.4 µs | 22.4 µs | 1.80 |
| jwe.decrypt/RSA-OAEP-256/A256GCM | 306.2 µs | 739.2 µs | 2.41 |
| jwe.encrypt/ECDH-ES/A256GCM | 45.7 µs | 34.8 µs | 0.76 |
| jwe.decrypt/ECDH-ES/A256GCM | 34.8 µs | 29.9 µs | 0.86 |
| jwe.encrypt/ECDH-ES+A256KW/A256GCM | 47.3 µs | 35.5 µs | 0.75 |
| jwe.decrypt/ECDH-ES+A256KW/A256GCM | 36.3 µs | 30.3 µs | 0.84 |
| jwe.encrypt/dir/A256GCM-64KiB | 31.8 µs | 45.5 µs | 1.43 |
| jwe.decrypt/dir/A256GCM-64KiB | 30.2 µs | 42.3 µs | 1.40 |
| jwe.parse/A256KW/A256GCM | 1.2 µs | 2.0 µs | 1.62 |
| jwt.sign/HS256 | 3.1 µs | 3.0 µs | 0.97 |
| jwt.verify/HS256 | 3.3 µs | 6.3 µs | 1.88 |
| jwt.sign/ES256 | 13.7 µs | 16.8 µs | 1.22 |
| jwt.verify/ES256 | 33.6 µs | 38.7 µs | 1.15 |
| jwk.parse/RSA-2048-public | 1.52 ms | 2.3 µs | 0.00 |
| jwk.parse/RSA-2048-private | 18.95 ms | 115.2 µs | 0.01 |
| jwk.parse/EC-P256-public | 6.9 µs | 1.4 µs | 0.20 |
| jwk.parse/EC-P256-private | 11.0 µs | 1.8 µs | 0.17 |

## Reading them

Most of the asymmetric rows compare OpenSSL with Go's crypto packages more
than they compare the two JOSE layers. OpenSSL pulls ahead on RSA
private-key operations (2.4 to 2.5 times) and P-521 (2 to 3.5 times), and by
1.1 to 1.6 times on P-256 and P-384. Go's Ed25519 is faster than OpenSSL's on
this machine.

The small symmetric cases are where the JOSE layer shows. Producing a token
costs jose2cpp up to 1.4 µs more than go-jose (`jwe.encrypt/A256KW`: 3.8 µs
against 2.4 µs), mostly because go-jose's `Signer` and `Encrypter` do their
setup once and jose2cpp does it per call. Parsing and checking one costs
jose2cpp less, up to 3.0 µs less for `jwt.verify/HS256` (3.3 µs against
6.3 µs).

One row stands out. The proportions below come from macOS `sample`
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
Running these found two plain slowdowns. The first was in base64url, which
every token goes through. Encoding appended one character at a time, which with libc++ is a
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

The second was ECDH-ES, at 84 µs to encrypt against go-jose's 35 µs. Key
agreement took about a third of that. The rest went to writing the
ephemeral key into the `"epk"` header: a full private-key check on a key
OpenSSL had just generated, a DER round trip to get its public half, and
then three validations of the same `"epk"`: once when it was set, again
when the recipient's parameters were merged into the protected header
(`header::set` re-parses the whole header on every call), and again in
`join_headers`. Decryption validated it twice. Now the header code reuses a key it
has already parsed when the JSON is identical, the `"epk"` JSON is written
straight from the ephemeral key, and EC `"x"` and `"y"` come from one read
of the encoded point instead of two conversions to affine coordinates.
Encryption takes 46 µs (1.3 times go-jose) and decryption 35 µs (1.2
times). Key generation and agreement in OpenSSL are now 69% of encryption;
the one remaining `"epk"` validation is 15%, kept so that every key in a
header has been checked.
