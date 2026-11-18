# go-jose interoperability

Checks that jose2cpp and [go-jose](https://github.com/go-jose/go-jose) v4 read
each other's output (PLAN.md Phase 2 item 11).

| Direction           | Producer                          | Consumer                          |
| ------------------- | --------------------------------- | --------------------------------- |
| go-jose → jose2cpp  | `go/` (`go run . generate`)       | `tests/test_interop.cpp`          |
| jose2cpp → go-jose  | `gen_jose2cpp.cpp` (`jose_interop_gen`) | `go/` (`go run . verify`)   |

Both directions cover every JWS algorithm and every JWE key-management
algorithm × content encryption that go-jose supports, in compact and JSON
form, plus ECDH-ES on P-384/P-521, DEFLATE, PBES2 at the producer's default
iteration count, the JSON `aad` member, multiple signatures and five-recipient
JWE. They also cover JWTs: signed with six algorithms, encrypted with `dir`,
AES key wrap and AES-GCM key wrap, and nested, each checked down to the
claims. One JWT each way is built from the library's own claims type
(go-jose's `jwt.Claims`, jose2cpp's `jwt::registered_claims`) with a single
audience, which both write as a plain string, and every JWT's claims are also
read back through the other library's claims type. go-jose also writes out
40 claims-validation cases with its own answers (see below), and jose2cpp has
to agree with each one. Consumers verify or decrypt with every listed key and (jose2cpp)
re-serialize the parsed object, compact byte-for-byte and JSON by value.

Not covered because go-jose doesn't support them: Ed448, and ECDH-ES with
X25519/X448.

## Checked-in vectors

`tests/vectors/interop/gojose.json` and `jose2cpp.json` are checked by the
normal test suite (`[interop]`), so no Go toolchain is needed day to day.
Refresh them with:

```sh
cmake --preset system-macos -DJOSE_INTEROP_GO=ON
cmake --build --preset system-macos --target interop_vectors
```

## Live tests

With `-DJOSE_INTEROP_GO=ON`, ctest also generates fresh vectors on both sides
and has each library check the other's (`interop.*` tests). The first run
downloads go-jose (pinned in `go/go.mod` / `go.sum`) through the Go module
proxy.

## Vector format

```json
{
  "producer": "go-jose v4.1.9",
  "jws": [{ "name", "algorithms": ["ES256"], "keys": [JWK...], "payload": "<b64url>",
            "b64": true, "serializations": { "compact": "...", "json": "..." } }],
  "jwe": [{ "name", "algorithms": [...], "enc": "A256GCM", "legacy": false,
            "keys": [JWK...], "plaintext": "<b64url>", "serializations": {...} }],
  "jwt": [{ "name", "kind": "signed" | "encrypted" | "nested",
            "signature_algorithms": [...], "key_algorithms": [...], "enc": "A256GCM",
            "verification_key": JWK, "decryption_key": JWK,
            "claims": { ... }, "token": "<compact>" }],
  "jws_incompatible": [{ ...as "jws", "reason": "..." }],
  "jwt_incompatible": [{ ...as "jwt", "reason": "..." }],
  "jwt_validation": [{ "name", "claims": { ... }, "expected": { "iss", "sub", "aud": [...], "jti" },
                       "time": <seconds>, "time_nanos": <nanoseconds, a whole number of microseconds>, "leeway": <seconds>,
                       "result": "" | "iss" | "sub" | "jti" | "aud" | "nbf" | "exp" | "iat" }]
}
```

`jwt_validation` is in go-jose's file only. Each case is go-jose's
`ValidateWithLeeway` answer: `""` when the claims pass, otherwise the claim
that failed. An expectation go-jose wouldn't check (`""`) is left out.

A `jwt` entry has only the fields its `kind` needs: a signed JWT has no
decryption key, an encrypted one no signature algorithms or verification key.
`claims` is what the consumer must get back after verifying or decrypting.

`keys` holds one key per signature/recipient, in order: public keys for JWS
(oct keys for HMAC), decryption keys for JWE. `legacy` marks RSA1_5.

`jws_incompatible` and `jwt_incompatible` list known differences. The other library must **reject**
them; each producer's own checker still requires them to verify. If a
consumer starts accepting one, its test fails so the vector can be moved
into `jws` or `jwt`.

## Known differences

- **RFC 7797 `b64=false`.** go-jose v4 signs the raw payload but still
  base64url-encodes it in both serializations, and base64url-decodes it when
  parsing, contrary to RFC 7797 §3 and §5. jose2cpp follows the RFC (and
  verifies its §4 examples), so neither library verifies the other's
  unencoded-payload tokens.
- **Stray `encrypted_key` in general JWE JSON.** go-jose's `FullSerialize`
  copies the first recipient's `encrypted_key` to the top level next to
  `recipients`. jose2cpp ignores that exact copy (and doesn't emit it); any
  other mix of general and flattened members is still rejected.
- **Nested JWTs with a public-key or password JWE.** jose2cpp's split rule
  limits encrypted-only JWTs to `dir`, AES key wrap and AES-GCM key wrap (an
  unsigned token encrypted to a public key can be forged by anyone holding
  that key), but lets nested JWTs, which are signed inside, use any key
  algorithm. go-jose v4.1.9 refuses RSA, ECDH-ES and PBES2 for nested JWTs
  too ("asymmetric encryption algorithms not supported for JWT"), so it
  rejects jose2cpp's nested JWTs that use them. Those are in
  `jwt_incompatible`, and go-jose has to reject them with exactly that
  error, so a vector that fails for some other reason doesn't count. Every
  nested JWT go-jose builds, jose2cpp reads.
- **Encrypted-only JWTs go-jose builds but won't parse.** go-jose applies its
  key-algorithm limit only in `jwt.ParseEncrypted`; `jwt.Encrypted` builds a
  token with any encrypter. jose2cpp refuses RSA, ECDH-ES and PBES2 for
  encrypted-only JWTs when building as well as parsing, so a go-jose producer
  can emit an RSA-OAEP or ECDH-ES encrypted-only JWT that jose2cpp (and
  go-jose's own parser) rejects. go-jose's `ParseEncrypted` also ignores
  `cty`, while jose2cpp's `parse_encrypted` refuses a token marked
  `"cty":"JWT"` and points at `parse_signed_and_encrypted`, since that token
  is nested. These aren't in the vectors: go-jose's own checker can't read
  the first kind, and the second is a misuse.
- **AAD in compact form.** go-jose's JWE `CompactSerialize` doesn't refuse a
  JWE with `aad`; it drops it, producing a token that can't be decrypted.
  jose2cpp's `compact()` refuses. The `aad` vectors are JSON-only.
- **A token at the instant of expiry.** RFC 7519 §4.1.4 says a JWT must not
  be accepted "on or after" `exp`. jose2cpp's `validate` treats exactly `exp`
  plus the leeway as expired; go-jose's `ValidateWithLeeway` only rejects
  after it. Three `jwt_validation` cases sit on that instant, and the C++
  test requires go-jose to still accept them and jose2cpp to reject them.
