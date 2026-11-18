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
JWE. Consumers verify or decrypt with every listed key and (jose2cpp)
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
  "jws_incompatible": [{ ...as "jws", "reason": "..." }]
}
```

`keys` holds one key per signature/recipient, in order: public keys for JWS
(oct keys for HMAC), decryption keys for JWE. `legacy` marks RSA1_5.

`jws_incompatible` lists known differences. The other library must **reject**
them; each producer's own checker still requires them to verify. If a
consumer starts accepting one, its test fails so the vector can be moved
into `jws`.

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
- **AAD in compact form.** go-jose's JWE `CompactSerialize` doesn't refuse a
  JWE with `aad`; it drops it, producing a token that can't be decrypted.
  jose2cpp's `compact()` refuses. The `aad` vectors are JSON-only.
