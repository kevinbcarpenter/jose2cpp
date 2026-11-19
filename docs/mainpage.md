# jose2cpp API reference {#mainpage}

jose2cpp is JOSE for C++20: JWS, JWE, JWK and JWT on OpenSSL 3, written to
match go-jose v4 so tokens move between Go and C++ services without
surprises. This is the reference for the public headers. For building,
installing and longer examples, see the
[README](https://github.com/kevinbcarpenter/jose2cpp#readme).

## Where to start

| You want to                                 | Read                       |
| ------------------------------------------- | -------------------------- |
| issue or check JWTs                         | jwt.hpp, jwt_claims.hpp    |
| sign or verify anything                     | jws.hpp                    |
| encrypt or decrypt anything                 | jwe.hpp                    |
| load, generate or publish keys              | jwk.hpp                    |
| keep keys from a JWKS URL                   | optional/jwks_fetcher.hpp  |
| keep private keys in an HSM or a cloud KMS  | opaque.hpp, async.hpp      |
| find out what an error code means           | error.hpp                  |

Including jose/jose.hpp gets you everything except the JWKS fetcher.

## Things that hold everywhere

Nothing throws for bad input or failed crypto. Every call that can fail
returns jose::expected, and the error carries a jose::errc to branch on
and a message for logs.

Parsing never lets a token pick its own algorithm. Every parse call takes
the list of algorithms you accept, so a token signed with something else
fails before any key is touched. "none" isn't implemented at all, and keys
embedded in a token ("jwk", "x5c", "jku") are never used to verify it.

A jose::jwk always holds a valid key. Every way of making one checks the
key material, and the key's own "alg", "use" and "key_ops" are enforced on
every operation.

Key material, CEKs and decrypted plaintext live in jose::secure_bytes,
which zeroes memory before freeing it.

Where jose2cpp and go-jose behave differently on purpose, the header
says so next to the function.
