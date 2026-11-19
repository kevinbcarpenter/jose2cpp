#!/usr/bin/env python3
"""Writes the seed corpus for the fuzz targets from the test vectors.

    python3 -I fuzz/make_corpus.py

Sources: tests/vectors/*.json (RFC 7515-7520 examples) and the go-jose
interop vectors in tests/vectors/interop/. Each seed is named by a hash of
its contents, so rerunning doesn't duplicate anything. Existing seeds,
including ones added by hand or kept from fuzzing runs, are left alone.

Added by hand, not by this script: the PEM seeds in corpus/jwk (RSA as
PKCS#8, PKCS#1 private and public, and SPKI; EC as SEC 1, PKCS#8 and SPKI;
Ed25519; X25519; an X.509 certificate; a truncated key and a PEM wrapping
junk), made once with `openssl genpkey` / `pkey` / `rsa` / `ec` / `req`.
"""

import hashlib
import json
import pathlib
import zlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
VECTORS = ROOT / "tests" / "vectors"
CORPUS = ROOT / "fuzz" / "corpus"


def load(name):
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


seeds = {name: set() for name in ("base64url", "jwk", "jws", "jwe", "jwt", "inflate")}


def add(target, data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    if data:
        seeds[target].add(data)


def add_json(target, value):
    add(target, json.dumps(value, separators=(",", ":"), sort_keys=True))


def add_parts(token):
    for part in token.split("."):
        add("base64url", part)


# RFC vectors.
for v in load("jwk.json"):
    add_json("jwk", v["jwk"])
for v in load("jwk_sets.json"):
    add_json("jwk", v["jwks"])
for v in load("jws.json"):
    add("jws", v["compact"]) if v.get("compact") else None
    for form in ("general", "flattened"):
        if v.get(form):
            add_json("jws", v[form])
    if v.get("compact"):
        add_parts(v["compact"])
    for k in v["keys"]:
        add_json("jwk", k)
for v in load("jwe.json"):
    if v.get("compact"):
        add("jwe", v["compact"])
        add_parts(v["compact"])
    for form in ("general", "flattened"):
        if v.get(form):
            add_json("jwe", v[form])
    for k in v["keys"]:
        add_json("jwk", k)

# go-jose interop vectors, both directions.
for name in ("gojose.json", "jose2cpp.json"):
    d = load("interop/" + name)
    for v in d.get("jws", []) + d.get("jws_incompatible", []):
        for s in v.get("serializations", {}).values():
            add("jws", s)
        for k in v.get("keys", []):
            add_json("jwk", k)
    for v in d.get("jwe", []):
        for s in v.get("serializations", {}).values():
            add("jwe", s)
    for v in d.get("jwt", []) + d.get("jwt_incompatible", []):
        if v.get("token"):
            add("jwt", v["token"])
            add_parts(v["token"])
        if v.get("claims"):
            add_json("jwt", v["claims"])
    for v in d.get("jwt_validation", []):
        if v.get("claims"):
            add_json("jwt", v["claims"])

# A few hand-made claims sets at the edges of the registered claims.
for claims in (
    {"exp": 4611686018427387903, "nbf": -4611686018427387903, "iat": 0},
    {"exp": 1.5, "aud": "api", "iss": "", "sub": "s", "jti": "j"},
    {"aud": ["a", "b"], "exp": None},
    {"exp": "tomorrow"},
):
    add_json("jwt", claims)

# Raw DEFLATE streams (as JWE "zip":"DEF" carries them).
for text in (b"", b"a", b"hello hello hello hello", bytes(range(256)) * 4, b"{\"sub\":\"kevin\"}" * 50):
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    stream = c.compress(text) + c.flush()
    add("inflate", stream)
    add("inflate", stream[: len(stream) // 2])  # truncated

written = 0
for target, items in seeds.items():
    out = CORPUS / target
    out.mkdir(parents=True, exist_ok=True)
    for data in sorted(items):
        path = out / hashlib.sha1(data).hexdigest()
        if not path.exists():
            path.write_bytes(data)
            written += 1
    print(f"{target}: {len(items)} seeds")
print(f"{written} new files")
