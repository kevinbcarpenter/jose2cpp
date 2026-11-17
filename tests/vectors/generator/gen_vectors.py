"""Generate tests/vectors/*.json from RFC text files.

Usage:
    mkdir -p /tmp/rfc && for n in 3394 7515 7517 7518 7520 7638 8032 8037; do
        curl -sSfL -o /tmp/rfc/rfc$n.txt https://www.rfc-editor.org/rfc/rfc$n.txt
    done
    python3 -I tests/vectors/generator/gen_vectors.py /tmp/rfc tests/vectors

Every value is pulled from the RFC text programmatically (no hand
transcription) and normalised to unpadded base64url.
"""
import base64, json, re, sys, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rfcfig  # noqa: E402

RFC_DIR, OUT_DIR = sys.argv[1], sys.argv[2]


def rfc(n):
    return os.path.join(RFC_DIR, f"rfc{n}.txt")


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]*", s):
        raise ValueError(f"not base64url: {s[:60]!r}")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def hexb(s: str) -> bytes:
    return bytes.fromhex("".join(s.split()))


def check_b64(s):
    unb64u(s)  # raises on garbage
    return s


def unescape(s: str) -> bytes:
    """RFC 7520 writes non-ASCII as \\xNN escapes inside ASCII text."""
    return s.encode("latin-1").decode("unicode_escape").encode("latin-1")


def section(path, start_re, end_re):
    lines = rfcfig.clean_lines(path)
    out, on = [], False
    for line in lines:
        if not on and re.match(start_re, line):
            on = True
        elif on and re.match(end_re, line):
            break
        if on:
            out.append(line)
    if not out:
        raise ValueError(f"section {start_re} not found in {path}")
    return out


def json_block(text: str):
    """Parse the first JSON object in text, removing RFC line-wrap whitespace."""
    i = text.index("{")
    depth = 0
    for j in range(i, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return json.loads("".join(text[i : j + 1].split()))
    raise ValueError("unterminated JSON")


# --------------------------------------------------------------------------
# RFC 7520 (JOSE Cookbook)
# --------------------------------------------------------------------------
F = rfcfig.figures(rfc(7520))


def fig_b64(n):
    # Keep only the trailing run of pure base64url lines; anything above
    # it is prose the figure extractor picked up.
    body = []
    for line in reversed(F[n][1]):
        if not re.fullmatch(r"\s+[A-Za-z0-9_.-]+\s*", line):
            break
        body.append(line)
    if not body:
        raise ValueError(f"fig {n}: no base64url lines")
    value = rfcfig.b64(list(reversed(body)))
    for part in value.split("."):  # signing inputs are b64.b64
        check_b64(part)
    return value


def fig_json(n):
    return json_block("\n".join(F[n][1]))


def fig_quoted_bytes(n):
    out = []
    for line in F[n][1]:
        m = re.fullmatch(r'\s+"([^"]*)"\s*', line)
        if m:
            out.append(unescape(m.group(1)))
    return b"".join(out)


plaintext_7520 = fig_quoted_bytes(72)
payload_7520 = unb64u(fig_b64(8))
assert payload_7520 == fig_quoted_bytes(7), "RFC 7520 fig 7/8 payload mismatch"


def ascii_b64(n):
    """AAD for compact JWE = ASCII(BASE64URL(protected header))."""
    return b64u(fig_b64(n).encode("ascii"))


signatures = []
content = []
aes_kw = []
aes_gcm_kw = []
rsa_kek = []
ecdh = []
pbes2 = []

for sec, alg, key_fig, input_fig, sig_fig, det in [
    ("4.1", "RS256", 4, 11, 12, True),
    ("4.2", "PS384", 4, 18, 19, False),
    ("4.3", "ES512", 2, 25, 26, False),
    ("4.4", "HS256", 5, 32, 33, True),
]:
    signatures.append({
        "source": f"RFC 7520 §{sec}",
        "alg": alg,
        "key": fig_json(key_fig),
        "message": b64u(fig_b64(input_fig).encode("ascii")),
        "signature": fig_b64(sig_fig),
        "deterministic": det,
    })

# content encryption: (section, enc, cek source, iv, protected-header b64, ct, tag)
# cek source is either a fig number of a base64url CEK or ("jwk", fig).
for sec, enc, cek_src, iv_fig, hdr_fig, ct_fig, tag_fig in [
    ("5.1", "A128CBC-HS256", 74, 75, 78, 79, 80),
    ("5.2", "A256GCM", 85, 86, 89, 90, 91),
    ("5.4", "A128GCM", 109, 110, 114, 115, 116),
    ("5.5", "A128CBC-HS256", 123, 121, 125, 126, 127),
    ("5.6", "A128GCM", ("jwk", 130), 131, 133, 134, 135),
    ("5.7", "A128CBC-HS256", 139, 140, 145, 146, 147),
    ("5.8", "A128GCM", 152, 153, 156, 157, 158),
]:
    cek = fig_json(cek_src[1])["k"] if isinstance(cek_src, tuple) else fig_b64(cek_src)
    content.append({
        "source": f"RFC 7520 §{sec}",
        "enc": enc,
        "cek": check_b64(cek),
        "iv": fig_b64(iv_fig),
        "plaintext": b64u(plaintext_7520),
        "aad": ascii_b64(hdr_fig),
        "ciphertext": fig_b64(ct_fig),
        "tag": fig_b64(tag_fig),
    })

rsa_kek.append({
    "source": "RFC 7520 §5.1",
    "alg": "RSA1_5",
    "key": fig_json(73),
    "encrypted_key": fig_b64(76),
    "cek": fig_b64(74),
})
rsa_kek.append({
    "source": "RFC 7520 §5.2",
    "alg": "RSA-OAEP",
    "key": fig_json(84),
    "encrypted_key": fig_b64(87),
    "cek": fig_b64(85),
})

hdr_53 = fig_json(101)
pbes2.append({
    "source": "RFC 7520 §5.3",
    "alg": hdr_53["alg"],
    "password": b64u(unescape(F[96][1][0].strip())),
    "p2s": check_b64(hdr_53["p2s"]),
    "p2c": hdr_53["p2c"],
    "encrypted_key": fig_b64(100),
    "cek": fig_b64(97),
})
assert unb64u(pbes2[-1]["p2s"]) == unb64u(fig_b64(99))

hdr_54 = fig_json(113)
eph_54 = fig_json(111)
assert {k: eph_54[k] for k in ("kty", "crv", "x", "y")} == hdr_54["epk"]
ecdh.append({
    "source": "RFC 7520 §5.4",
    "alg_id": "ECDH-ES+A128KW",
    "keydatalen": 128,
    "apu": "",
    "apv": "",
    "recipient": fig_json(108),
    "ephemeral": eph_54,
    "kw_alg": "A128KW",
    "encrypted_key": fig_b64(112),
    "cek": fig_b64(109),
})

hdr_55 = fig_json(124)
eph_55 = fig_json(122)
assert {k: eph_55[k] for k in ("kty", "crv", "x", "y")} == hdr_55["epk"]
ecdh.append({
    "source": "RFC 7520 §5.5",
    "alg_id": "A128CBC-HS256",
    "keydatalen": 256,
    "apu": "",
    "apv": "",
    "recipient": fig_json(120),
    "ephemeral": eph_55,
    "derived_key": fig_b64(123),
})

aes_gcm_kw.append({
    "source": "RFC 7520 §5.7",
    "alg": "A256GCMKW",
    "kek": check_b64(fig_json(138)["k"]),
    "iv": fig_b64(141),
    "tag": fig_b64(143),
    "encrypted_key": fig_b64(142),
    "cek": fig_b64(139),
})

aes_kw.append({
    "source": "RFC 7520 §5.8",
    "alg": "A128KW",
    "kek": check_b64(fig_json(151)["k"]),
    "cek": fig_b64(152),
    "wrapped": fig_b64(154),
})

# --------------------------------------------------------------------------
# RFC 7518 Appendix B (AES-CBC-HMAC) and C (ECDH-ES)
# --------------------------------------------------------------------------
def hex_fields(lines):
    """Parse 'NAME = hex ...' blocks with continuation lines."""
    fields, cur = {}, None
    for line in lines:
        m = re.match(r"^\s+([A-Z_]+)\s*=\s*((?:[0-9a-f]{2} ?)+)\s*$", line)
        if m:
            cur = m.group(1)
            fields[cur] = m.group(2)
        elif cur and re.match(r"^\s+((?:[0-9a-f]{2} ?)+)\s*$", line):
            fields[cur] += " " + line.strip()
        else:
            cur = None
    return {k: hexb(v) for k, v in fields.items()}


for sub, enc, next_re in [
    ("B.1", "A128CBC-HS256", r"^B\.2\."),
    ("B.2", "A192CBC-HS384", r"^B\.3\."),
    ("B.3", "A256CBC-HS512", r"^Appendix C\."),
]:
    f = hex_fields(section(rfc(7518), rf"^{re.escape(sub)}\.  Test Cases", next_re))
    assert f["K"] == f["MAC_KEY"] + f["ENC_KEY"]
    assert f["M"][: len(f["T"])] == f["T"]
    content.append({
        "source": f"RFC 7518 Appendix {sub}",
        "enc": enc,
        "cek": b64u(f["K"]),
        "iv": b64u(f["IV"]),
        "plaintext": b64u(f["P"]),
        "aad": b64u(f["A"]),
        "ciphertext": b64u(f["E"]),
        "tag": b64u(f["T"]),
    })

app_c = "\n".join(section(rfc(7518), r"^Appendix C\.", r"^Acknowledgements"))
jwks_c = []
pos = 0
while len(jwks_c) < 2:
    i = app_c.index('{"kty"', pos)
    jwks_c.append(json_block(app_c[i:]))
    pos = i + 1
derived_c = re.search(r"representation of this derived key is:\s*\n\s*(\S+)", app_c)
ecdh.append({
    "source": "RFC 7518 Appendix C",
    "alg_id": "A128GCM",
    "keydatalen": 128,
    "apu": b64u(b"Alice"),
    "apv": b64u(b"Bob"),
    "recipient": jwks_c[1],
    "ephemeral": jwks_c[0],
    "derived_key": check_b64(derived_c.group(1)),
})
assert ecdh[-1]["derived_key"] == "VqqN6vgjbSBcIijNcacQGg"

# --------------------------------------------------------------------------
# RFC 3394 §4 (AES Key Wrap)
# --------------------------------------------------------------------------
kw_alg = {16: "A128KW", 24: "A192KW", 32: "A256KW"}
for n in range(1, 7):
    lines = section(rfc(3394), rf"^4\.{n} Wrap", rf"^(4\.{n + 1} |5\. )")
    text = "\n".join(lines)
    kek = hexb(re.search(r"KEK:\s*([0-9A-F]+)", text).group(1))
    data = hexb(re.search(r"Key Data:\s*([0-9A-F]+)", text).group(1))
    ct_m = re.search(r"Ciphertext:?\s+((?:[0-9A-F]{16}\s+)+)", text)
    ct = hexb(ct_m.group(1))
    assert len(ct) == len(data) + 8, (n, len(ct), len(data))
    aes_kw.append({
        "source": f"RFC 3394 §4.{n}",
        "alg": kw_alg[len(kek)],
        "kek": b64u(kek),
        "cek": b64u(data),
        "wrapped": b64u(ct),
    })

# --------------------------------------------------------------------------
# RFC 7517 Appendix C (PBES2-HS256+A128KW)
# --------------------------------------------------------------------------
app = "\n".join(section(rfc(7517), r"^C\.2\.", r"^C\.6\."))
hdr = json_block(app)
nums = lambda s: bytes(int(x) for x in re.findall(r"\d+", s))
cek_c = nums(re.search(r"the value \(using JSON array\s+notation\) is:\s*(\[[^\]]*\])", app).group(1))
ek_c = re.search(r"BASE64URL\(JWE Encrypted Key\) gives\s+this value:\s*(\S+)", app).group(1)
pw_c = re.search(r"passphrase:\s*\n\s*(.+?)\s*\n", app).group(1)
pbes2.append({
    "source": "RFC 7517 Appendix C",
    "alg": hdr["alg"],
    "password": b64u(pw_c.encode()),
    "p2s": check_b64(hdr["p2s"]),
    "p2c": hdr["p2c"],
    "encrypted_key": check_b64(ek_c),
    "cek": b64u(cek_c),
})
assert pw_c == "Thus from my lips, by yours, my sin is purged."

# --------------------------------------------------------------------------
# RFC 7515 Appendix A (HS256, RS256, ES256, ES512)
# --------------------------------------------------------------------------
for sub, alg, det, next_re in [
    ("A.1", "HS256", True, r"^A\.1\.2\."),
    ("A.2", "RS256", True, r"^A\.2\.2\."),
    ("A.3", "ES256", False, r"^A\.3\.2\."),
    ("A.4", "ES512", False, r"^A\.4\.2\."),
]:
    text = "\n".join(section(rfc(7515), rf"^{re.escape(sub)}\.1\.  Encoding", next_re))
    jwk = json_block(text[text.index('{"kty"'):])
    # The last compact serialization in the section: header . payload . sig
    tail = text[text.rindex("JWS Compact Serialization"):]
    compact = "".join(tail.split(":", 1)[1].split())
    parts = compact.split(".")
    assert len(parts) == 3, (sub, compact[:80])
    for p in parts:
        check_b64(p)
    signatures.append({
        "source": f"RFC 7515 Appendix {sub}",
        "alg": alg,
        "key": jwk,
        "message": b64u(f"{parts[0]}.{parts[1]}".encode("ascii")),
        "signature": parts[2],
        "deterministic": det,
    })

# --------------------------------------------------------------------------
# RFC 8037 Appendix A (Ed25519 signing, X25519/X448 ECDH-ES)
# --------------------------------------------------------------------------
t8037 = "\n".join(rfcfig.clean_lines(rfc(8037)))
a1 = t8037[t8037.rindex("A.1.  Ed25519 Private Key"):]
ed_jwk = json_block(a1)
a4 = t8037[t8037.rindex("A.4.  Ed25519 Signing"):t8037.rindex("A.5.  Ed25519 Validation")]
sig_in = re.search(r"signing input is.*?is:\s*\n\s*(\S+)\s*\n", a4, re.S).group(1)
sig_hex = re.search(r"signature \(hex\):\s*\n((?:\s*(?:[0-9a-f]{2} ?)+\n)+)", a4).group(1)
sig_b64 = "".join(re.search(r"Converting this to base64url yields:\s*\n(.*?)\n\s*\n?\s*So", a4, re.S).group(1).split())
assert b64u(hexb(sig_hex)) == sig_b64
signatures.append({
    "source": "RFC 8037 Appendix A.4",
    "alg": "EdDSA",
    "key": ed_jwk,
    "message": b64u(sig_in.encode("ascii")),
    "signature": sig_b64,
    "deterministic": True,
})


def hex_after(text, label):
    m = re.search(re.escape(label) + r".*?\n((?:\s*(?:[0-9a-f]{2} ?)+\n)+)", text, re.S)
    return hexb(m.group(1))


for sub, crv, alg_id, bits, end in [
    ("A.6", "X25519", "ECDH-ES+A128KW", 128, "A.7.  ECDH-ES with X448"),
    ("A.7", "X448", "ECDH-ES+A256KW", 256, "Author"),
]:
    start = {"A.6": "A.6.  ECDH-ES with X25519", "A.7": "A.7.  ECDH-ES with X448"}[sub]
    t = t8037[t8037.rindex(start):t8037.index(end, t8037.rindex(start))]
    recv_pub = hex_after(t, "The public key from the target key is (hex)")
    eph_sec = hex_after(t, "The ephemeral secret happens to be (hex)")
    eph_pub = hex_after(t, "So the ephemeral public key is")
    z = hex_after(t, "And the sender computes the DH Z value")
    assert z == hex_after(t, "The receiver computes the DH Z value")
    hdr = json_block(t[t.index('{"alg"'):])
    assert hdr["alg"] == alg_id and unb64u(hdr["epk"]["x"]) == eph_pub
    ecdh.append({
        "source": f"RFC 8037 Appendix {sub}",
        "alg_id": alg_id,
        "keydatalen": bits,
        "apu": "",
        "apv": "",
        "recipient": {"kty": "OKP", "crv": crv, "x": b64u(recv_pub)},
        "ephemeral": {"kty": "OKP", "crv": crv, "x": b64u(eph_pub), "d": b64u(eph_sec)},
        "z": b64u(z),
    })

# --------------------------------------------------------------------------
# RFC 8032 §7.4 (Ed448, "1 octet" and "blank" vectors)
# --------------------------------------------------------------------------
t8032 = "\n".join(l for l in rfcfig.clean_lines(rfc(8032)))
s74 = t8032[t8032.rindex("7.4.  Test Vectors for Ed448"):t8032.rindex("7.5.  Test Vectors for Ed448ph")]
for name in ("Blank", "1 octet"):
    blk = s74[s74.index("-----" + name):]
    blk = blk[: blk.index("-----", 5)]

    def hx(label):
        m = re.search(label + r"[^\n]*:\s*\n((?:\s*[0-9a-f]+\s*\n)*)", blk)
        return hexb(m.group(1))

    sk, pk, msg, sig = hx("SECRET KEY"), hx("PUBLIC KEY"), hx("MESSAGE"), hx("SIGNATURE")
    assert len(sk) == 57 and len(pk) == 57 and len(sig) == 114, name
    signatures.append({
        "source": f"RFC 8032 §7.4 ({name})",
        "alg": "EdDSA",
        "key": {"kty": "OKP", "crv": "Ed448", "x": b64u(pk), "d": b64u(sk)},
        "message": b64u(msg),
        "signature": b64u(sig),
        "deterministic": True,
    })

# --------------------------------------------------------------------------
# JWK parsing / thumbprints: RFC 7517 App. A + B, RFC 7638 §3.1,
# RFC 8037 App. A, RFC 7520 §3 and the §5 encryption keys.
# --------------------------------------------------------------------------
def json_block_wrapped(text: str):
    """Like json_block, but only joins RFC line wraps (strip each line and
    concatenate), so spaces inside string values survive."""
    i = text.index("{")
    depth, in_str, esc = 0, False, False
    for j in range(i, len(text)):
        ch = text[j]
        if in_str:
            esc = (ch == "\\") and not esc
            if ch == '"' and not esc:
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return json.loads("".join(l.strip() for l in text[i : j + 1].split("\n")))
    raise ValueError("unterminated JSON")


jwk_cases = []
jwk_sets = []

t7517 = "\n".join(rfcfig.clean_lines(rfc(7517)))
for sub, nxt, private in [("A.1", "A.2", False), ("A.2", "A.3", True), ("A.3", "Appendix B", None)]:
    start = t7517.rindex(f"{sub}.  Example")
    blk = t7517[start:t7517.index(nxt, start + 5)]
    jset = json_block_wrapped(blk)
    assert len(jset["keys"]) == 2, sub
    jwk_sets.append({"source": f"RFC 7517 Appendix {sub}", "jwks": jset})
    for k in jset["keys"]:
        jwk_cases.append({"source": f"RFC 7517 Appendix {sub}", "jwk": k,
                          "private": k["kty"] == "oct" or "d" in k})

b = t7517[t7517.rindex("Appendix B.  Example Use"):t7517.rindex("Appendix C.  Example Encrypted")]
x5c_jwk = json_block_wrapped(b)
assert len(x5c_jwk["x5c"]) == 1
base64.b64decode(x5c_jwk["x5c"][0], validate=True)  # standard base64, not url
jwk_cases.append({"source": "RFC 7517 Appendix B", "jwk": x5c_jwk, "private": False})

t7638 = "\n".join(rfcfig.clean_lines(rfc(7638)))
s31 = t7638[t7638.rindex("3.1.  Example JWK Thumbprint Computation"):t7638.rindex("3.2.  JWK Members Used")]
tp_7638 = re.search(r"\(key ID\) value\) is:\s*\n\s*(\S+)", s31).group(1)
jwk_cases.append({"source": "RFC 7638 §3.1", "jwk": json_block_wrapped(s31), "private": False,
                  "thumbprint_sha256": check_b64(tp_7638)})
assert tp_7638 == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

a3 = t8037[t8037.rindex("A.3.  JWK Thumbprint Canonicalization"):t8037.rindex("A.4.  Ed25519 Signing")]
tp_8037 = re.search(r'representation\s+of "([^"]+)"', a3).group(1)
assert tp_8037 == "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
jwk_cases.append({"source": "RFC 8037 Appendix A.1", "jwk": ed_jwk, "private": True,
                  "thumbprint_sha256": tp_8037})
a2 = t8037[t8037.rindex("A.2.  Ed25519 Public Key"):t8037.rindex("A.3.  JWK Thumbprint")]
jwk_cases.append({"source": "RFC 8037 Appendix A.2", "jwk": json_block(a2), "private": False,
                  "thumbprint_sha256": tp_8037})
for c in ecdh:
    if c["source"].startswith("RFC 8037"):
        jwk_cases.append({"source": c["source"], "jwk": c["recipient"], "private": False})

for n in (1, 2, 3, 4, 5, 6, 73, 84, 108, 120, 130, 138, 151):
    k = fig_json(n)
    jwk_cases.append({"source": f"RFC 7520 Figure {n}", "jwk": k,
                      "private": k["kty"] == "oct" or "d" in k})

# --------------------------------------------------------------------------
os.makedirs(OUT_DIR, exist_ok=True)
for name, cases in [
    ("signatures", signatures),
    ("content_encryption", content),
    ("aes_kw", aes_kw),
    ("aes_gcm_kw", aes_gcm_kw),
    ("rsa_key_encryption", rsa_kek),
    ("ecdh_es", ecdh),
    ("pbes2", pbes2),
    ("jwk", jwk_cases),
    ("jwk_sets", jwk_sets),
]:
    # Every string field except a few known non-b64 ones must decode.
    for c in cases:
        for k, v in c.items():
            if isinstance(v, str) and k not in ("source", "alg", "enc", "alg_id", "kw_alg"):
                check_b64(v)
    with open(os.path.join(OUT_DIR, f"{name}.json"), "w") as fh:
        json.dump(cases, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print(f"{name}: {len(cases)} cases")
