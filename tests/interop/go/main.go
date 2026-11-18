// Interoperability harness between go-jose v4 and jose2cpp (PLAN.md Phase 2
// item 11).
//
//	go run . generate <out.json>   sign and encrypt with go-jose
//	go run . verify <in.json>      verify and decrypt jose2cpp's output
//
// Both directions use the same vector format (see README.md in the parent
// directory). Keys are JWKs, so each side parses the other's keys too.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"runtime/debug"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type jwsVector struct {
	Name           string            `json:"name"`
	Reason         string            `json:"reason,omitempty"` // jws_incompatible only
	Algorithms     []string          `json:"algorithms"`
	Keys           []json.RawMessage `json:"keys"`
	Payload        string            `json:"payload"` // base64url
	B64            bool              `json:"b64"`
	Serializations map[string]string `json:"serializations"`
}

type jweVector struct {
	Name           string            `json:"name"`
	Algorithms     []string          `json:"algorithms"`
	Encryption     string            `json:"enc"`
	Legacy         bool              `json:"legacy,omitempty"` // needs RSA1_5
	Keys           []json.RawMessage `json:"keys"`
	Plaintext      string            `json:"plaintext"` // base64url
	Serializations map[string]string `json:"serializations"`
}

// A JWT: "signed" (verification_key), "encrypted" (decryption_key) or
// "nested" (both). claims is the expected claims object.
type jwtVector struct {
	Name                string          `json:"name"`
	Reason              string          `json:"reason,omitempty"`        // jwt_incompatible only
	RejectedWith        string          `json:"rejected_with,omitempty"` // the consumer's error must contain this
	Kind                string          `json:"kind"`
	SignatureAlgorithms []string        `json:"signature_algorithms,omitempty"`
	KeyAlgorithms       []string        `json:"key_algorithms,omitempty"`
	Encryption          string          `json:"enc,omitempty"`
	VerificationKey     json.RawMessage `json:"verification_key,omitempty"`
	DecryptionKey       json.RawMessage `json:"decryption_key,omitempty"`
	Claims              json.RawMessage `json:"claims"`
	Token               string          `json:"token"`
}

type vectorFile struct {
	Producer string      `json:"producer"`
	JWS      []jwsVector `json:"jws"`
	JWE      []jweVector `json:"jwe"`
	JWT      []jwtVector `json:"jwt"`
	// Known incompatibilities: the consumer must NOT accept these. If it
	// starts to, the difference has been fixed and the vector can move.
	JWSIncompatible []jwsVector `json:"jws_incompatible"`
	JWTIncompatible []jwtVector `json:"jwt_incompatible"`
}

// go-jose v4 signs the raw payload when "b64" is false but still
// base64url-encodes it in both serializations, and base64url-decodes it
// when parsing, contrary to RFC 7797 §3 and §5. jose2cpp follows the RFC
// (and its §4 examples), so neither side verifies the other's tokens.
const b64Reason = "go-jose base64url-encodes the payload of b64=false tokens (RFC 7797 §3, §5)"

var b64u = base64.RawURLEncoding

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func goJoseVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == "github.com/go-jose/go-jose/v4" {
				return "go-jose " + dep.Version
			}
		}
	}
	return "go-jose v4"
}

// ===========================================================================
// generate
// ===========================================================================

type keys struct {
	rsa  *rsa.PrivateKey
	ec   map[string]*ecdsa.PrivateKey
	ed   ed25519.PrivateKey
	kids int
}

func newKeys() *keys {
	k := &keys{
		rsa: must(rsa.GenerateKey(rand.Reader, 2048)),
		ec:  map[string]*ecdsa.PrivateKey{},
	}
	for name, curve := range map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()} {
		k.ec[name] = must(ecdsa.GenerateKey(curve, rand.Reader))
	}
	_, k.ed = must2(ed25519.GenerateKey(rand.Reader))
	return k
}

func must2[A, B any](a A, b B, err error) (A, B) {
	if err != nil {
		panic(err)
	}
	return a, b
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	must(rand.Read(b))
	return b
}

func (k *keys) jwk(key interface{}) jose.JSONWebKey {
	k.kids++
	return jose.JSONWebKey{Key: key, KeyID: fmt.Sprintf("go-%d", k.kids)}
}

func marshal(k jose.JSONWebKey) json.RawMessage {
	return must(json.Marshal(k))
}

func publicJWK(k jose.JSONWebKey) json.RawMessage {
	if _, ok := k.Key.([]byte); ok {
		return marshal(k)
	}
	return marshal(k.Public())
}

var hmacSizes = map[jose.SignatureAlgorithm]int{jose.HS256: 32, jose.HS384: 48, jose.HS512: 64}

func (k *keys) signingKey(alg jose.SignatureAlgorithm) jose.JSONWebKey {
	switch alg {
	case jose.HS256, jose.HS384, jose.HS512:
		return k.jwk(randomBytes(hmacSizes[alg]))
	case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
		return k.jwk(k.rsa)
	case jose.ES256:
		return k.jwk(k.ec["P-256"])
	case jose.ES384:
		return k.jwk(k.ec["P-384"])
	case jose.ES512:
		return k.jwk(k.ec["P-521"])
	case jose.EdDSA:
		return k.jwk(k.ed)
	}
	panic("no key for " + alg)
}

func generateJWS(k *keys) []jwsVector {
	payload := []byte(`{"iss":"go-jose","msg":"interop ✓","n":42}`)
	algs := []jose.SignatureAlgorithm{
		jose.HS256, jose.HS384, jose.HS512, jose.RS256, jose.RS384, jose.RS512,
		jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.ES384, jose.ES512, jose.EdDSA,
	}
	var out []jwsVector
	for _, alg := range algs {
		key := k.signingKey(alg)
		signer := must(jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, (&jose.SignerOptions{}).WithType("JWT")))
		obj := must(signer.Sign(payload))
		out = append(out, jwsVector{
			Name:       string(alg),
			Algorithms: []string{string(alg)},
			Keys:       []json.RawMessage{publicJWK(key)},
			Payload:    b64u.EncodeToString(payload),
			B64:        true,
			Serializations: map[string]string{
				"compact": must(obj.CompactSerialize()),
				"json":    obj.FullSerialize(),
			},
		})
	}

	// Several signatures (general JSON).
	multi := []jose.JSONWebKey{k.signingKey(jose.RS256), k.signingKey(jose.ES384), k.signingKey(jose.EdDSA)}
	signer := must(jose.NewMultiSigner([]jose.SigningKey{
		{Algorithm: jose.RS256, Key: multi[0]}, {Algorithm: jose.ES384, Key: multi[1]}, {Algorithm: jose.EdDSA, Key: multi[2]},
	}, nil))
	obj := must(signer.Sign(payload))
	out = append(out, jwsVector{
		Name:           "multi-signature",
		Algorithms:     []string{"RS256", "ES384", "EdDSA"},
		Keys:           []json.RawMessage{publicJWK(multi[0]), publicJWK(multi[1]), publicJWK(multi[2])},
		Payload:        b64u.EncodeToString(payload),
		B64:            true,
		Serializations: map[string]string{"json": obj.FullSerialize()},
	})

	return out
}

func generateIncompatibleJWS(k *keys) []jwsVector {
	raw := []byte("unencoded payload, no dots")
	hk := k.signingKey(jose.HS256)
	signer := must(jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: hk}, (&jose.SignerOptions{}).WithBase64(false)))
	obj := must(signer.Sign(raw))
	return []jwsVector{{
		Name:       "b64=false",
		Reason:     b64Reason,
		Algorithms: []string{"HS256"},
		Keys:       []json.RawMessage{publicJWK(hk)},
		Payload:    b64u.EncodeToString(raw),
		B64:        false,
		Serializations: map[string]string{
			"compact": must(obj.CompactSerialize()),
			"json":    obj.FullSerialize(),
		},
	}}
}

var cekSizes = map[jose.ContentEncryption]int{
	jose.A128CBC_HS256: 32, jose.A192CBC_HS384: 48, jose.A256CBC_HS512: 64,
	jose.A128GCM: 16, jose.A192GCM: 24, jose.A256GCM: 32,
}

var kwSizes = map[jose.KeyAlgorithm]int{
	jose.A128KW: 16, jose.A192KW: 24, jose.A256KW: 32, jose.A128GCMKW: 16, jose.A192GCMKW: 24, jose.A256GCMKW: 32,
}

// The recipient (public or symmetric) and the matching decryption key.
func (k *keys) recipient(alg jose.KeyAlgorithm, enc jose.ContentEncryption, curve string) (jose.Recipient, jose.JSONWebKey) {
	switch alg {
	case jose.RSA1_5, jose.RSA_OAEP, jose.RSA_OAEP_256:
		priv := k.jwk(k.rsa)
		return jose.Recipient{Algorithm: alg, Key: priv.Public()}, priv
	case jose.ECDH_ES, jose.ECDH_ES_A128KW, jose.ECDH_ES_A192KW, jose.ECDH_ES_A256KW:
		priv := k.jwk(k.ec[curve])
		return jose.Recipient{Algorithm: alg, Key: priv.Public()}, priv
	case jose.DIRECT:
		key := k.jwk(randomBytes(cekSizes[enc]))
		return jose.Recipient{Algorithm: alg, Key: key}, key
	case jose.PBES2_HS256_A128KW, jose.PBES2_HS384_A192KW, jose.PBES2_HS512_A256KW:
		key := k.jwk([]byte("correct horse battery staple"))
		// Small count keeps the test fast; one vector below uses the default.
		return jose.Recipient{Algorithm: alg, Key: key, PBES2Count: 1000}, key
	default:
		key := k.jwk(randomBytes(kwSizes[alg]))
		return jose.Recipient{Algorithm: alg, Key: key}, key
	}
}

func jweSerializations(obj *jose.JSONWebEncryption) map[string]string {
	s := map[string]string{"json": obj.FullSerialize()}
	if compact, err := obj.CompactSerialize(); err == nil {
		s["compact"] = compact
	}
	return s
}

func generateJWE(k *keys) []jweVector {
	plaintext := []byte("go-jose → jose2cpp: The true sign of intelligence is not knowledge but imagination.")
	keyAlgs := []jose.KeyAlgorithm{
		jose.RSA1_5, jose.RSA_OAEP, jose.RSA_OAEP_256, jose.A128KW, jose.A192KW, jose.A256KW, jose.DIRECT,
		jose.ECDH_ES, jose.ECDH_ES_A128KW, jose.ECDH_ES_A192KW, jose.ECDH_ES_A256KW,
		jose.A128GCMKW, jose.A192GCMKW, jose.A256GCMKW,
		jose.PBES2_HS256_A128KW, jose.PBES2_HS384_A192KW, jose.PBES2_HS512_A256KW,
	}
	encs := []jose.ContentEncryption{
		jose.A128CBC_HS256, jose.A192CBC_HS384, jose.A256CBC_HS512, jose.A128GCM, jose.A192GCM, jose.A256GCM,
	}

	var out []jweVector
	add := func(name string, algs []jose.KeyAlgorithm, enc jose.ContentEncryption, keys []jose.JSONWebKey,
		pt []byte, obj *jose.JSONWebEncryption) {
		v := jweVector{Name: name, Encryption: string(enc), Plaintext: b64u.EncodeToString(pt),
			Serializations: jweSerializations(obj)}
		for _, a := range algs {
			v.Algorithms = append(v.Algorithms, string(a))
			v.Legacy = v.Legacy || a == jose.RSA1_5
		}
		for _, key := range keys {
			v.Keys = append(v.Keys, marshal(key))
		}
		out = append(out, v)
	}

	for _, alg := range keyAlgs {
		for _, enc := range encs {
			rcpt, key := k.recipient(alg, enc, "P-256")
			obj := must(must(jose.NewEncrypter(enc, rcpt, nil)).Encrypt(plaintext))
			add(string(alg)+" "+string(enc), []jose.KeyAlgorithm{alg}, enc, []jose.JSONWebKey{key}, plaintext, obj)
		}
	}

	// ECDH-ES on the other curves.
	for _, curve := range []string{"P-384", "P-521"} {
		for _, alg := range []jose.KeyAlgorithm{jose.ECDH_ES, jose.ECDH_ES_A256KW} {
			rcpt, key := k.recipient(alg, jose.A256GCM, curve)
			obj := must(must(jose.NewEncrypter(jose.A256GCM, rcpt, nil)).Encrypt(plaintext))
			add(string(alg)+" "+curve, []jose.KeyAlgorithm{alg}, jose.A256GCM, []jose.JSONWebKey{key}, plaintext, obj)
		}
	}

	// DEFLATE compression.
	long := bytes.Repeat([]byte("compressible "), 200)
	for _, alg := range []jose.KeyAlgorithm{jose.RSA_OAEP_256, jose.A256KW, jose.ECDH_ES} {
		rcpt, key := k.recipient(alg, jose.A128GCM, "P-256")
		enc := must(jose.NewEncrypter(jose.A128GCM, rcpt, &jose.EncrypterOptions{Compression: jose.DEFLATE}))
		add(string(alg)+" zip=DEF", []jose.KeyAlgorithm{alg}, jose.A128GCM, []jose.JSONWebKey{key}, long,
			must(enc.Encrypt(long)))
	}

	// PBES2 with go-jose's default iteration count.
	{
		key := k.jwk([]byte("correct horse battery staple"))
		rcpt := jose.Recipient{Algorithm: jose.PBES2_HS512_A256KW, Key: key}
		obj := must(must(jose.NewEncrypter(jose.A256GCM, rcpt, nil)).Encrypt(plaintext))
		add("PBES2 default p2c", []jose.KeyAlgorithm{jose.PBES2_HS512_A256KW}, jose.A256GCM,
			[]jose.JSONWebKey{key}, plaintext, obj)
	}

	// JSON "aad" member.
	{
		rcpt, key := k.recipient(jose.A128KW, jose.A128CBC_HS256, "")
		obj := must(must(jose.NewEncrypter(jose.A128CBC_HS256, rcpt, nil)).EncryptWithAuthData(plaintext, []byte("extra ✓")))
		add("aad", []jose.KeyAlgorithm{jose.A128KW}, jose.A128CBC_HS256, []jose.JSONWebKey{key}, plaintext, obj)
		// go-jose's CompactSerialize doesn't refuse a JWE with "aad"; it
		// silently drops it, producing a token nobody can decrypt.
		delete(out[len(out)-1].Serializations, "compact")
	}

	// Several recipients (general JSON).
	{
		algs := []jose.KeyAlgorithm{jose.RSA_OAEP, jose.A192KW, jose.ECDH_ES_A128KW, jose.A256GCMKW, jose.PBES2_HS256_A128KW}
		var rcpts []jose.Recipient
		var keys []jose.JSONWebKey
		for _, alg := range algs {
			rcpt, key := k.recipient(alg, jose.A256CBC_HS512, "P-384")
			rcpts = append(rcpts, rcpt)
			keys = append(keys, key)
		}
		enc := must(jose.NewMultiEncrypter(jose.A256CBC_HS512, rcpts, &jose.EncrypterOptions{Compression: jose.DEFLATE}))
		add("multi-recipient", algs, jose.A256CBC_HS512, keys, plaintext, must(enc.Encrypt(plaintext)))
	}
	return out
}

var jwtClaims = map[string]interface{}{
	"iss":  "https://issuer.example",
	"sub":  "kevin",
	"aud":  []interface{}{"api", "web"},
	"exp":  1900000000,
	"nbf":  1700000000,
	"name": "Kevin ✓",
	"ctx":  map[string]interface{}{"role": "admin", "levels": []interface{}{1, 2, 3}},
}

func generateJWT(k *keys) []jwtVector {
	claims := must(json.Marshal(jwtClaims))
	var out []jwtVector

	for _, alg := range []jose.SignatureAlgorithm{jose.HS256, jose.RS256, jose.PS384, jose.ES256, jose.ES512, jose.EdDSA} {
		key := k.signingKey(alg)
		signer := must(jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, (&jose.SignerOptions{}).WithType("JWT")))
		out = append(out, jwtVector{
			Name: "signed " + string(alg), Kind: "signed", SignatureAlgorithms: []string{string(alg)},
			VerificationKey: publicJWK(key), Claims: claims,
			Token: must(jwt.Signed(signer).Claims(jwtClaims).Serialize()),
		})
	}

	// Built from go-jose's own jwt.Claims, with a single audience, which
	// jwt.Audience writes as a plain string.
	{
		std := jwt.Claims{
			Issuer: "https://issuer.example", Subject: "kevin", Audience: jwt.Audience{"api"},
			Expiry: jwt.NewNumericDate(time.Unix(1900000000, 0)), NotBefore: jwt.NewNumericDate(time.Unix(1700000000, 0)),
			IssuedAt: jwt.NewNumericDate(time.Unix(1700000000, 0)), ID: "go-claims-1",
		}
		key := k.signingKey(jose.ES256)
		signer := must(jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType("JWT")))
		out = append(out, jwtVector{
			Name: "signed ES256 jwt.Claims", Kind: "signed", SignatureAlgorithms: []string{"ES256"},
			VerificationKey: publicJWK(key), Claims: must(json.Marshal(std)),
			Token: must(jwt.Signed(signer).Claims(std).Serialize()),
		})
	}

	type encCase struct {
		alg jose.KeyAlgorithm
		enc jose.ContentEncryption
	}
	for _, c := range []encCase{{jose.DIRECT, jose.A128GCM}, {jose.A256KW, jose.A256GCM}, {jose.A192GCMKW, jose.A192CBC_HS384}} {
		rcpt, key := k.recipient(c.alg, c.enc, "")
		enc := must(jose.NewEncrypter(c.enc, rcpt, (&jose.EncrypterOptions{}).WithType("JWT")))
		out = append(out, jwtVector{
			Name: "encrypted " + string(c.alg) + " " + string(c.enc), Kind: "encrypted",
			KeyAlgorithms: []string{string(c.alg)}, Encryption: string(c.enc),
			DecryptionKey: marshal(key), Claims: claims,
			Token: must(jwt.Encrypted(enc).Claims(jwtClaims).Serialize()),
		})
	}

	type nestedCase struct {
		alg jose.KeyAlgorithm
		enc jose.ContentEncryption
		sig jose.SignatureAlgorithm
	}
	for _, c := range []nestedCase{
		{jose.A128KW, jose.A128GCM, jose.RS256},
		{jose.DIRECT, jose.A256GCM, jose.ES256},
		{jose.A256GCMKW, jose.A256CBC_HS512, jose.EdDSA},
	} {
		sigKey := k.signingKey(c.sig)
		signer := must(jose.NewSigner(jose.SigningKey{Algorithm: c.sig, Key: sigKey}, (&jose.SignerOptions{}).WithType("JWT")))
		rcpt, decKey := k.recipient(c.alg, c.enc, "")
		enc := must(jose.NewEncrypter(c.enc, rcpt, (&jose.EncrypterOptions{}).WithContentType("JWT")))
		out = append(out, jwtVector{
			Name: "nested " + string(c.alg) + " " + string(c.enc) + " " + string(c.sig), Kind: "nested",
			SignatureAlgorithms: []string{string(c.sig)}, KeyAlgorithms: []string{string(c.alg)},
			Encryption: string(c.enc), VerificationKey: publicJWK(sigKey), DecryptionKey: marshal(decKey),
			Claims: claims, Token: must(jwt.SignedAndEncrypted(signer, enc).Claims(jwtClaims).Serialize()),
		})
	}
	return out
}

func generate(path string) error {
	k := newKeys()
	file := vectorFile{Producer: goJoseVersion(), JWS: generateJWS(k), JWE: generateJWE(k), JWT: generateJWT(k),
		JWSIncompatible: generateIncompatibleJWS(k), JWTIncompatible: []jwtVector{}}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// ===========================================================================
// verify
// ===========================================================================

func parseKeys(raw []json.RawMessage) ([]jose.JSONWebKey, error) {
	var out []jose.JSONWebKey
	for i, r := range raw {
		var k jose.JSONWebKey
		if err := json.Unmarshal(r, &k); err != nil {
			return nil, fmt.Errorf("key %d: %w", i, err)
		}
		out = append(out, k)
	}
	return out, nil
}

func verifyJWS(v jwsVector) error {
	keys, err := parseKeys(v.Keys)
	if err != nil {
		return err
	}
	want := must(b64u.DecodeString(v.Payload))
	var algs []jose.SignatureAlgorithm
	for _, a := range v.Algorithms {
		algs = append(algs, jose.SignatureAlgorithm(a))
	}
	for form, token := range v.Serializations {
		var obj *jose.JSONWebSignature
		if form == "compact" {
			obj, err = jose.ParseSignedCompact(token, algs)
		} else {
			obj, err = jose.ParseSignedJSON(token, algs)
		}
		if err != nil {
			return fmt.Errorf("%s: parse: %w", form, err)
		}
		for i, key := range keys {
			var got []byte
			if len(obj.Signatures) == 1 {
				got, err = obj.Verify(key)
			} else {
				_, _, got, err = obj.VerifyMulti(key)
			}
			if err != nil {
				return fmt.Errorf("%s: key %d: verify: %w", form, i, err)
			}
			if !bytes.Equal(got, want) {
				return fmt.Errorf("%s: key %d: payload mismatch", form, i)
			}
		}
	}
	return nil
}

func verifyJWE(v jweVector) error {
	keys, err := parseKeys(v.Keys)
	if err != nil {
		return err
	}
	want := must(b64u.DecodeString(v.Plaintext))
	var algs []jose.KeyAlgorithm
	for _, a := range v.Algorithms {
		algs = append(algs, jose.KeyAlgorithm(a))
	}
	encs := []jose.ContentEncryption{jose.ContentEncryption(v.Encryption)}
	for form, token := range v.Serializations {
		var obj *jose.JSONWebEncryption
		if form == "compact" {
			obj, err = jose.ParseEncryptedCompact(token, algs, encs)
		} else {
			obj, err = jose.ParseEncryptedJSON(token, algs, encs)
		}
		if err != nil {
			return fmt.Errorf("%s: parse: %w", form, err)
		}
		for i, key := range keys {
			// go-jose decrypts symmetric keys given as []byte, which is
			// what an oct JWK unmarshals to.
			got, err := obj.Decrypt(key)
			if len(keys) > 1 {
				_, _, got, err = obj.DecryptMulti(key)
			}
			if err != nil {
				return fmt.Errorf("%s: key %d: decrypt: %w", form, i, err)
			}
			if !bytes.Equal(got, want) {
				return fmt.Errorf("%s: key %d: plaintext mismatch", form, i)
			}
		}
	}
	return nil
}

func parseKey(raw json.RawMessage) (jose.JSONWebKey, error) {
	var k jose.JSONWebKey
	err := json.Unmarshal(raw, &k)
	return k, err
}

func verifyJWT(v jwtVector) error {
	var sigAlgs []jose.SignatureAlgorithm
	for _, a := range v.SignatureAlgorithms {
		sigAlgs = append(sigAlgs, jose.SignatureAlgorithm(a))
	}
	var keyAlgs []jose.KeyAlgorithm
	for _, a := range v.KeyAlgorithms {
		keyAlgs = append(keyAlgs, jose.KeyAlgorithm(a))
	}
	encs := []jose.ContentEncryption{jose.ContentEncryption(v.Encryption)}

	var got map[string]interface{}
	switch v.Kind {
	case "signed":
		key, err := parseKey(v.VerificationKey)
		if err != nil {
			return err
		}
		tok, err := jwt.ParseSigned(v.Token, sigAlgs)
		if err != nil {
			return fmt.Errorf("parse: %w", err)
		}
		if err := tok.Claims(key, &got); err != nil {
			return fmt.Errorf("claims: %w", err)
		}
	case "encrypted":
		key, err := parseKey(v.DecryptionKey)
		if err != nil {
			return err
		}
		tok, err := jwt.ParseEncrypted(v.Token, keyAlgs, encs)
		if err != nil {
			return fmt.Errorf("parse: %w", err)
		}
		if err := tok.Claims(key, &got); err != nil {
			return fmt.Errorf("claims: %w", err)
		}
	case "nested":
		verKey, err := parseKey(v.VerificationKey)
		if err != nil {
			return err
		}
		decKey, err := parseKey(v.DecryptionKey)
		if err != nil {
			return err
		}
		tok, err := jwt.ParseSignedAndEncrypted(v.Token, keyAlgs, encs, sigAlgs)
		if err != nil {
			return fmt.Errorf("parse: %w", err)
		}
		inner, err := tok.Decrypt(decKey)
		if err != nil {
			return fmt.Errorf("decrypt: %w", err)
		}
		if err := inner.Claims(verKey, &got); err != nil {
			return fmt.Errorf("claims: %w", err)
		}
	default:
		return fmt.Errorf("unknown kind %q", v.Kind)
	}
	var want map[string]interface{}
	if err := json.Unmarshal(v.Claims, &want); err != nil {
		return err
	}
	if !reflect.DeepEqual(got, want) {
		return fmt.Errorf("claims mismatch: got %v, want %v", got, want)
	}
	// The registered claims must also read through go-jose's jwt.Claims
	// (its Audience and NumericDate types).
	var std jwt.Claims
	if err := json.Unmarshal(v.Claims, &std); err != nil {
		return fmt.Errorf("jwt.Claims: %w", err)
	}
	if want["sub"] != nil && std.Subject != want["sub"] {
		return fmt.Errorf("jwt.Claims subject %q, want %v", std.Subject, want["sub"])
	}
	if exp, ok := want["exp"].(float64); ok && (std.Expiry == nil || std.Expiry.Time().Unix() != int64(exp)) {
		return fmt.Errorf("jwt.Claims expiry %v, want %v", std.Expiry, exp)
	}
	return nil
}

func verify(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var file vectorFile
	if err := json.Unmarshal(data, &file); err != nil {
		return err
	}
	if len(file.JWS) == 0 || len(file.JWE) == 0 || len(file.JWT) == 0 {
		return fmt.Errorf("%s has no vectors", path)
	}
	var failures []string
	count := 0
	for _, v := range file.JWS {
		count += len(v.Serializations)
		if err := verifyJWS(v); err != nil {
			failures = append(failures, "JWS "+v.Name+": "+err.Error())
		}
	}
	for _, v := range file.JWE {
		count += len(v.Serializations)
		if err := verifyJWE(v); err != nil {
			failures = append(failures, "JWE "+v.Name+": "+err.Error())
		}
	}
	for _, v := range file.JWT {
		count++
		if err := verifyJWT(v); err != nil {
			failures = append(failures, "JWT "+v.Name+": "+err.Error())
		}
	}
	// Each serialization of the other library's known incompatibilities
	// must fail here; go-jose's own must of course still verify.
	own := strings.HasPrefix(file.Producer, "go-jose")
	for _, v := range file.JWTIncompatible {
		err := verifyJWT(v)
		if own && err != nil {
			failures = append(failures, "JWT "+v.Name+": "+err.Error())
		} else if !own && err == nil {
			failures = append(failures, "JWT "+v.Name+": listed as incompatible ("+v.Reason+
				") but go-jose accepted it; move it to \"jwt\"")
		} else if !own && !strings.Contains(err.Error(), v.RejectedWith) {
			// Rejected, but not for the documented reason: the vector or
			// go-jose has changed, so the listed difference is unproven.
			failures = append(failures, "JWT "+v.Name+": expected go-jose to reject it with \""+v.RejectedWith+
				"\", got: "+err.Error())
		}
	}
	for _, v := range file.JWSIncompatible {
		if own {
			count += len(v.Serializations)
			if err := verifyJWS(v); err != nil {
				failures = append(failures, "JWS "+v.Name+": "+err.Error())
			}
			continue
		}
		for form, token := range v.Serializations {
			single := v
			single.Serializations = map[string]string{form: token}
			if verifyJWS(single) == nil {
				failures = append(failures, "JWS "+v.Name+" ("+form+"): listed as incompatible ("+v.Reason+
					") but go-jose accepted it; move it to \"jws\"")
			}
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("%d of %d vectors from %s failed:\n  %s", len(failures),
			len(file.JWS)+len(file.JWE)+len(file.JWT)+len(file.JWSIncompatible)+len(file.JWTIncompatible),
			file.Producer, strings.Join(failures, "\n  "))
	}
	fmt.Printf("%s verified %d JWS, %d JWE and %d JWT vectors (%d tokens) from %s", goJoseVersion(),
		len(file.JWS), len(file.JWE), len(file.JWT), count, file.Producer)
	if !own {
		fmt.Printf("; %d known incompatibilities still rejected", len(file.JWSIncompatible)+len(file.JWTIncompatible))
	}
	fmt.Println()
	return nil
}

func main() {
	if len(os.Args) != 3 || (os.Args[1] != "generate" && os.Args[1] != "verify") {
		fmt.Fprintln(os.Stderr, "usage: interop generate <out.json> | verify <in.json>")
		os.Exit(2)
	}
	var err error
	if os.Args[1] == "generate" {
		err = generate(os.Args[2])
	} else {
		err = verify(os.Args[2])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
