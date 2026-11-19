// go-jose v4 benchmarks to compare with jose2cpp's jose_bench (PLAN.md Phase
// 3 item 11, §Benchmarks). The cases, keys, payloads, timing loop and output
// match benchmarks/bench_main.cpp; benchmarks/compare.py runs both.
//
//	go run . [--quick] [--list] [--filter TEXT] [--time-ms N] [--samples N] [--keys FILE]
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type benchCase struct {
	name string
	op   func() int // returns a size so the work can't be optimized out
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "go_bench: "+format+"\n", args...)
	os.Exit(1)
}

func must[T any](v T, err error) T {
	if err != nil {
		die("%v", err)
	}
	return v
}

// --- Inputs shared with benchmarks/bench_main.cpp ---------------------------

const smallPayload = `{"iss":"https://auth.example.com","sub":"user-1234567890","aud":"api.example.com",` +
	`"exp":4102444800,"iat":1700000000,"jti":"4f1c2a9e-7b3d-4e8a-9c61-0d5f2b8e3a17",` +
	`"scope":"read:messages write:messages","name":"Example User"}`

func largePayload() []byte {
	v := make([]byte, 64*1024)
	for i := range v {
		v[i] = byte(i % 251)
	}
	return v
}

const validateAt = 1800000000

// --- Timing -----------------------------------------------------------------

type settings struct {
	sampleTime time.Duration
	samples    int
	filter     string
	quick      bool
}

var sink int

func run(c benchCase, s settings) {
	iterations := 1
	var perOp []float64
	if s.quick {
		sink += c.op()
		perOp = append(perOp, 0)
	} else {
		warmUntil := time.Now().Add(s.sampleTime / 4)
		warm := 0
		start := time.Now()
		for {
			sink += c.op()
			warm++
			if !time.Now().Before(warmUntil) {
				break
			}
		}
		ns := float64(time.Since(start).Nanoseconds()) / float64(warm)
		iterations = max(1, int(float64(s.sampleTime.Nanoseconds())/ns))
		for k := 0; k < s.samples; k++ {
			t0 := time.Now()
			for i := 0; i < iterations; i++ {
				sink += c.op()
			}
			perOp = append(perOp, float64(time.Since(t0).Nanoseconds())/float64(iterations))
		}
	}
	sort.Float64s(perOp)
	out, _ := json.Marshal(map[string]any{
		"impl":          "go-jose",
		"case":          c.name,
		"ns_per_op":     perOp[len(perOp)/2],
		"min_ns_per_op": perOp[0],
		"iterations":    iterations,
		"samples":       len(perOp),
	})
	fmt.Println(string(out))
}

// --- Cases ------------------------------------------------------------------

type keyring map[string]json.RawMessage

func (k keyring) get(name string) jose.JSONWebKey {
	raw, ok := k[name]
	if !ok {
		die("keys file has no %q", name)
	}
	var key jose.JSONWebKey
	if err := key.UnmarshalJSON(raw); err != nil {
		die("key %s: %v", name, err)
	}
	return key
}

func (k keyring) pub(name string) jose.JSONWebKey {
	key := k.get(name)
	if _, symmetric := key.Key.([]byte); symmetric {
		return key
	}
	return key.Public()
}

func makeCases(keys keyring) []benchCase {
	var cases []benchCase
	large := largePayload()

	// JWS: Sign + CompactSerialize, then ParseSignedCompact + Verify.
	addJWS := func(alg jose.SignatureAlgorithm, key string, payload []byte, suffix string) {
		name := string(alg) + suffix
		signer := must(jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: keys.get(key)}, nil))
		verifier := keys.pub(key)
		token := must(must(signer.Sign(payload)).CompactSerialize())
		check := must(must(jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{alg})).Verify(verifier))
		if !bytes.Equal(check, payload) {
			die("verify %s: payload differs", name)
		}
		cases = append(cases,
			benchCase{"jws.sign/" + name, func() int {
				return len(must(must(signer.Sign(payload)).CompactSerialize()))
			}},
			benchCase{"jws.verify/" + name, func() int {
				p := must(jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{alg}))
				return len(must(p.Verify(verifier)))
			}})
	}
	for _, s := range []struct {
		alg jose.SignatureAlgorithm
		key string
	}{
		{jose.HS256, "oct32_hmac"}, {jose.RS256, "rsa2048"}, {jose.PS256, "rsa2048"},
		{jose.ES256, "p256"}, {jose.ES384, "p384"}, {jose.ES512, "p521"}, {jose.EdDSA, "ed25519"},
	} {
		addJWS(s.alg, s.key, []byte(smallPayload), "")
	}
	addJWS(jose.HS256, "oct32_hmac", large, "-64KiB")
	{
		signer := must(jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: keys.get("p256")}, nil))
		token := must(must(signer.Sign([]byte(smallPayload))).CompactSerialize())
		cases = append(cases, benchCase{"jws.parse/ES256", func() int {
			return len(must(jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{jose.ES256})).Signatures)
		}})
	}

	// JWE: Encrypt + CompactSerialize, then ParseEncryptedCompact + Decrypt.
	addJWE := func(alg jose.KeyAlgorithm, enc jose.ContentEncryption, key string, plaintext []byte, suffix string) {
		name := string(alg) + "/" + string(enc) + suffix
		encrypter := must(jose.NewEncrypter(enc, jose.Recipient{Algorithm: alg, Key: keys.pub(key)}, nil))
		decrypter := keys.get(key)
		algs, encs := []jose.KeyAlgorithm{alg}, []jose.ContentEncryption{enc}
		token := must(must(encrypter.Encrypt(plaintext)).CompactSerialize())
		check := must(must(jose.ParseEncryptedCompact(token, algs, encs)).Decrypt(decrypter))
		if !bytes.Equal(check, plaintext) {
			die("decrypt %s: plaintext differs", name)
		}
		cases = append(cases,
			benchCase{"jwe.encrypt/" + name, func() int {
				return len(must(must(encrypter.Encrypt(plaintext)).CompactSerialize()))
			}},
			benchCase{"jwe.decrypt/" + name, func() int {
				p := must(jose.ParseEncryptedCompact(token, algs, encs))
				return len(must(p.Decrypt(decrypter)))
			}})
	}
	for _, s := range []struct {
		alg jose.KeyAlgorithm
		enc jose.ContentEncryption
		key string
	}{
		{jose.DIRECT, jose.A256GCM, "oct32_dir_gcm"},
		{jose.DIRECT, jose.A128CBC_HS256, "oct32_dir_cbc"},
		{jose.A256KW, jose.A256GCM, "oct32_kw"},
		{jose.RSA_OAEP_256, jose.A256GCM, "rsa2048"},
		{jose.ECDH_ES, jose.A256GCM, "p256"},
		{jose.ECDH_ES_A256KW, jose.A256GCM, "p256"},
	} {
		addJWE(s.alg, s.enc, s.key, []byte(smallPayload), "")
	}
	addJWE(jose.DIRECT, jose.A256GCM, "oct32_dir_gcm", large, "-64KiB")
	{
		encrypter := must(jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.A256KW, Key: keys.get("oct32_kw")}, nil))
		token := must(must(encrypter.Encrypt([]byte(smallPayload))).CompactSerialize())
		cases = append(cases, benchCase{"jwe.parse/A256KW/A256GCM", func() int {
			p := must(jose.ParseEncryptedCompact(token, []jose.KeyAlgorithm{jose.A256KW}, []jose.ContentEncryption{jose.A256GCM}))
			return len(p.Header.KeyID) + 1
		}})
	}

	// JWT: build + Serialize; ParseSigned + Claims (registered and all) +
	// ValidateWithLeeway, as jose2cpp's claims() + decode + validate.
	var claims map[string]any
	must(0, json.Unmarshal([]byte(smallPayload), &claims))
	for _, s := range []struct {
		alg jose.SignatureAlgorithm
		key string
	}{{jose.HS256, "oct32_hmac"}, {jose.ES256, "p256"}} {
		name := string(s.alg)
		alg := s.alg
		signer := must(jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: keys.get(s.key)}, (&jose.SignerOptions{}).WithType("JWT")))
		verifier := keys.pub(s.key)
		token := must(jwt.Signed(signer).Claims(claims).Serialize())
		want := jwt.Expected{Issuer: "https://auth.example.com", Time: time.Unix(validateAt, 0)}
		verifyOnce := func() (int, error) {
			parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{alg})
			if err != nil {
				return 0, err
			}
			var reg jwt.Claims
			var all map[string]any
			if err := parsed.Claims(verifier, &reg, &all); err != nil {
				return 0, err
			}
			if err := reg.ValidateWithLeeway(want, jwt.DefaultLeeway); err != nil {
				return 0, err
			}
			return len(all), nil
		}
		must(verifyOnce())
		cases = append(cases,
			benchCase{"jwt.sign/" + name, func() int {
				return len(must(jwt.Signed(signer).Claims(claims).Serialize()))
			}},
			benchCase{"jwt.verify/" + name, func() int { return must(verifyOnce()) }})
	}

	// JWK: parse one key from text.
	addJWK := func(name, key string, private bool) {
		var text []byte
		if private {
			var compact bytes.Buffer // as jose_bench, which re-serializes it compactly
			must(0, json.Compact(&compact, keys[key]))
			text = compact.Bytes()
		} else {
			pub := keys.pub(key)
			text = must(pub.MarshalJSON())
		}
		parse := func() int {
			var k jose.JSONWebKey
			must(0, k.UnmarshalJSON(text))
			if k.IsPublic() {
				return 0
			}
			return 1
		}
		parse()
		cases = append(cases, benchCase{"jwk.parse/" + name, parse})
	}
	addJWK("RSA-2048-public", "rsa2048", false)
	addJWK("RSA-2048-private", "rsa2048", true)
	addJWK("EC-P256-public", "p256", false)
	addJWK("EC-P256-private", "p256", true)

	return cases
}

func main() {
	quick := flag.Bool("quick", false, "run each case once without timing (a smoke test)")
	list := flag.Bool("list", false, "print the case names and exit")
	filter := flag.String("filter", "", "only cases whose name contains TEXT")
	timeMs := flag.Int("time-ms", 200, "length of one timed sample")
	samples := flag.Int("samples", 5, "timed samples per case; the median is reported")
	keysPath := flag.String("keys", "../keys.json", "the shared keys")
	flag.Parse()
	if flag.NArg() != 0 || *timeMs < 1 || *samples < 1 {
		flag.Usage()
		os.Exit(1)
	}

	var keys keyring
	must(0, json.Unmarshal(must(os.ReadFile(*keysPath)), &keys))
	cases := makeCases(keys)
	if *list {
		for _, c := range cases {
			fmt.Println(c.name)
		}
		return
	}

	goJose := "unknown"
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, d := range info.Deps {
			if d.Path == "github.com/go-jose/go-jose/v4" {
				goJose = d.Version
			}
		}
	}
	n := *samples
	if *quick {
		n = 1
	}
	meta, _ := json.Marshal(map[string]any{"meta": map[string]any{
		"impl": "go-jose", "go": runtime.Version(), "go-jose": goJose,
		"gomaxprocs": runtime.GOMAXPROCS(0), "sample_ms": *timeMs, "samples": n,
	}})
	fmt.Println(string(meta))

	s := settings{sampleTime: time.Duration(*timeMs) * time.Millisecond, samples: *samples, filter: *filter, quick: *quick}
	for _, c := range cases {
		if s.filter == "" || strings.Contains(c.name, s.filter) {
			run(c, s)
		}
	}
}
