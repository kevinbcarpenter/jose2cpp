// jose2cpp benchmarks (PLAN.md Phase 3 item 11, §Benchmarks).
//
// The same cases, keys, payloads and timing loop as benchmarks/go/main.go,
// so benchmarks/compare.py can put the two side by side. Each case is one
// public API call as an application makes it: sign and serialize, or parse
// and verify. Prints one JSON object per line (see --help).

#include <jose/jose.hpp>

#include <nlohmann/json.hpp>
#include <openssl/crypto.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

using clock_type = std::chrono::steady_clock;

struct bench_case {
    std::string name;
    std::function<std::size_t()> op; // returns a size so the work can't be optimized out
};

[[noreturn]] void die(const std::string& what) {
    std::cerr << "jose_bench: " << what << '\n';
    std::exit(1);
}

template <typename T>
auto must(jose::expected<T> r, const std::string& what) -> T {
    if (!r) die(what + ": " + r.error().message);
    if constexpr (!std::is_void_v<T>) return std::move(*r);
}

// --- Inputs shared with benchmarks/go/main.go -------------------------------

// A typical set of JWT claims, used as the JWS payload and JWE plaintext.
constexpr std::string_view small_payload =
    R"({"iss":"https://auth.example.com","sub":"user-1234567890","aud":"api.example.com",)"
    R"("exp":4102444800,"iat":1700000000,"jti":"4f1c2a9e-7b3d-4e8a-9c61-0d5f2b8e3a17",)"
    R"("scope":"read:messages write:messages","name":"Example User"})";

// 64 KiB of bytes i % 251, for the bulk cases.
auto large_payload() -> std::vector<uint8_t> {
    std::vector<uint8_t> v(64 * 1024);
    for (std::size_t i = 0; i < v.size(); ++i) v[i] = static_cast<uint8_t>(i % 251);
    return v;
}

auto bytes(std::string_view s) -> std::span<const uint8_t> {
    return {reinterpret_cast<const uint8_t*>(s.data()), s.size()};
}

// The JWT cases validate against this instant (between "iat" and "exp").
constexpr std::int64_t validate_at = 1800000000;

// --- Timing ------------------------------------------------------------------

struct settings {
    std::chrono::milliseconds sample_time{200};
    int samples = 5;
    std::string filter;
    bool quick = false;
    bool list = false;
    std::string keys_path = JOSE_BENCH_KEYS;
};

volatile std::size_t sink = 0;

// Warm up for a quarter of a sample, size a batch to take sample_time, then
// time `samples` batches. Reports the median and fastest batch per op.
void run(const bench_case& c, const settings& s) {
    std::size_t iterations = 1;
    std::vector<double> per_op;
    if (s.quick) {
        sink = sink + c.op();
        per_op.push_back(0);
    } else {
        auto warm_until = clock_type::now() + s.sample_time / 4;
        std::size_t warm = 0;
        auto start = clock_type::now();
        do {
            sink = sink + c.op();
            ++warm;
        } while (clock_type::now() < warm_until);
        double ns = std::chrono::duration<double, std::nano>(clock_type::now() - start).count() / double(warm);
        double target = std::chrono::duration<double, std::nano>(s.sample_time).count();
        iterations = std::max<std::size_t>(1, static_cast<std::size_t>(target / ns));
        for (int k = 0; k < s.samples; ++k) {
            auto t0 = clock_type::now();
            for (std::size_t i = 0; i < iterations; ++i) sink = sink + c.op();
            auto t1 = clock_type::now();
            per_op.push_back(std::chrono::duration<double, std::nano>(t1 - t0).count() / double(iterations));
        }
    }
    std::sort(per_op.begin(), per_op.end());
    nlohmann::json out = {
        {"impl", "jose2cpp"},
        {"case", c.name},
        {"ns_per_op", per_op[per_op.size() / 2]},
        {"min_ns_per_op", per_op.front()},
        {"iterations", iterations},
        {"samples", per_op.size()},
    };
    std::cout << out.dump() << std::endl;
}

// --- Cases -------------------------------------------------------------------

struct keyring {
    nlohmann::json json;
    auto get(const std::string& name) const -> jose::jwk {
        if (!json.contains(name)) die("keys file has no \"" + name + "\"");
        return must(jose::jwk::from_json(json.at(name)), "key " + name);
    }
    auto pub(const std::string& name) const -> jose::jwk {
        auto k = get(name);
        if (k.key_type() == jose::kty::oct) return k;
        return must(k.public_key(), "public key " + name);
    }
};

auto make_cases(const keyring& keys) -> std::vector<bench_case> {
    using namespace jose;
    std::vector<bench_case> cases;
    static const auto large = large_payload();

    // JWS: sign + compact, then parse_compact + verify.
    struct jws_spec {
        signing_algorithm alg;
        const char* key;
    };
    const jws_spec jws_specs[] = {
        {signing_algorithm::HS256, "oct32_hmac"}, {signing_algorithm::RS256, "rsa2048"},
        {signing_algorithm::PS256, "rsa2048"},    {signing_algorithm::ES256, "p256"},
        {signing_algorithm::ES384, "p384"},       {signing_algorithm::ES512, "p521"},
        {signing_algorithm::EdDSA, "ed25519"},
    };
    auto add_jws = [&](signing_algorithm alg, const char* key, std::span<const uint8_t> payload,
                       const std::string& suffix) {
        std::string name = std::string(to_string(alg)) + suffix;
        jws_signer signer{alg, keys.get(key)};
        auto verifier = keys.pub(key);
        auto token = must(must(jws::sign(payload, signer), "sign " + name).compact(), "compact " + name);
        auto check = must(must(jws::parse_compact(token, {alg}), "parse " + name).verify(verifier), "verify " + name);
        if (!std::ranges::equal(check, payload)) die("verify " + name + ": payload differs");

        cases.push_back({"jws.sign/" + name, [=] {
                             auto s = jws::sign(payload, signer);
                             if (!s) die("jws.sign failed");
                             auto c = s->compact();
                             if (!c) die("jws.compact failed");
                             return c->size();
                         }});
        cases.push_back({"jws.verify/" + name, [=] {
                             auto p = jws::parse_compact(token, {alg});
                             if (!p) die("jws.parse failed");
                             auto v = p->verify(verifier);
                             if (!v) die("jws.verify failed");
                             return v->size();
                         }});
    };
    for (const auto& s : jws_specs) add_jws(s.alg, s.key, bytes(small_payload), "");
    add_jws(signing_algorithm::HS256, "oct32_hmac", large, "-64KiB");
    {
        jws_signer signer{signing_algorithm::ES256, keys.get("p256")};
        auto token = must(must(jws::sign(bytes(small_payload), signer), "sign").compact(), "compact");
        cases.push_back({"jws.parse/ES256", [=] {
                             auto p = jws::parse_compact(token, {signing_algorithm::ES256});
                             if (!p) die("jws.parse failed");
                             return p->signatures().size();
                         }});
    }

    // JWE: encrypt + compact, then parse_compact + decrypt.
    struct jwe_spec {
        key_algorithm alg;
        content_encryption enc;
        const char* key;
    };
    const jwe_spec jwe_specs[] = {
        {key_algorithm::dir, content_encryption::A256GCM, "oct32_dir_gcm"},
        {key_algorithm::dir, content_encryption::A128CBC_HS256, "oct32_dir_cbc"},
        {key_algorithm::A256KW, content_encryption::A256GCM, "oct32_kw"},
        {key_algorithm::RSA_OAEP_256, content_encryption::A256GCM, "rsa2048"},
        {key_algorithm::ECDH_ES, content_encryption::A256GCM, "p256"},
        {key_algorithm::ECDH_ES_A256KW, content_encryption::A256GCM, "p256"},
    };
    auto add_jwe = [&](key_algorithm alg, content_encryption enc, const char* key,
                       std::span<const uint8_t> plaintext, const std::string& suffix) {
        std::string name = std::string(to_string(alg)) + "/" + std::string(to_string(enc)) + suffix;
        jwe_recipient recipient{alg, keys.pub(key)};
        auto decrypter = keys.get(key);
        auto token = must(must(jwe::encrypt(plaintext, enc, recipient), "encrypt " + name).compact(),
                          "compact " + name);
        auto check =
            must(must(jwe::parse_compact(token, {alg}, {enc}), "parse " + name).decrypt(decrypter), "decrypt " + name);
        if (!std::ranges::equal(check, plaintext)) die("decrypt " + name + ": plaintext differs");

        cases.push_back({"jwe.encrypt/" + name, [=] {
                             auto e = jwe::encrypt(plaintext, enc, recipient);
                             if (!e) die("jwe.encrypt failed");
                             auto c = e->compact();
                             if (!c) die("jwe.compact failed");
                             return c->size();
                         }});
        cases.push_back({"jwe.decrypt/" + name, [=] {
                             auto p = jwe::parse_compact(token, {alg}, {enc});
                             if (!p) die("jwe.parse failed");
                             auto d = p->decrypt(decrypter);
                             if (!d) die("jwe.decrypt failed");
                             return d->size();
                         }});
    };
    for (const auto& s : jwe_specs) add_jwe(s.alg, s.enc, s.key, bytes(small_payload), "");
    add_jwe(key_algorithm::dir, content_encryption::A256GCM, "oct32_dir_gcm", large, "-64KiB");
    {
        jwe_recipient recipient{key_algorithm::A256KW, keys.get("oct32_kw")};
        auto token = must(must(jwe::encrypt(bytes(small_payload), content_encryption::A256GCM, recipient), "encrypt")
                              .compact(),
                          "compact");
        cases.push_back({"jwe.parse/A256KW/A256GCM", [=] {
                             auto p = jwe::parse_compact(token, {key_algorithm::A256KW}, {content_encryption::A256GCM});
                             if (!p) die("jwe.parse failed");
                             return p->recipients().size();
                         }});
    }

    // JWT: build + serialize; parse + verify + registered claims + validate.
    const auto claims = nlohmann::json::parse(small_payload);
    for (const auto& [alg, key] : {std::pair{signing_algorithm::HS256, "oct32_hmac"},
                                   std::pair{signing_algorithm::ES256, "p256"}}) {
        std::string name(to_string(alg));
        jws_signer signer{alg, keys.get(key)};
        auto verifier = keys.pub(key);
        auto token = must(jwt::signed_token(signer).claims(claims).serialize(), "jwt " + name);
        const jwt::expected_claims want{.issuer = "https://auth.example.com",
                                        .time = std::chrono::system_clock::time_point(std::chrono::seconds(validate_at))};
        auto verify_once = [=]() -> jose::expected<std::size_t> {
            auto parsed = jwt::parse_signed(token, {alg});
            if (!parsed) return jose::unexpected(parsed.error());
            auto c = parsed->claims(verifier);
            if (!c) return jose::unexpected(c.error());
            auto reg = jwt::decode<jwt::registered_claims>(*c);
            if (!reg) return jose::unexpected(reg.error());
            if (auto ok = reg->validate(want); !ok) return jose::unexpected(ok.error());
            return c->size();
        };
        must(verify_once(), "jwt verify " + name);

        cases.push_back({"jwt.sign/" + name, [=] {
                             auto t = jwt::signed_token(signer).claims(claims).serialize();
                             if (!t) die("jwt.sign failed");
                             return t->size();
                         }});
        cases.push_back({"jwt.verify/" + name, [=] {
                             auto r = verify_once();
                             if (!r) die("jwt.verify failed");
                             return *r;
                         }});
    }

    // JWK: parse and validate one key from text.
    auto add_jwk = [&](const std::string& name, const char* key, bool private_key) {
        std::string text = private_key ? keys.json.at(key).dump() : must(keys.pub(key).to_json_string(), "jwk " + name);
        must(jwk::from_json(std::string_view(text)), "jwk parse " + name);
        cases.push_back({"jwk.parse/" + name, [=] {
                             auto k = jwk::from_json(std::string_view(text));
                             if (!k) die("jwk.parse failed");
                             return static_cast<std::size_t>(k->is_private());
                         }});
    };
    add_jwk("RSA-2048-public", "rsa2048", false);
    add_jwk("RSA-2048-private", "rsa2048", true);
    add_jwk("EC-P256-public", "p256", false);
    add_jwk("EC-P256-private", "p256", true);

    return cases;
}

void usage() {
    std::cout << "usage: jose_bench [--quick] [--list] [--filter TEXT] [--time-ms N] [--samples N] [--keys FILE]\n"
                 "\n"
                 "  --quick       run each case once without timing (a smoke test)\n"
                 "  --list        print the case names and exit\n"
                 "  --filter TEXT only cases whose name contains TEXT\n"
                 "  --time-ms N   length of one timed sample (default 200)\n"
                 "  --samples N   timed samples per case; the median is reported (default 5)\n"
                 "  --keys FILE   the shared keys (default: benchmarks/keys.json in the source tree)\n"
                 "\n"
                 "Output: one JSON object per line, first {\"meta\":...}, then per case\n"
                 "{\"impl\",\"case\",\"ns_per_op\",\"min_ns_per_op\",\"iterations\",\"samples\"}.\n";
}

} // namespace

int main(int argc, char** argv) {
    settings s;
    for (int i = 1; i < argc; ++i) {
        std::string_view a = argv[i];
        auto value = [&]() -> std::string {
            if (i + 1 >= argc) die(std::string(a) + " needs a value");
            return argv[++i];
        };
        auto number = [&]() -> int {
            auto v = value();
            char* end = nullptr;
            long n = std::strtol(v.c_str(), &end, 10);
            if (*end != '\0' || n < 1 || n > 1000000) die(std::string(a) + ": bad number " + v);
            return static_cast<int>(n);
        };
        if (a == "--quick") s.quick = true;
        else if (a == "--list") s.list = true;
        else if (a == "--filter") s.filter = value();
        else if (a == "--time-ms") s.sample_time = std::chrono::milliseconds(number());
        else if (a == "--samples") s.samples = number();
        else if (a == "--keys") s.keys_path = value();
        else if (a == "--help" || a == "-h") { usage(); return 0; }
        else die("unknown argument " + std::string(a) + " (see --help)");
    }

    std::ifstream in(s.keys_path);
    if (!in) die("can't read " + s.keys_path);
    std::stringstream text;
    text << in.rdbuf();
    keyring keys{nlohmann::json::parse(text.str(), nullptr, false)};
    if (!keys.json.is_object()) die(s.keys_path + " is not a JSON object");

    auto cases = make_cases(keys);
    if (s.list) {
        for (const auto& c : cases) std::cout << c.name << '\n';
        return 0;
    }

#if defined(__OPTIMIZE__) || (defined(_MSC_VER) && defined(NDEBUG))
    constexpr bool optimized = true;
#else
    constexpr bool optimized = false;
    if (!s.quick) std::cerr << "jose_bench: warning: built without optimization; configure with a Release build\n";
#endif
    nlohmann::json meta = {
        {"impl", "jose2cpp"},
        {"openssl", OpenSSL_version(OPENSSL_VERSION)},
#if defined(__clang__)
        {"compiler", "clang " __clang_version__},
#elif defined(__GNUC__)
        {"compiler", "gcc " __VERSION__},
#elif defined(_MSC_VER)
        {"compiler", "msvc " + std::to_string(_MSC_VER)},
#endif
        {"optimized", optimized},
        {"sample_ms", s.sample_time.count()},
        {"samples", s.quick ? 1 : s.samples},
    };
    std::cout << nlohmann::json{{"meta", meta}}.dump() << std::endl;

    for (const auto& c : cases)
        if (s.filter.empty() || c.name.find(s.filter) != std::string::npos) run(c, s);
    return 0;
}
