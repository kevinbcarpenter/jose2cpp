#include "cli.hpp"

#include "jose/jose.hpp"
#include "jose/version.hpp"

#include <openssl/decoder.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <memory>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <share.h>
#include <sys/stat.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace jose::cli {

namespace {

// --- Failures ---------------------------------------------------------------

// A command fails with a message; `usage` picks the exit status.
struct failure {
    std::string message;
    bool usage = false;
};

template <typename T = void>
using outcome = nonstd::expected<T, failure>;

auto usage_error(std::string message) -> nonstd::unexpected_type<failure> {
    return nonstd::unexpected_type<failure>(failure{std::move(message), true});
}

auto failed(std::string message) -> nonstd::unexpected_type<failure> {
    return nonstd::unexpected_type<failure>(failure{std::move(message), false});
}

auto failed(const jose::error& e) -> nonstd::unexpected_type<failure> { return failed(e.message); }

// --- Command lines ----------------------------------------------------------

struct command_line {
    std::map<std::string, std::vector<std::string>, std::less<>> values;
    std::set<std::string, std::less<>> flags;
    bool help = false;

    // The value of a flag given at most once.
    [[nodiscard]] auto one(std::string_view name) const -> outcome<std::optional<std::string>> {
        const auto it = values.find(name);
        if (it == values.end()) return std::optional<std::string>{};
        if (it->second.size() > 1) return usage_error("--" + std::string(name) + " is given more than once");
        return std::optional<std::string>{it->second.front()};
    }
    // Every value of a repeatable flag, commas splitting further.
    [[nodiscard]] auto all(std::string_view name) const -> std::vector<std::string> {
        std::vector<std::string> out;
        const auto it = values.find(name);
        if (it == values.end()) return out;
        for (const auto& v : it->second) {
            std::string_view rest = v;
            while (!rest.empty()) {
                const auto comma = rest.find(',');
                const auto part = rest.substr(0, comma);
                if (!part.empty()) out.emplace_back(part);
                if (comma == std::string_view::npos) break;
                rest.remove_prefix(comma + 1);
            }
        }
        return out;
    }
    [[nodiscard]] auto has(std::string_view name) const -> bool { return flags.contains(name); }
};

struct flag_spec {
    std::set<std::string, std::less<>> valued;  // --name VALUE
    std::set<std::string, std::less<>> boolean; // --name
};

// Accepts -name and --name, with the value as the next argument or after
// '=', like Go's flag package (so jose-util command lines work).
auto parse_command_line(const std::vector<std::string>& args, std::size_t first, const flag_spec& spec)
    -> outcome<command_line> {
    command_line cl;
    for (std::size_t i = first; i < args.size(); ++i) {
        std::string_view arg = args[i];
        if (arg == "--") {
            // The end of the flags, as in Go. No command takes arguments.
            if (i + 1 < args.size()) return usage_error("unexpected argument '" + args[i + 1] + "'");
            break;
        }
        if (arg.size() < 2 || arg[0] != '-') return usage_error("unexpected argument '" + std::string(arg) + "'");
        arg.remove_prefix(arg[1] == '-' ? 2 : 1);
        if (arg == "h" || arg == "help") {
            cl.help = true;
            continue;
        }
        std::optional<std::string> value;
        if (const auto eq = arg.find('='); eq != std::string_view::npos) {
            value = std::string(arg.substr(eq + 1));
            arg = arg.substr(0, eq);
        }
        const std::string name(arg);
        if (spec.boolean.contains(name)) {
            // The spellings Go's strconv.ParseBool accepts.
            static const std::set<std::string_view> yes{"1", "t", "T", "TRUE", "true", "True"};
            static const std::set<std::string_view> no{"0", "f", "F", "FALSE", "false", "False"};
            if (value && !yes.contains(*value)) {
                if (!no.contains(*value)) return usage_error("--" + name + " takes true or false, not '" + *value + "'");
                cl.flags.erase(name);
                continue;
            }
            cl.flags.insert(name);
        } else if (spec.valued.contains(name)) {
            if (!value) {
                if (i + 1 == args.size()) return usage_error("--" + name + " needs a value");
                value = args[++i];
            }
            cl.values[name].push_back(std::move(*value));
        } else {
            return usage_error("unknown option --" + name);
        }
    }
    return cl;
}

// --- Input and output -------------------------------------------------------

// Overwrites a string's bytes before it goes away, for key material. Best
// effort: copies the JSON and PEM parsers make aren't reached.
struct wiped {
    std::string& s;
    explicit wiped(std::string& str) noexcept : s(str) {}
    wiped(const wiped&) = delete;
    wiped& operator=(const wiped&) = delete;
    ~wiped() { OPENSSL_cleanse(s.data(), s.size()); }
};

auto read_stream(std::istream& in) -> std::optional<std::string> {
    std::string out;
    std::array<char, 16384> buf{};
    while (in.read(buf.data(), buf.size()) || in.gcount() > 0) {
        out.append(buf.data(), static_cast<std::size_t>(in.gcount()));
        if (!in) break;
    }
    if (in.bad()) return std::nullopt;
    return out;
}

// With stdio rather than a stream: a filebuf reports a read error (a
// directory, a failing device) as the end of the file.
auto read_file(const std::string& path, std::string_view what) -> outcome<std::string> {
    std::error_code ec;
    if (std::filesystem::is_directory(path, ec)) return failed(std::string(what) + " " + path + " is a directory");
    const std::unique_ptr<std::FILE, decltype(&std::fclose)> f(std::fopen(path.c_str(), "rb"), &std::fclose);
    if (!f) return failed("can't open " + std::string(what) + " " + path);
    std::string data;
    if (const auto size = std::filesystem::file_size(path, ec); !ec) data.reserve(size); // no regrowth: no stale copies
    std::array<char, 16384> buf{};
    while (const auto n = std::fread(buf.data(), 1, buf.size(), f.get())) data.append(buf.data(), n);
    if (std::ferror(f.get())) {
        OPENSSL_cleanse(data.data(), data.size());
        return failed("can't read " + std::string(what) + " " + path);
    }
    return data;
}

auto read_input(const command_line& cl, streams& io) -> outcome<std::string> {
    auto in = cl.one("in");
    if (!in) return nonstd::unexpected_type<failure>(in.error());
    if (*in) return read_file(**in, "input file");
    auto data = read_stream(io.in);
    if (!data) return failed("can't read standard input");
    return std::move(*data);
}

// `secret` output (decrypted plaintext) goes to a file created 0600; an
// existing file keeps its permissions.
auto write_output(const command_line& cl, streams& io, std::string_view data, bool secret = false) -> outcome<> {
    auto out = cl.one("out");
    if (!out) return nonstd::unexpected_type<failure>(out.error());
    if (*out) {
        const std::string& name = **out;
#ifdef _WIN32
        (void)secret;
        std::ofstream f(name, std::ios::binary | std::ios::trunc);
        if (!f) return failed("can't open output file " + name);
        f.write(data.data(), static_cast<std::streamsize>(data.size()));
        f.close();
        if (!f) return failed("can't write output file " + name);
#else
        const int fd = ::open(name.c_str(), O_WRONLY | O_CREAT | O_TRUNC, secret ? 0600 : 0666);
        if (fd < 0) return failed("can't open output file " + name);
        std::size_t done = 0;
        while (done < data.size()) {
            const auto n = ::write(fd, data.data() + done, data.size() - done);
            if (n <= 0) break;
            done += static_cast<std::size_t>(n);
        }
        const bool closed = ::close(fd) == 0;
        if (done != data.size() || !closed) return failed("can't write output file " + name);
#endif
        return {};
    }
    io.out.write(data.data(), static_cast<std::streamsize>(data.size()));
    io.out.flush();
    if (!io.out) return failed("can't write standard output");
    return {};
}

auto as_view(std::span<const uint8_t> bytes) -> std::string_view {
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

// Creates `path` for writing, failing if it exists (a dangling symlink
// counts). On POSIX it's readable only by the owner (0400) or by everyone
// (0444) from the moment it exists, so a private key is never briefly
// readable by others. On Windows it's created read-only and otherwise gets
// the directory's ACL.
auto write_new_file(const std::filesystem::path& path, std::string_view data, bool private_file) -> outcome<> {
    const std::string name = path.string();
#ifdef _WIN32
    int fd = -1;
    if (_wsopen_s(&fd, path.c_str(), _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY, _SH_DENYRW, _S_IREAD) != 0)
        return failed("can't create " + name + " (does it exist already?)");
    const auto written = _write(fd, data.data(), static_cast<unsigned>(data.size()));
    const bool closed = _close(fd) == 0;
#else
    (void)private_file;
    const int fd = ::open(name.c_str(), O_WRONLY | O_CREAT | O_EXCL, private_file ? 0400 : 0444);
    if (fd < 0) return failed("can't create " + name + " (does it exist already?)");
    const auto written = ::write(fd, data.data(), data.size());
    const bool closed = ::close(fd) == 0;
#endif
    if (written < 0 || static_cast<std::size_t>(written) != data.size() || !closed)
        return failed("can't write " + name);
    return {};
}

// --- Algorithms -------------------------------------------------------------

constexpr std::array all_signing{
    signing_algorithm::HS256, signing_algorithm::HS384, signing_algorithm::HS512, signing_algorithm::RS256,
    signing_algorithm::RS384, signing_algorithm::RS512, signing_algorithm::ES256, signing_algorithm::ES384,
    signing_algorithm::ES512, signing_algorithm::PS256, signing_algorithm::PS384, signing_algorithm::PS512,
    signing_algorithm::EdDSA,
};

constexpr std::array all_key_management{
    key_algorithm::RSA1_5,         key_algorithm::RSA_OAEP,           key_algorithm::RSA_OAEP_256,
    key_algorithm::A128KW,         key_algorithm::A192KW,             key_algorithm::A256KW,
    key_algorithm::dir,            key_algorithm::ECDH_ES,            key_algorithm::ECDH_ES_A128KW,
    key_algorithm::ECDH_ES_A192KW, key_algorithm::ECDH_ES_A256KW,     key_algorithm::A128GCMKW,
    key_algorithm::A192GCMKW,      key_algorithm::A256GCMKW,          key_algorithm::PBES2_HS256_A128KW,
    key_algorithm::PBES2_HS384_A192KW, key_algorithm::PBES2_HS512_A256KW,
};

constexpr std::array all_content{
    content_encryption::A128CBC_HS256, content_encryption::A192CBC_HS384, content_encryption::A256CBC_HS512,
    content_encryption::A128GCM,       content_encryption::A192GCM,       content_encryption::A256GCM,
};

template <typename Alg>
auto parse_list(const std::vector<std::string>& names, auto parse, std::string_view flag) -> outcome<std::vector<Alg>> {
    std::vector<Alg> out;
    for (const auto& name : names) {
        auto alg = parse(name);
        if (!alg) return usage_error("--" + std::string(flag) + ": " + alg.error().message);
        out.push_back(*alg);
    }
    return out;
}

// --- Keys -------------------------------------------------------------------

// A key file: one key, or (where a command allows it) a JWK Set.
struct key_file {
    std::optional<jwk> key;
    std::optional<jwk_set> set;

    [[nodiscard]] auto keys() const -> std::vector<std::reference_wrapper<const jwk>> {
        std::vector<std::reference_wrapper<const jwk>> out;
        if (key) out.emplace_back(*key);
        if (set)
            for (const auto& k : set->keys()) out.emplace_back(k);
        return out;
    }
};

// DER: a private or public key in any encoding OpenSSL knows (PKCS#8,
// PKCS#1, SEC 1, SubjectPublicKeyInfo), or an X.509 certificate. Each
// supported key type is tried by name, because an untyped decode can read a
// PKCS#1 RSA public key (two INTEGERs) as DH parameters. Trailing bytes
// are refused.
auto key_from_der(std::string_view der) -> outcome<jwk> {
    // Failed attempts leave errors on OpenSSL's per-thread queue; drop them
    // so they can't be mistaken for a later operation's.
    struct error_mark {
        error_mark() { ERR_set_mark(); }
        ~error_mark() { ERR_pop_to_mark(); }
        error_mark(const error_mark&) = delete;
        error_mark& operator=(const error_mark&) = delete;
    } mark;
    const auto* bytes = reinterpret_cast<const unsigned char*>(der.data());
    for (const char* type : {"RSA", "EC", "ED25519", "ED448", "X25519", "X448"}) {
        EVP_PKEY* raw = nullptr;
        OSSL_DECODER_CTX* ctx = OSSL_DECODER_CTX_new_for_pkey(&raw, "DER", nullptr, type, 0, nullptr, nullptr);
        if (!ctx) continue;
        const unsigned char* p = bytes;
        std::size_t len = der.size();
        const bool ok = OSSL_DECODER_from_data(ctx, &p, &len) == 1 && raw != nullptr;
        OSSL_DECODER_CTX_free(ctx);
        if (ok && len == 0) {
            auto key = jwk::from_pkey(evp_pkey_ptr(raw, EVP_PKEY_free));
            if (!key) return failed(key.error());
            return std::move(*key);
        }
        EVP_PKEY_free(raw);
        if (ok) return failed("trailing bytes after the DER key");
    }
    const unsigned char* p = bytes;
    if (X509* cert = d2i_X509(nullptr, &p, static_cast<long>(der.size()))) {
        const bool whole = p == bytes + der.size();
        EVP_PKEY* pub = whole ? X509_get_pubkey(cert) : nullptr;
        X509_free(cert);
        if (!whole) return failed("trailing bytes after the DER certificate");
        if (pub) {
            auto key = jwk::from_pkey(evp_pkey_ptr(pub, EVP_PKEY_free));
            if (!key) return failed(key.error());
            return std::move(*key);
        }
    }
    return failed("not a key in PEM, DER or JWK format");
}

auto load_key(const command_line& cl, bool allow_set) -> outcome<key_file> {
    auto path = cl.one("key");
    if (!path) return nonstd::unexpected_type<failure>(path.error());
    if (!*path) return usage_error("--key is required");
    auto data = read_file(**path, "key file");
    if (!data) return nonstd::unexpected_type<failure>(data.error());
    const wiped wipe_data{*data};
    const auto start = data->find_first_not_of(" \t\r\n");
    const std::string_view text = start == std::string::npos ? std::string_view{} : std::string_view(*data).substr(start);

    const auto where = [&](const std::string& message) { return failed("key file " + **path + ": " + message); };
    key_file out;
    if (text.starts_with("{")) {
        auto j = nlohmann::json::parse(text, nullptr, false);
        if (!j.is_discarded() && j.is_object() && j.contains("keys")) {
            if (!allow_set) return where("a JWK Set can't be used here; give a single key");
            auto set = jwk_set::from_json(text);
            if (!set) return where(set.error().message);
            if (set->empty()) return where("the JWK Set has no usable key");
            out.set = std::move(*set);
            return out;
        }
        auto key = jwk::from_json(text);
        if (!key) return where(key.error().message);
        out.key = std::move(*key);
        return out;
    }
    if (text.find("-----BEGIN") != std::string_view::npos) {
        auto key = jwk::from_pem(text);
        if (!key) return where(key.error().message);
        out.key = std::move(*key);
        return out;
    }
    auto key = key_from_der(*data);
    if (!key) return where(key.error().message);
    out.key = std::move(*key);
    return out;
}

auto need_single(const key_file& kf) -> const jwk& { return *kf.key; }

// --- Commands ---------------------------------------------------------------

struct command {
    std::string_view name;
    std::string_view summary;
    std::string_view help;
    flag_spec flags;
    std::function<outcome<>(const command_line&, streams&)> run;
};

auto serialize_jws(const jws& token, bool full) -> outcome<std::string> {
    auto s = full ? token.to_json_string(token.signatures().size() == 1 ? jws_json_format::flattened
                                                                        : jws_json_format::general)
                  : token.compact();
    if (!s) return failed(s.error());
    return std::move(*s);
}

auto serialize_jwe(const jwe& token, bool full) -> outcome<std::string> {
    auto s = full ? token.to_json_string(token.recipients().size() == 1 ? jwe_json_format::flattened
                                                                        : jwe_json_format::general)
                  : token.compact();
    if (!s) return failed(s.error());
    return std::move(*s);
}

auto do_sign(const command_line& cl, streams& io) -> outcome<> {
    auto kf = load_key(cl, false);
    if (!kf) return nonstd::unexpected_type<failure>(kf.error());
    const jwk& key = need_single(*kf);
    auto alg_name = cl.one("alg");
    if (!alg_name) return nonstd::unexpected_type<failure>(alg_name.error());
    if (!*alg_name && !key.algorithm()) return usage_error("--alg is required (the key has no \"alg\")");
    auto alg = parse_signing_algorithm(*alg_name ? **alg_name : *key.algorithm());
    if (!alg) return usage_error("--alg: " + alg.error().message);

    auto payload = read_input(cl, io);
    if (!payload) return nonstd::unexpected_type<failure>(payload.error());
    auto token = jws::sign(*payload, {*alg, key});
    if (!token) return failed(token.error());
    auto text = serialize_jws(*token, cl.has("full"));
    if (!text) return nonstd::unexpected_type<failure>(text.error());
    return write_output(cl, io, *text + "\n");
}

auto do_verify(const command_line& cl, streams& io) -> outcome<> {
    auto kf = load_key(cl, true);
    if (!kf) return nonstd::unexpected_type<failure>(kf.error());

    auto algs = parse_list<signing_algorithm>(cl.all("alg"), parse_signing_algorithm, "alg");
    if (!algs) return nonstd::unexpected_type<failure>(algs.error());
    if (algs->empty()) {
        // Without --alg the key decides: verify() refuses a signature whose
        // "alg" the key can't be used with (jwk::check_algorithm), so every
        // algorithm can be let through parsing. That also lets a JSON JWS
        // whose other signatures use other algorithms through.
        const bool any = std::ranges::any_of(all_signing, [&](signing_algorithm alg) {
            return std::ranges::any_of(kf->keys(), [&](const jwk& k) { return !!k.check_algorithm(to_string(alg)); });
        });
        if (!any) return failed("the key can't be used with any JWS algorithm");
        algs->assign(all_signing.begin(), all_signing.end());
    }

    auto input = read_input(cl, io);
    if (!input) return nonstd::unexpected_type<failure>(input.error());
    auto parsed = jws::parse(*input, *algs);
    if (!parsed) return failed(parsed.error());
    // Each key in turn (one, or every key of a JWK Set), against every
    // signature; the first that verifies wins.
    std::optional<jose::error> last;
    for (const jwk& key : kf->keys()) {
        auto v = parsed->verify_multi(key);
        if (v) return write_output(cl, io, as_view(v->payload));
        last = v.error();
    }
    return failed(*last);
}

auto do_encrypt(const command_line& cl, streams& io) -> outcome<> {
    auto enc_name = cl.one("enc");
    if (!enc_name) return nonstd::unexpected_type<failure>(enc_name.error());
    if (!*enc_name) return usage_error("--enc is required");
    auto enc = parse_content_encryption(**enc_name);
    if (!enc) return usage_error("--enc: " + enc.error().message);
    auto kf = load_key(cl, false);
    if (!kf) return nonstd::unexpected_type<failure>(kf.error());
    const jwk& key = need_single(*kf);
    auto alg_name = cl.one("alg");
    if (!alg_name) return nonstd::unexpected_type<failure>(alg_name.error());
    if (!*alg_name && !key.algorithm()) return usage_error("--alg is required (the key has no \"alg\")");
    auto alg = parse_key_algorithm(*alg_name ? **alg_name : *key.algorithm());
    if (!alg) return usage_error("--alg: " + alg.error().message);

    auto plaintext = read_input(cl, io);
    if (!plaintext) return nonstd::unexpected_type<failure>(plaintext.error());
    jwe_encrypt_options options;
    options.compress = cl.has("zip");
    options.legacy.allow_rsa1_5 = cl.has("allow-legacy");
    auto token = jwe::encrypt(*plaintext, *enc, {*alg, key}, options);
    if (!token) return failed(token.error());
    auto text = serialize_jwe(*token, cl.has("full"));
    if (!text) return nonstd::unexpected_type<failure>(text.error());
    return write_output(cl, io, *text + "\n");
}

auto do_decrypt(const command_line& cl, streams& io) -> outcome<> {
    auto kf = load_key(cl, true);
    if (!kf) return nonstd::unexpected_type<failure>(kf.error());

    auto algs = parse_list<key_algorithm>(cl.all("alg"), parse_key_algorithm, "alg");
    if (!algs) return nonstd::unexpected_type<failure>(algs.error());
    if (algs->empty()) {
        // As in verify: decrypt() refuses a recipient whose "alg" the key
        // can't be used with, so the key decides.
        const bool any = std::ranges::any_of(all_key_management, [&](key_algorithm alg) {
            return std::ranges::any_of(kf->keys(), [&](const jwk& k) { return !!k.check_algorithm(to_string(alg)); });
        });
        if (!any) return failed("the key can't be used with any JWE key management algorithm");
        algs->assign(all_key_management.begin(), all_key_management.end());
    }
    auto encs = parse_list<content_encryption>(cl.all("enc"), parse_content_encryption, "enc");
    if (!encs) return nonstd::unexpected_type<failure>(encs.error());
    if (encs->empty()) encs->assign(all_content.begin(), all_content.end());

    auto input = read_input(cl, io);
    if (!input) return nonstd::unexpected_type<failure>(input.error());
    auto parsed = jwe::parse(*input, *algs, *encs);
    if (!parsed) return failed(parsed.error());
    jwe_decrypt_options options;
    options.legacy.allow_rsa1_5 = cl.has("allow-legacy");
    // As in verify: each key against every recipient.
    std::optional<jose::error> last;
    for (const jwk& key : kf->keys()) {
        auto d = parsed->decrypt_multi(key, options);
        if (d) return write_output(cl, io, as_view(d->plaintext), true);
        last = d.error();
    }
    return failed(*last);
}

auto do_expand(const command_line& cl, streams& io) -> outcome<> {
    auto format = cl.one("format");
    if (!format) return nonstd::unexpected_type<failure>(format.error());
    auto input = read_input(cl, io);
    if (!input) return nonstd::unexpected_type<failure>(input.error());

    std::string kind = format->value_or("");
    const auto start = input->find_first_not_of(" \t\r\n");
    const bool is_json = start != std::string::npos && (*input)[start] == '{';
    if (kind.empty()) {
        if (is_json) {
            // JSON already (jose-util accepts it too): a JWE has "ciphertext".
            const auto j = nlohmann::json::parse(*input, nullptr, false);
            kind = j.is_object() && j.contains("ciphertext") ? "JWE" : "JWS";
        } else {
            const auto dots = std::count(input->begin(), input->end(), '.');
            if (dots == 2)
                kind = "JWS";
            else if (dots == 4)
                kind = "JWE";
            else
                return failed("not a compact JWS (3 parts) or JWE (5 parts); give --format to say which");
        }
    }
    std::string text;
    if (kind == "JWS") {
        auto parsed = jws::parse(*input, {all_signing.begin(), all_signing.end()});
        if (!parsed) return failed(parsed.error());
        auto s = serialize_jws(*parsed, true);
        if (!s) return nonstd::unexpected_type<failure>(s.error());
        text = std::move(*s);
    } else if (kind == "JWE") {
        auto parsed = jwe::parse(*input, {all_key_management.begin(), all_key_management.end()},
                                         {all_content.begin(), all_content.end()});
        if (!parsed) return failed(parsed.error());
        auto s = serialize_jwe(*parsed, true);
        if (!s) return nonstd::unexpected_type<failure>(s.error());
        text = std::move(*s);
    } else {
        return usage_error("--format must be JWS or JWE");
    }
    return write_output(cl, io, text + "\n");
}

auto parse_size(const command_line& cl) -> outcome<int> {
    auto s = cl.one("size");
    if (!s) return nonstd::unexpected_type<failure>(s.error());
    if (!*s) return 0;
    int bits = 0;
    const auto& v = **s;
    const auto [end, ec] = std::from_chars(v.data(), v.data() + v.size(), bits);
    if (ec != std::errc{} || end != v.data() + v.size() || bits <= 0) return usage_error("--size must be a positive number of bits");
    return bits;
}

auto ec_for_size(int bits) -> outcome<ec_curve> {
    switch (bits) {
    case 0:
    case 256: return ec_curve::P256;
    case 384: return ec_curve::P384;
    case 521: return ec_curve::P521;
    default: return usage_error("--size for an EC key must be 256, 384 or 521");
    }
}

auto oct_bytes(int bits, std::size_t default_bytes, bool exact) -> outcome<std::size_t> {
    if (bits == 0) return default_bytes;
    if (bits % 8 != 0) return usage_error("--size for a symmetric key must be a whole number of bytes");
    const auto bytes = static_cast<std::size_t>(bits) / 8;
    if (exact && bytes != default_bytes)
        return usage_error("--size for this algorithm must be " + std::to_string(default_bytes * 8));
    return bytes;
}

// The key generate-key makes for an algorithm.
auto generate_for(std::string_view use, std::string_view alg, int bits, const std::optional<std::string>& crv,
                  const std::optional<std::string>& enc) -> outcome<jwk> {
    const auto done = [](expected<jwk> k) -> outcome<jwk> {
        if (!k) return failed(k.error());
        return std::move(*k);
    };
    const auto crv_only_for = [&](bool allowed) -> outcome<> {
        if (crv && !allowed) return usage_error("--crv doesn't apply to " + std::string(alg));
        return {};
    };
    if (enc && alg != "dir") return usage_error("--enc only applies to dir");

    if (use == "sig") {
        auto a = parse_signing_algorithm(alg);
        if (!a) return usage_error("--alg: " + a.error().message);
        if (auto c = crv_only_for(*a == signing_algorithm::EdDSA); !c) return nonstd::unexpected_type<failure>(c.error());
        switch (*a) {
        case signing_algorithm::ES256:
        case signing_algorithm::ES384:
        case signing_algorithm::ES512: {
            const auto curve = *a == signing_algorithm::ES256   ? ec_curve::P256
                               : *a == signing_algorithm::ES384 ? ec_curve::P384
                                                                : ec_curve::P521;
            const int size = curve == ec_curve::P256 ? 256 : curve == ec_curve::P384 ? 384 : 521;
            if (bits != 0 && bits != size) return usage_error("--size for " + std::string(alg) + " must be " + std::to_string(size));
            return done(jwk::generate_ec(curve));
        }
        case signing_algorithm::EdDSA: {
            if (crv && bits) return usage_error("give --crv or --size, not both");
            if (crv ? *crv == "Ed448" : bits == 448) return done(jwk::generate_okp(okp_curve::Ed448));
            if (crv ? *crv == "Ed25519" : (bits == 0 || bits == 256)) return done(jwk::generate_okp(okp_curve::Ed25519));
            return usage_error("EdDSA keys are Ed25519 (--size 256) or Ed448 (--size 448)");
        }
        case signing_algorithm::HS256:
        case signing_algorithm::HS384:
        case signing_algorithm::HS512: {
            const std::size_t hash = *a == signing_algorithm::HS256 ? 32 : *a == signing_algorithm::HS384 ? 48 : 64;
            auto bytes = oct_bytes(bits, hash, false);
            if (!bytes) return nonstd::unexpected_type<failure>(bytes.error());
            return done(jwk::generate_oct(*bytes));
        }
        default: return done(jwk::generate_rsa(bits == 0 ? 2048 : bits));
        }
    }
    if (use == "enc") {
        auto a = parse_key_algorithm(alg);
        if (!a) return usage_error("--alg: " + a.error().message);
        const bool ecdh = *a == key_algorithm::ECDH_ES || *a == key_algorithm::ECDH_ES_A128KW ||
                          *a == key_algorithm::ECDH_ES_A192KW || *a == key_algorithm::ECDH_ES_A256KW;
        if (auto c = crv_only_for(ecdh); !c) return nonstd::unexpected_type<failure>(c.error());
        switch (*a) {
        case key_algorithm::RSA1_5:
        case key_algorithm::RSA_OAEP:
        case key_algorithm::RSA_OAEP_256: return done(jwk::generate_rsa(bits == 0 ? 2048 : bits));
        case key_algorithm::ECDH_ES:
        case key_algorithm::ECDH_ES_A128KW:
        case key_algorithm::ECDH_ES_A192KW:
        case key_algorithm::ECDH_ES_A256KW: {
            if (crv && bits) return usage_error("give --crv or --size, not both");
            if (crv) {
                if (*crv == "X25519") return done(jwk::generate_okp(okp_curve::X25519));
                if (*crv == "X448") return done(jwk::generate_okp(okp_curve::X448));
                auto c = parse_ec_curve(*crv);
                if (!c) return usage_error("--crv must be P-256, P-384, P-521, X25519 or X448");
                return done(jwk::generate_ec(*c));
            }
            auto c = ec_for_size(bits);
            if (!c) return nonstd::unexpected_type<failure>(c.error());
            return done(jwk::generate_ec(*c));
        }
        case key_algorithm::A128KW:
        case key_algorithm::A128GCMKW:
        case key_algorithm::A192KW:
        case key_algorithm::A192GCMKW:
        case key_algorithm::A256KW:
        case key_algorithm::A256GCMKW: {
            const std::size_t size = (*a == key_algorithm::A128KW || *a == key_algorithm::A128GCMKW)   ? 16
                                     : (*a == key_algorithm::A192KW || *a == key_algorithm::A192GCMKW) ? 24
                                                                                                         : 32;
            auto bytes = oct_bytes(bits, size, true);
            if (!bytes) return nonstd::unexpected_type<failure>(bytes.error());
            return done(jwk::generate_oct(*bytes));
        }
        case key_algorithm::dir: {
            if (!enc && bits == 0) return usage_error("dir needs --enc (or --size) to know how large a key to make");
            std::size_t want = 0;
            if (enc) {
                auto e = parse_content_encryption(*enc);
                if (!e) return usage_error("--enc: " + e.error().message);
                want = cek_byte_size(*e);
            }
            auto bytes = oct_bytes(bits, want, enc.has_value());
            if (!bytes) return nonstd::unexpected_type<failure>(bytes.error());
            return done(jwk::generate_oct(*bytes));
        }
        default: return usage_error("PBES2 keys are passwords; there's nothing to generate");
        }
    }
    return usage_error("--use must be sig or enc");
}

// Characters a kid may keep in a file name; others become '_'.
auto file_safe(std::string_view kid) -> std::string {
    std::string out;
    for (const char c : kid) {
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ||
                        c == '_' || c == '.';
        out += ok ? c : '_';
    }
    if (out.empty() || out.front() == '.') out.insert(out.begin(), '_');
    return out;
}

auto do_generate(const command_line& cl, streams& io) -> outcome<> {
    auto use = cl.one("use");
    auto alg = cl.one("alg");
    auto kid = cl.one("kid");
    auto dir = cl.one("dir");
    auto crv = cl.one("crv");
    auto enc = cl.one("enc");
    for (const auto* o : {&use, &alg, &kid, &dir, &crv, &enc})
        if (!*o) return nonstd::unexpected_type<failure>(o->error());
    if (!*use) return usage_error("--use is required (sig or enc)");
    if (!*alg) return usage_error("--alg is required");
    auto bits = parse_size(cl);
    if (!bits) return nonstd::unexpected_type<failure>(bits.error());

    auto key = generate_for(**use, **alg, *bits, *crv, *enc);
    if (!key) return nonstd::unexpected_type<failure>(key.error());
    if (auto r = key->set_algorithm(**alg); !r) return failed(r.error());
    if (auto r = key->set_use(**use); !r) return failed(r.error());
    if (*kid && !(*kid)->empty()) {
        key->set_key_id(**kid);
    } else { // as jose-util, an empty --kid means the thumbprint
        auto thumb = key->thumbprint();
        if (!thumb) return failed(thumb.error());
        key->set_key_id(base64url::encode(*thumb));
    }

    const std::filesystem::path base = dir->value_or(".");
    const std::string stem = "jwk-" + **use + "-" + file_safe(*key->key_id());
    struct output {
        std::filesystem::path path;
        std::string data;
        bool private_file;
    };
    std::vector<output> files;
    files.reserve(2); // wipe_priv refers into it: no reallocation
    auto priv = key->to_json_string();
    if (!priv) return failed(priv.error());
    files.push_back({base / (stem + "-priv.json"), std::move(*priv), true});
    const wiped wipe_priv{files.front().data};
    if (key->key_type() != kty::oct) {
        auto pub = key->public_key();
        if (!pub) return failed(pub.error());
        auto pub_json = pub->to_json_string();
        if (!pub_json) return failed(pub_json.error());
        files.push_back({base / (stem + "-pub.json"), std::move(*pub_json), false});
    }
    // Refuse before writing anything, so a clash doesn't leave half a pair.
    // symlink_status: a dangling symlink is in the way too.
    for (const auto& f : files) {
        std::error_code ec;
        if (std::filesystem::exists(std::filesystem::symlink_status(f.path, ec)))
            return failed(f.path.string() + " exists already");
    }
    // Private key first; if a later file fails, remove what was written.
    for (std::size_t i = 0; i < files.size(); ++i) {
        if (auto w = write_new_file(files[i].path, files[i].data, files[i].private_file); !w) {
            for (std::size_t j = 0; j < i; ++j) {
                std::error_code ec;
                std::filesystem::remove(files[j].path, ec);
            }
            return w;
        }
    }
    for (const auto& f : files) io.out << f.path.string() << "\n";
    return {};
}

const std::array<command, 6>& commands() {
    static const std::array<command, 6> table{{
        {"sign", "Sign a payload, output a JWS",
         "Usage: jose-cli sign --key FILE [--alg ALG] [--full] [--in FILE] [--out FILE]\n"
         "\n"
         "Signs the input and writes a compact JWS (or, with --full, the JSON\n"
         "serialization) followed by a newline. --alg defaults to the key's \"alg\".\n",
         {{"key", "alg", "in", "out"}, {"full"}}, do_sign},
        {"verify", "Verify a JWS, output its payload",
         "Usage: jose-cli verify --key FILE [--alg ALG]... [--in FILE] [--out FILE]\n"
         "\n"
         "Verifies a compact or JSON JWS and writes its payload as is. The key file\n"
         "may be a JWK Set, whose keys are each tried. Without --alg, the key\n"
         "decides: a signature verifies only with an algorithm the key can be used\n"
         "with. --alg (repeatable, or comma separated) limits it to those listed;\n"
         "every signature in the token must then use one of them. Exits with 1 if\n"
         "the signature doesn't verify.\n",
         {{"key", "alg", "in", "out"}, {}}, do_verify},
        {"encrypt", "Encrypt a plaintext, output a JWE",
         "Usage: jose-cli encrypt --key FILE [--alg ALG] --enc ENC [--zip] [--full]\n"
         "                        [--allow-legacy] [--in FILE] [--out FILE]\n"
         "\n"
         "Encrypts the input and writes a compact JWE (or, with --full, the JSON\n"
         "serialization) followed by a newline. --alg is the key management\n"
         "algorithm and defaults to the key's \"alg\"; --enc is the content\n"
         "encryption. --zip compresses first. RSA1_5 needs --allow-legacy.\n",
         {{"key", "alg", "enc", "in", "out"}, {"full", "zip", "allow-legacy"}}, do_encrypt},
        {"decrypt", "Decrypt a JWE, output its plaintext",
         "Usage: jose-cli decrypt --key FILE [--alg ALG]... [--enc ENC]... [--allow-legacy]\n"
         "                        [--in FILE] [--out FILE]\n"
         "\n"
         "Decrypts a compact or JSON JWE and writes the plaintext as is. The key\n"
         "file may be a JWK Set, whose keys are each tried. Without --alg, the key\n"
         "decides which key management algorithms work; without --enc, every content\n"
         "encryption is accepted. Both flags limit it to those listed. RSA1_5 needs\n"
         "--allow-legacy. On POSIX, a new --out file is created readable only by you.\n",
         {{"key", "alg", "enc", "in", "out"}, {"allow-legacy"}}, do_decrypt},
        {"expand", "Convert a compact JWS or JWE to the JSON serialization",
         "Usage: jose-cli expand [--format JWS|JWE] [--in FILE] [--out FILE]\n"
         "\n"
         "Rewrites a compact token as JSON without checking its signature or\n"
         "decrypting it. The format is worked out from the number of parts unless\n"
         "--format says.\n",
         {{"format", "in", "out"}, {}}, do_expand},
        {"generate-key", "Generate a key in JWK format",
         "Usage: jose-cli generate-key --use sig|enc --alg ALG [--size BITS] [--crv CRV]\n"
         "                             [--enc ENC] [--kid KID] [--dir DIR]\n"
         "\n"
         "Generates a key for ALG and writes jwk-USE-KID-priv.json (on POSIX,\n"
         "readable only by you) and, for asymmetric keys, jwk-USE-KID-pub.json, in\n"
         "DIR (default the current directory). It won't overwrite either. KID\n"
         "defaults to the key's RFC 7638 thumbprint; characters other than letters,\n"
         "digits, '.', '-' and '_' become '_' in the file names. --size picks the RSA size (default 2048), the\n"
         "EC curve (256, 384, 521) or the symmetric key size; --crv picks the curve\n"
         "for EdDSA (Ed25519, Ed448) and ECDH-ES (P-256, P-384, P-521, X25519,\n"
         "X448); dir needs --enc or --size. Prints the files written.\n",
         {{"use", "alg", "size", "kid", "dir", "crv", "enc"}, {}}, do_generate},
    }};
    return table;
}

auto usage(std::ostream& os) -> void {
    os << "Usage: jose-cli COMMAND [OPTIONS]\n\nCommands:\n";
    for (const auto& c : commands()) {
        os << "  " << c.name << std::string(14 - c.name.size(), ' ') << c.summary << "\n";
    }
    os << "\nRun 'jose-cli COMMAND --help' for a command's options. Input is read from\n"
          "--in or standard input, output goes to --out or standard output.\n";
}

} // namespace

auto run(const std::vector<std::string>& args, streams io) -> int {
    if (args.empty()) {
        usage(io.err);
        return exit_usage;
    }
    const std::string_view name = args[0];
    if (name == "help" || name == "-h" || name == "--help" || name == "-help") {
        usage(io.out);
        return exit_ok;
    }
    if (name == "version" || name == "--version") {
        io.out << "jose-cli " << JOSE_VERSION << "\n";
        return exit_ok;
    }
    const auto& table = commands();
    const auto it = std::find_if(table.begin(), table.end(), [&](const command& c) { return c.name == name; });
    if (it == table.end()) {
        io.err << "jose-cli: unknown command '" << name << "'\n\n";
        usage(io.err);
        return exit_usage;
    }
    auto cl = parse_command_line(args, 1, it->flags);
    if (cl && cl->help) {
        io.out << it->help;
        return exit_ok;
    }
    auto result = [&]() -> outcome<> {
        if (!cl) return nonstd::unexpected_type<failure>(cl.error());
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        try {
            return it->run(*cl, io);
        } catch (const std::exception& e) { // a path that can't be converted, out of memory, ...
            return failed(e.what());
        }
#else
        return it->run(*cl, io);
#endif
    }();
    if (result) return exit_ok;
    io.err << "jose-cli " << name << ": " << result.error().message << "\n";
    if (result.error().usage) {
        io.err << "Run 'jose-cli " << name << " --help' for usage.\n";
        return exit_usage;
    }
    return exit_failed;
}

} // namespace jose::cli
