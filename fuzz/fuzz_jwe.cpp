// jwe::parse (compact or JSON) with every algorithm allowed, then
// re-serialization and decryption with keys of every kind. A JWE that
// parses re-serializes to something that parses to the same "enc" and
// recipients, and serializing that again gives exactly the same text,
// which covers the headers, "aad", "iv", ciphertext and "tag".

#include "fuzz_common.hpp"

namespace {

auto same(const jose::jwe& a, const jose::jwe& b) -> bool {
    if (a.enc() != b.enc() || a.recipients().size() != b.recipients().size()) return false;
    for (std::size_t i = 0; i < a.recipients().size(); ++i) {
        const auto& ra = a.recipients()[i];
        const auto& rb = b.recipients()[i];
        if (ra.alg != rb.alg || ra.encrypted_key != rb.encrypted_key) return false;
    }
    return true;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
    const auto input = fuzz::text(data, size);
    const auto& algs = fuzz::all_key_management();
    const auto& encs = fuzz::all_content();

    if (auto parsed = jose::jwe::parse(input, algs, encs)) {
        if (auto json = parsed->to_json_string()) {
            auto again = jose::jwe::parse(*json, algs, encs);
            fuzz::check(again.has_value(), "re-serialized JSON JWE doesn't parse");
            fuzz::check(same(*parsed, *again), "JSON round trip changed the JWE");
            auto twice = again->to_json_string();
            fuzz::check(twice.has_value() && *twice == *json, "JSON serialization isn't stable");
        }
        if (auto compact = parsed->compact()) {
            auto again = jose::jwe::parse(*compact, algs, encs);
            fuzz::check(again.has_value(), "re-serialized compact JWE doesn't parse");
            fuzz::check(same(*parsed, *again), "compact round trip changed the JWE");
            auto twice = again->compact();
            fuzz::check(twice.has_value() && *twice == *compact, "compact serialization isn't stable");
        }
        const auto options = fuzz::decrypt_options();
        for (const auto& key : fuzz::keys()) (void)parsed->decrypt_multi(key, options);
        (void)parsed->decrypt(jose::jwk_set(fuzz::keys()), options);
    }
    return 0;
}
