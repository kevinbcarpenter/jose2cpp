// jws::parse (compact or JSON) with every algorithm allowed, then
// re-serialization and verification with keys of every kind. A JWS that
// parses re-serializes to something that parses to the same payload and
// signatures, and serializing that again gives exactly the same text.

#include "fuzz_common.hpp"

namespace {

auto same(const jose::jws& a, const jose::jws& b) -> bool {
    if (a.signatures().size() != b.signatures().size()) return false;
    const auto pa = a.unsafe_payload();
    const auto pb = b.unsafe_payload();
    if (!std::equal(pa.begin(), pa.end(), pb.begin(), pb.end())) return false;
    for (std::size_t i = 0; i < a.signatures().size(); ++i) {
        const auto& sa = a.signatures()[i];
        const auto& sb = b.signatures()[i];
        if (sa.alg != sb.alg || sa.signature != sb.signature || sa.encoded_protected != sb.encoded_protected)
            return false;
    }
    return true;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
    const auto input = fuzz::text(data, size);
    const auto& algs = fuzz::all_signing();

    if (auto parsed = jose::jws::parse(input, algs)) {
        if (auto json = parsed->to_json_string()) {
            auto again = jose::jws::parse(*json, algs);
            fuzz::check(again.has_value(), "re-serialized JSON JWS doesn't parse");
            fuzz::check(same(*parsed, *again), "JSON round trip changed the JWS");
            auto twice = again->to_json_string();
            fuzz::check(twice.has_value() && *twice == *json, "JSON serialization isn't stable");
        }
        if (auto compact = parsed->compact()) {
            auto again = jose::jws::parse(*compact, algs);
            fuzz::check(again.has_value(), "re-serialized compact JWS doesn't parse");
            fuzz::check(same(*parsed, *again), "compact round trip changed the JWS");
            auto twice = again->compact();
            fuzz::check(twice.has_value() && *twice == *compact, "compact serialization isn't stable");
        }
        for (const auto& key : fuzz::keys()) (void)parsed->verify_multi(key);
        (void)parsed->verify(jose::jwk_set(fuzz::keys()));
    }

    const std::string_view detached = "detached payload";
    (void)jose::jws::parse_detached(input, std::span(reinterpret_cast<const uint8_t*>(detached.data()), detached.size()),
                                    algs);
    return 0;
}
