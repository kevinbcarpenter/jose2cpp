// jwk::from_json, jwk_set::from_json and jwk::from_pem on arbitrary input.
// A key that parses serializes, parses again to the same key (same type,
// same privacy, same thumbprint), and its public half has that thumbprint.

#include "fuzz_common.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
    const auto input = fuzz::text(data, size);

    if (auto key = jose::jwk::from_json(input)) {
        auto j = key->to_json();
        fuzz::check(j.has_value(), "a parsed JWK doesn't serialize");
        auto again = jose::jwk::from_json(*j);
        fuzz::check(again.has_value(), "a serialized JWK doesn't parse");
        fuzz::check(again->key_type() == key->key_type(), "round trip changed kty");
        fuzz::check(again->is_private() == key->is_private(), "round trip changed privacy");
        auto t1 = key->thumbprint();
        auto t2 = again->thumbprint();
        fuzz::check(t1.has_value() == t2.has_value(), "round trip changed whether a thumbprint exists");
        if (t1) fuzz::check(*t1 == *t2, "round trip changed the thumbprint");
        if (key->key_type() != jose::kty::oct) {
            auto pub = key->public_key();
            fuzz::check(pub.has_value() && pub->is_public(), "no public half");
            if (t1) {
                auto tp = pub->thumbprint();
                fuzz::check(tp.has_value() && *tp == *t1, "public half has another thumbprint");
            }
        }
        for (const auto alg : fuzz::all_signing()) (void)key->check_algorithm(jose::to_string(alg));
        for (const auto alg : fuzz::all_key_management()) (void)key->check_algorithm(jose::to_string(alg));
        for (const char* op : {"sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey"})
            (void)key->check_operation(op);
    }

    if (auto set = jose::jwk_set::from_json(input)) {
        (void)set->to_json();
        (void)set->find("k0");
    }

    // PEM only when it looks like PEM: OpenSSL's decoder setup costs about a
    // millisecond per call, which would slow the whole target down.
    if (input.find("-----BEGIN") != std::string_view::npos) (void)jose::jwk::from_pem(input);
    return 0;
}
