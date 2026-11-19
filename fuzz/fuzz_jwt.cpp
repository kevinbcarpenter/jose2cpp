// The JWT parsers (signed, encrypted, nested) on arbitrary input, and the
// registered claims (decode, validate, re-encode) on the token's unverified
// claims and on the input read as JSON.

#include "fuzz_common.hpp"

#include <chrono>

namespace {

auto exercise_claims(const nlohmann::json& j) -> void {
    auto claims = jose::jwt::decode<jose::jwt::registered_claims>(j);
    if (!claims) return;
    for (const auto leeway : {std::chrono::seconds(0), std::chrono::seconds(60), std::chrono::seconds(-60),
                              std::chrono::seconds((std::int64_t{1} << 62) - 1), std::chrono::seconds::max()}) {
        for (const auto t : {std::int64_t{0}, std::int64_t{1700000000}, std::int64_t{-1}}) {
            (void)claims->validate({.issuer = "iss", .subject = "sub", .any_audience = {"aud"}, .id = "jti",
                                    .time = std::chrono::system_clock::time_point(std::chrono::seconds(t))},
                                   leeway);
        }
    }
    // Registered claims that decode write back out as JSON that decodes to
    // the same claims.
    const nlohmann::json out = *claims;
    auto back = jose::jwt::decode<jose::jwt::registered_claims>(out);
    fuzz::check(back.has_value(), "re-encoded claims don't decode");
    fuzz::check(*back == *claims, "claims round trip changed them");
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
    const auto input = fuzz::text(data, size);
    const auto options = fuzz::decrypt_options();

    if (auto token = jose::jwt::parse_signed(input, fuzz::all_signing())) {
        if (auto claims = token->unsafe_claims()) exercise_claims(*claims);
        for (const auto& key : fuzz::keys()) (void)token->claims(key);
        (void)token->claims(jose::jwk_set(fuzz::keys()));
    }

    if (auto token = jose::jwt::parse_encrypted(input, fuzz::symmetric_key_management(), fuzz::all_content())) {
        for (const auto& key : fuzz::keys()) (void)token->claims(key, options);
    }

    if (auto token = jose::jwt::parse_signed_and_encrypted(input, fuzz::all_key_management(), fuzz::all_content(),
                                                           fuzz::all_signing())) {
        for (const auto& key : fuzz::keys()) {
            if (auto inner = token->decrypt(key, options)) (void)inner->claims(key);
        }
    }

    const auto j = nlohmann::json::parse(input, nullptr, false);
    if (!j.is_discarded()) exercise_claims(j);
    return 0;
}
