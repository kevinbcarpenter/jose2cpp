// Signs and verifies a JWT through the installed headers and library.
#include <jose/jose.hpp>
#include <jose/version.hpp>

#include <chrono>
#include <cstdio>

int main() {
    auto key = jose::jwk::generate_ec(jose::ec_curve::P256);
    if (!key) return 1;
    jose::jwt::registered_claims claims;
    claims.subject = "package-test";
    auto token = jose::jwt::signed_token({jose::signing_algorithm::ES256, *key}).claims(claims).serialize();
    if (!token) return 2;
    auto parsed = jose::jwt::parse_signed(*token, {jose::signing_algorithm::ES256});
    if (!parsed) return 3;
    auto got = parsed->claims(*key);
    if (!got) return 4;
    std::printf("jose2cpp %s: signed and verified a %zu-byte JWT\n", jose::version_string, token->size());
    return 0;
}
