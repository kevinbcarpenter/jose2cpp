#pragma once

// Shared by the fuzz targets: every algorithm, a key of every kind, and a
// check that aborts (so libFuzzer and the sanitizers report it) when an
// invariant breaks. A target must never crash, throw or leak; an error
// return from the library is the expected way to fail (PLAN.md §Fuzz
// Testing).

#include "jose/jose.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <string_view>
#include <vector>

namespace fuzz {

inline auto check(bool ok, const char* what) -> void {
    if (!ok) {
        std::fprintf(stderr, "fuzz invariant broken: %s\n", what);
        std::abort();
    }
}

inline auto text(const uint8_t* data, std::size_t size) -> std::string_view {
    return {reinterpret_cast<const char*>(data), size};
}

inline auto all_signing() -> const std::vector<jose::signing_algorithm>& {
    using enum jose::signing_algorithm;
    static const std::vector<jose::signing_algorithm> v{HS256, HS384, HS512, RS256, RS384, RS512, ES256,
                                                        ES384, ES512, PS256, PS384, PS512, EdDSA};
    return v;
}

inline auto all_key_management() -> const std::vector<jose::key_algorithm>& {
    using enum jose::key_algorithm;
    static const std::vector<jose::key_algorithm> v{RSA1_5,         RSA_OAEP,           RSA_OAEP_256,       A128KW,
                                                    A192KW,         A256KW,             dir,                ECDH_ES,
                                                    ECDH_ES_A128KW, ECDH_ES_A192KW,     ECDH_ES_A256KW,     A128GCMKW,
                                                    A192GCMKW,      A256GCMKW,          PBES2_HS256_A128KW, PBES2_HS384_A192KW,
                                                    PBES2_HS512_A256KW};
    return v;
}

// The ones an encrypted-only JWT may use (PLAN.md §JWT).
inline auto symmetric_key_management() -> const std::vector<jose::key_algorithm>& {
    using enum jose::key_algorithm;
    static const std::vector<jose::key_algorithm> v{A128KW, A192KW, A256KW, dir, A128GCMKW, A192GCMKW, A256GCMKW};
    return v;
}

inline auto all_content() -> const std::vector<jose::content_encryption>& {
    using enum jose::content_encryption;
    static const std::vector<jose::content_encryption> v{A128CBC_HS256, A192CBC_HS384, A256CBC_HS512,
                                                         A128GCM,       A192GCM,       A256GCM};
    return v;
}

// One key of every type and size the library handles (RSA 2048, P-256/384/
// 521, Ed25519, Ed448, X25519, X448, oct of 16, 24, 32, 48 and 64 octets,
// and a PBES2 password), with kids k0 to k13. They're fixed (fuzz_keys.inc)
// so a crash reproduces in another process. Tokens the fuzzer makes won't
// verify or decrypt with them, but every code path up to the cryptography
// runs.
inline auto keys() -> const std::vector<jose::jwk>& {
    static const std::vector<jose::jwk> v = [] {
        static constexpr const char* json[] = {
#include "fuzz_keys.inc"
        };
        std::vector<jose::jwk> out;
        for (const char* text : json) {
            auto k = jose::jwk::from_json(std::string_view(text));
            check(k.has_value(), "a fixed fuzz key doesn't parse");
            out.push_back(std::move(*k));
        }
        return out;
    }();
    return v;
}

// Decrypt options for fuzzing: every path enabled, PBES2 work kept small
// so a high "p2c" doesn't slow the fuzzer down.
inline auto decrypt_options() -> jose::jwe_decrypt_options {
    return {.legacy = {.allow_rsa1_5 = true}, .max_pbes2_iterations = 20000};
}

} // namespace fuzz
