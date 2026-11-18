#pragma once

// Internal helpers shared by jwk.cpp and header.cpp. Not installed.

#include "jose/error.hpp"

#include <nlohmann/json.hpp>
#include <openssl/evp.h>

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace jose::internal {

// Parse JSON text, rejecting duplicate member names in any object (RFC 7515
// §4, RFC 7516 §4, RFC 7517 §4 allow either rejecting duplicates or keeping
// the last one; rejecting removes any ambiguity between parsers). `what`
// names the document in error messages ("JWK", "JOSE header", ...).
auto parse_json_strict(std::string_view text, std::string_view what) -> expected<nlohmann::json>;

// Strips leading and trailing JSON whitespace (space, tab, CR, LF) from a
// compact JWS or JWE, so a token read from a file, an environment variable
// or a hand-copied header still parses, as the JSON serializations already
// do. Whitespace inside the token is still refused: allowing it would give
// one token many spellings (go-jose strips it everywhere).
inline auto trim_compact(std::string_view s) -> std::string_view {
    constexpr std::string_view ws = " \t\r\n";
    const auto first = s.find_first_not_of(ws);
    if (first == std::string_view::npos) return {};
    return s.substr(first, s.find_last_not_of(ws) - first + 1);
}

// Standard (padded) base64, used by "x5c" (RFC 7515 §4.1.6, RFC 7517 §4.7).
auto b64std_decode(std::string_view s) -> expected<std::vector<uint8_t>>;
auto b64std_encode(std::span<const uint8_t> in) -> std::string;

// RFC 3629 UTF-8 (no overlongs, surrogates, or code points > U+10FFFF).
auto is_valid_utf8(std::string_view s) -> bool;

auto digest(const EVP_MD* md, std::span<const uint8_t> in) -> expected<std::vector<uint8_t>>;

} // namespace jose::internal
