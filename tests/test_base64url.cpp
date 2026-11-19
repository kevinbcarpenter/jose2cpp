#include <catch2/catch_test_macros.hpp>

#include "jose/base64url.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

using namespace jose;

namespace {

auto make_bytes(std::initializer_list<uint8_t> il) -> std::vector<uint8_t> {
    return {il};
}

auto bytes_from_string(std::string_view s) -> std::vector<uint8_t> {
    return {s.begin(), s.end()};
}

} // namespace

TEST_CASE("base64url round-trip", "[base64url]") {
    SECTION("short ASCII string") {
        std::string_view input = "Hello, World!";
        auto encoded = base64url::encode(input);
        auto decoded = base64url::decode(encoded);
        REQUIRE(decoded.has_value());
        REQUIRE(std::string(decoded->begin(), decoded->end()) == input);
    }

    SECTION("binary data") {
        std::vector<uint8_t> input = {0x00, 0xFF, 0x80, 0x7F, 0x01, 0xFE};
        auto encoded = base64url::encode(std::span<const uint8_t>(input));
        auto decoded = base64url::decode(encoded);
        REQUIRE(decoded.has_value());
        REQUIRE(std::vector<uint8_t>(decoded->begin(), decoded->end()) == input);
    }
}

TEST_CASE("base64url empty input", "[base64url]") {
    SECTION("encode empty") {
        auto result = base64url::encode(std::string_view{});
        CHECK(result.empty());
    }

    SECTION("decode empty") {
        auto result = base64url::decode("");
        REQUIRE(result.has_value());
        CHECK(result->empty());
    }
}

TEST_CASE("base64url various lengths (padding cases)", "[base64url]") {
    // len % 3 == 0: no padding needed
    // len % 3 == 1: 2 base64url chars (would be == padding in std base64)
    // len % 3 == 2: 3 base64url chars (would be = padding in std base64)

    SECTION("1 byte") {
        auto enc = base64url::encode(std::string_view("f"));
        CHECK(enc == "Zg");
        auto dec = base64url::decode(enc);
        REQUIRE(dec.has_value());
        CHECK(std::string(dec->begin(), dec->end()) == "f");
    }

    SECTION("2 bytes") {
        auto enc = base64url::encode(std::string_view("fo"));
        CHECK(enc == "Zm8");
        auto dec = base64url::decode(enc);
        REQUIRE(dec.has_value());
        CHECK(std::string(dec->begin(), dec->end()) == "fo");
    }

    SECTION("3 bytes") {
        auto enc = base64url::encode(std::string_view("foo"));
        CHECK(enc == "Zm9v");
        auto dec = base64url::decode(enc);
        REQUIRE(dec.has_value());
        CHECK(std::string(dec->begin(), dec->end()) == "foo");
    }

    SECTION("4 bytes") {
        auto enc = base64url::encode(std::string_view("foob"));
        CHECK(enc == "Zm9vYg");
        auto dec = base64url::decode(enc);
        REQUIRE(dec.has_value());
        CHECK(std::string(dec->begin(), dec->end()) == "foob");
    }

    SECTION("5 bytes") {
        auto enc = base64url::encode(std::string_view("fooba"));
        CHECK(enc == "Zm9vYmE");
        auto dec = base64url::decode(enc);
        REQUIRE(dec.has_value());
        CHECK(std::string(dec->begin(), dec->end()) == "fooba");
    }
}

TEST_CASE("base64url RFC 7515 Appendix A vectors", "[base64url]") {
    // RFC 7515 A.1 — the JWS header
    // {"typ":"JWT",\r\n "alg":"HS256"}  (with the specific whitespace)
    SECTION("JWS header") {
        std::string_view expected_b64 = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9";
        auto decoded = base64url::decode(expected_b64);
        REQUIRE(decoded.has_value());
        std::string text(decoded->begin(), decoded->end());
        CHECK(text == "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}");
        // Re-encode should match
        CHECK(base64url::encode(text) == expected_b64);
    }

    // RFC 7515 A.1 — the JWS payload
    SECTION("JWS payload") {
        std::string_view expected_b64 = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
        auto decoded = base64url::decode(expected_b64);
        REQUIRE(decoded.has_value());
        std::string text(decoded->begin(), decoded->end());
        CHECK(text == "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}");
    }
}

TEST_CASE("base64url padding rejected (RFC 7515 strict)", "[base64url]") {
    // RFC 7515 §2 defines base64url as unpadded; '=' must be rejected.
    // Lenient decoding would make signed tokens malleable.
    SECTION("single = padding") {
        auto result = base64url::decode("Zm9vYmE=");
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code == errc::invalid_base64);
    }

    SECTION("double == padding") {
        auto result = base64url::decode("Zg==");
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code == errc::invalid_base64);
    }

    SECTION("unpadded form works") {
        auto dec = base64url::decode("Zg");
        REQUIRE(dec.has_value());
        CHECK(std::string(dec->begin(), dec->end()) == "f");
    }
}

TEST_CASE("base64url invalid characters return error", "[base64url]") {
    SECTION("space") {
        auto result = base64url::decode("Zm9 vYg");
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code == errc::invalid_base64);
    }

    SECTION("special character") {
        auto result = base64url::decode("Zm9v!g");
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code == errc::invalid_base64);
    }

    SECTION("newline") {
        auto result = base64url::decode("Zm9v\nYg");
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code == errc::invalid_base64);
    }
}

TEST_CASE("base64url standard base64 chars rejected (RFC 7515 strict)", "[base64url]") {
    // Only the base64url alphabet ('-', '_') is valid. The standard base64
    // chars '+' and '/' must be rejected — accepting them would let multiple
    // token strings decode to the same bytes (signature malleability).
    SECTION("+ rejected, - accepted") {
        auto dec_url = base64url::decode("-w");
        auto dec_std = base64url::decode("+w");
        REQUIRE(dec_url.has_value());
        REQUIRE_FALSE(dec_std.has_value());
        CHECK(dec_std.error().code == errc::invalid_base64);
    }

    SECTION("/ rejected, _ accepted") {
        auto dec_url = base64url::decode("_w");
        auto dec_std = base64url::decode("/w");
        REQUIRE(dec_url.has_value());
        REQUIRE_FALSE(dec_std.has_value());
        CHECK(dec_std.error().code == errc::invalid_base64);
    }
}

TEST_CASE("base64url invalid length rejected", "[base64url]") {
    // No unpadded base64url encoding produces length ≡ 1 (mod 4).
    SECTION("length 1") {
        auto result = base64url::decode("A");
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code == errc::invalid_base64);
    }

    SECTION("length 5") {
        auto result = base64url::decode("Zm9vY");
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code == errc::invalid_base64);
    }
}

TEST_CASE("base64url non-zero trailing bits return error", "[base64url]") {
    // "Zg" decodes 'f' (0x66). The 4 trailing bits are 0000 — valid.
    // "Zh" would have the last 6 bits = 100001, output byte = 0x66,
    // trailing 4 bits = 0001 — non-zero, should error.
    auto result = base64url::decode("Zh");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == errc::invalid_base64);
}

namespace {

// A plain bit-accumulator codec (the decoder is the one base64url.cpp used
// before it went four characters at a time); the fast paths must agree with
// it exactly.
constexpr std::string_view reference_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

auto reference_encode(const std::vector<uint8_t>& in) -> std::string {
    std::string out;
    uint32_t accum = 0;
    int bits = 0;
    for (uint8_t b : in) {
        accum = (accum << 8) | b;
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            out += reference_alphabet[(accum >> bits) & 0x3F];
        }
    }
    if (bits > 0) out += reference_alphabet[(accum << (6 - bits)) & 0x3F];
    return out;
}

// std::nullopt where decode must fail.
auto reference_decode(std::string_view in) -> std::optional<std::vector<uint8_t>> {
    if (in.size() % 4 == 1) return std::nullopt;
    std::vector<uint8_t> out;
    uint32_t accum = 0;
    int bits = 0;
    for (char c : in) {
        auto pos = reference_alphabet.find(c);
        if (pos == std::string_view::npos) return std::nullopt;
        accum = (accum << 6) | static_cast<uint32_t>(pos);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>(accum >> bits));
        }
    }
    if (bits > 0 && (accum & ((1u << bits) - 1)) != 0) return std::nullopt;
    return out;
}

} // namespace

TEST_CASE("base64url matches a bit-at-a-time reference", "[base64url]") {
    SECTION("encode and decode, every length to 200") {
        uint32_t state = 12345;
        for (size_t len = 0; len <= 200; ++len) {
            std::vector<uint8_t> in(len);
            for (auto& b : in) b = static_cast<uint8_t>((state = state * 1103515245 + 12345) >> 16);
            auto encoded = base64url::encode(std::span<const uint8_t>(in));
            REQUIRE(encoded == reference_encode(in));
            auto decoded = base64url::decode(encoded);
            REQUIRE(decoded.has_value());
            CHECK(std::vector<uint8_t>(decoded->begin(), decoded->end()) == in);
        }
    }

    SECTION("an invalid character anywhere is reported by name") {
        for (size_t len : {2u, 3u, 4u, 6u, 7u, 8u, 10u, 11u, 12u}) {
            for (size_t at = 0; at < len; ++at) {
                std::string text(len, 'A');
                text[at] = '!';
                auto result = base64url::decode(text);
                REQUIRE_FALSE(result.has_value());
                CHECK(result.error().code == errc::invalid_base64);
                CHECK(result.error().message == "invalid base64url character: '!'");
            }
        }
        // The first bad character wins, wherever the group boundary falls.
        auto result = base64url::decode("AAA=AA+A");
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().message == "invalid base64url character: '='");
    }

    SECTION("whitespace is reported first, whatever else is wrong") {
        for (std::string_view text : {"Zm9 vYg", "Zm9v Y", "!A A", "AAAA AA!", "Zh ", "\tQUJD"}) {
            auto result = base64url::decode(text);
            REQUIRE_FALSE(result.has_value());
            CHECK(result.error().code == errc::invalid_base64);
            CHECK(result.error().message.starts_with("whitespace inside base64url"));
        }
    }

    SECTION("every final character of a 2- and 3-character tail") {
        for (std::string prefix : {"", "QUJD"}) {
            for (std::string tail_start : {"Q", "QU"}) {
                for (char last : reference_alphabet) {
                    auto text = prefix + tail_start + last;
                    auto want = reference_decode(text);
                    auto got = base64url::decode(text);
                    REQUIRE(got.has_value() == want.has_value());
                    if (want) CHECK(std::vector<uint8_t>(got->begin(), got->end()) == *want);
                    else CHECK(got.error().message == "non-zero trailing bits in base64url");
                }
            }
        }
    }
}
