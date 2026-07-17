#include <catch2/catch_test_macros.hpp>

#include "jose/base64url.hpp"

#include <cstdint>
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
