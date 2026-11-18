#include "jose/base64url.hpp"

#include <array>

namespace jose::base64url {

namespace {

constexpr auto k_encode_table =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

constexpr auto make_decode_table() -> std::array<int8_t, 256> {
    std::array<int8_t, 256> table{};
    table.fill(-1);
    for (int i = 0; i < 64; ++i) {
        table[static_cast<uint8_t>(k_encode_table[i])] = static_cast<int8_t>(i);
    }
    // Strict RFC 7515 §2 alphabet only: '-' and '_'. The standard base64
    // chars '+' and '/' are deliberately rejected — lenient decoding makes
    // signed tokens malleable (multiple encodings of the same bytes).
    return table;
}

constexpr auto k_decode_table = make_decode_table();

} // namespace

auto encode(std::span<const uint8_t> input) -> std::string {
    std::string result;
    result.reserve(((input.size() + 2) / 3) * 4);

    size_t i = 0;
    const size_t len = input.size();

    while (i + 2 < len) {
        uint32_t triple = (static_cast<uint32_t>(input[i]) << 16)
                        | (static_cast<uint32_t>(input[i + 1]) << 8)
                        | static_cast<uint32_t>(input[i + 2]);
        result += k_encode_table[(triple >> 18) & 0x3F];
        result += k_encode_table[(triple >> 12) & 0x3F];
        result += k_encode_table[(triple >> 6) & 0x3F];
        result += k_encode_table[triple & 0x3F];
        i += 3;
    }

    if (i + 1 == len) {
        uint32_t val = static_cast<uint32_t>(input[i]) << 16;
        result += k_encode_table[(val >> 18) & 0x3F];
        result += k_encode_table[(val >> 12) & 0x3F];
        // No padding
    } else if (i + 2 == len) {
        uint32_t val = (static_cast<uint32_t>(input[i]) << 16)
                     | (static_cast<uint32_t>(input[i + 1]) << 8);
        result += k_encode_table[(val >> 18) & 0x3F];
        result += k_encode_table[(val >> 12) & 0x3F];
        result += k_encode_table[(val >> 6) & 0x3F];
        // No padding
    }

    return result;
}

auto encode(std::string_view input) -> std::string {
    return encode(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(input.data()), input.size()));
}

auto encode(const secure_bytes& input) -> std::string {
    return encode(std::span<const uint8_t>(input.data(), input.size()));
}

auto decode(std::string_view input) -> expected<secure_bytes> {
    auto sv = input;

    if (sv.empty()) {
        return secure_bytes{};
    }

    // Checked before the length, so whitespace is reported as such whatever
    // length it leaves.
    if (sv.find_first_of(" \t\r\n") != std::string_view::npos)
        return make_error(errc::invalid_base64,
                          "whitespace inside base64url (compact tokens may only have it at either end)");

    // RFC 7515 §2: base64url is unpadded — '=' is rejected below via the
    // decode table. A valid unpadded encoding is never length ≡ 1 (mod 4).
    if (sv.size() % 4 == 1) {
        return make_error(errc::invalid_base64, "invalid base64url length");
    }

    // Compute output size
    size_t out_len = (sv.size() * 3) / 4;

    secure_bytes result;
    result.reserve(out_len);

    uint32_t accum = 0;
    int bits = 0;

    for (char c : sv) {
        auto idx = static_cast<uint8_t>(c);
        int8_t val = k_decode_table[idx];
        if (val < 0) {
            return make_error(errc::invalid_base64,
                std::string("invalid base64url character: '") + c + "'");
        }
        accum = (accum << 6) | static_cast<uint32_t>(val);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            result.push_back(static_cast<uint8_t>((accum >> bits) & 0xFF));
        }
    }

    // Reject trailing bits that aren't zero
    if (bits > 0 && (accum & ((1u << bits) - 1)) != 0) {
        return make_error(errc::invalid_base64, "non-zero trailing bits in base64url");
    }

    return result;
}

} // namespace jose::base64url
