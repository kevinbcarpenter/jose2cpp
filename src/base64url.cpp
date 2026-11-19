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

// The decode table pre-shifted for each position in a group of four, so a
// group is four lookups OR-ed together. A character outside the alphabet
// sets a bit above the low 24, which the OR keeps.
constexpr uint32_t k_bad = 0x01000000;
constexpr auto make_shifted_table(int shift) -> std::array<uint32_t, 256> {
    std::array<uint32_t, 256> table{};
    for (int i = 0; i < 256; ++i)
        table[i] = k_decode_table[i] < 0 ? k_bad : static_cast<uint32_t>(k_decode_table[i]) << shift;
    return table;
}
constexpr auto k_shift18 = make_shifted_table(18);
constexpr auto k_shift12 = make_shifted_table(12);
constexpr auto k_shift6 = make_shifted_table(6);
constexpr auto k_shift0 = make_shifted_table(0);

} // namespace

auto encode(std::span<const uint8_t> input) -> std::string {
    // Sized up front and written through a pointer: appending one char at a
    // time costs a library call per character with libc++ (PLAN.md §Benchmarks).
    const size_t len = input.size();
    std::string result(len / 3 * 4 + (len % 3 == 0 ? 0 : len % 3 + 1), '\0');
    char* out = result.data();
    const uint8_t* in = input.data();

    size_t i = 0;
    for (; i + 2 < len; i += 3) {
        const uint32_t triple = (static_cast<uint32_t>(in[i]) << 16)
                              | (static_cast<uint32_t>(in[i + 1]) << 8)
                              | static_cast<uint32_t>(in[i + 2]);
        *out++ = k_encode_table[(triple >> 18) & 0x3F];
        *out++ = k_encode_table[(triple >> 12) & 0x3F];
        *out++ = k_encode_table[(triple >> 6) & 0x3F];
        *out++ = k_encode_table[triple & 0x3F];
    }

    // No padding (RFC 7515 §2).
    if (i + 1 == len) {
        const uint32_t val = static_cast<uint32_t>(in[i]) << 16;
        *out++ = k_encode_table[(val >> 18) & 0x3F];
        *out++ = k_encode_table[(val >> 12) & 0x3F];
    } else if (i + 2 == len) {
        const uint32_t val = (static_cast<uint32_t>(in[i]) << 16)
                           | (static_cast<uint32_t>(in[i + 1]) << 8);
        *out++ = k_encode_table[(val >> 18) & 0x3F];
        *out++ = k_encode_table[(val >> 12) & 0x3F];
        *out++ = k_encode_table[(val >> 6) & 0x3F];
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

namespace {

auto decode_unchecked_whitespace(std::string_view sv) -> expected<secure_bytes> {
    // RFC 7515 §2: base64url is unpadded — '=' is rejected below via the
    // decode table. A valid unpadded encoding is never length ≡ 1 (mod 4).
    if (sv.size() % 4 == 1) {
        return make_error(errc::invalid_base64, "invalid base64url length");
    }

    // Exact output size for unpadded input. Four characters at a time into a
    // presized buffer (PLAN.md §Benchmarks), with the pre-shifted tables;
    // the 2- or 3-character tail uses the plain table, where a character
    // outside the alphabet is -1.
    const size_t rem = sv.size() % 4;
    secure_bytes result(sv.size() / 4 * 3 + (rem == 0 ? 0 : rem - 1));
    uint8_t* out = result.data();
    const char* in = sv.data();
    const char* const full_end = in + (sv.size() - rem);

    auto value = [](char c) -> int { return k_decode_table[static_cast<uint8_t>(c)]; };
    auto bad_char = [](const char* from, size_t count) -> jose::unexpected {
        for (size_t k = 0; k < count; ++k)
            if (k_decode_table[static_cast<uint8_t>(from[k])] < 0)
                return make_error(errc::invalid_base64,
                                  std::string("invalid base64url character: '") + from[k] + "'");
        return make_error(errc::invalid_base64, "invalid base64url character");
    };

    for (; in != full_end; in += 4) {
        const uint32_t triple = k_shift18[static_cast<uint8_t>(in[0])] | k_shift12[static_cast<uint8_t>(in[1])]
                              | k_shift6[static_cast<uint8_t>(in[2])] | k_shift0[static_cast<uint8_t>(in[3])];
        if (triple >= k_bad) return bad_char(in, 4);
        *out++ = static_cast<uint8_t>(triple >> 16);
        *out++ = static_cast<uint8_t>(triple >> 8);
        *out++ = static_cast<uint8_t>(triple);
    }

    // The last 2 or 3 characters carry 1 or 2 octets; the bits left over
    // must be zero, or several encodings would decode to the same bytes.
    if (rem == 2) {
        const int a = value(in[0]), b = value(in[1]);
        if ((a | b) < 0) return bad_char(in, 2);
        if ((b & 0x0F) != 0) return make_error(errc::invalid_base64, "non-zero trailing bits in base64url");
        *out++ = static_cast<uint8_t>((a << 2) | (b >> 4));
    } else if (rem == 3) {
        const int a = value(in[0]), b = value(in[1]), c = value(in[2]);
        if ((a | b | c) < 0) return bad_char(in, 3);
        if ((c & 0x03) != 0) return make_error(errc::invalid_base64, "non-zero trailing bits in base64url");
        *out++ = static_cast<uint8_t>((a << 2) | (b >> 4));
        *out++ = static_cast<uint8_t>(((b & 0x0F) << 4) | (c >> 2));
    }

    return result;
}

} // namespace

auto decode(std::string_view input) -> expected<secure_bytes> {
    if (input.empty()) return secure_bytes{};
    auto result = decode_unchecked_whitespace(input);
    // Whitespace is reported as such whatever else is wrong (its length, a
    // character before it). It is outside the alphabet, so any input that
    // has it fails above; looking for it only then keeps the scan off the
    // success path (PLAN.md §Benchmarks).
    if (!result && input.find_first_of(" \t\r\n") != std::string_view::npos)
        return make_error(errc::invalid_base64,
                          "whitespace inside base64url (compact tokens may only have it at either end)");
    return result;
}

} // namespace jose::base64url
