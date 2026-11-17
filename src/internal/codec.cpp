#include "internal/codec.hpp"

#include "jose/crypto/openssl_util.hpp"

#include <set>

namespace jose::internal {

using json = nlohmann::json;

auto parse_json_strict(std::string_view text, std::string_view what) -> expected<json> {
    // One set of member names per open object. Arrays don't open a scope:
    // their elements are values, and any objects inside push their own set.
    std::vector<std::set<std::string>> scopes;
    std::string duplicate;
    bool has_duplicate = false;

    json::parser_callback_t cb = [&](int /*depth*/, json::parse_event_t event, json& parsed) {
        switch (event) {
        case json::parse_event_t::object_start:
            scopes.emplace_back();
            break;
        case json::parse_event_t::object_end:
            if (!scopes.empty()) scopes.pop_back();
            break;
        case json::parse_event_t::key:
            if (!scopes.empty() && !scopes.back().insert(parsed.get<std::string>()).second &&
                !has_duplicate) {
                has_duplicate = true;
                duplicate = parsed.get<std::string>();
            }
            break;
        default:
            break;
        }
        return true;
    };

    auto j = json::parse(text, cb, /*allow_exceptions=*/false);
    if (j.is_discarded())
        return make_error(errc::serialization_error, std::string(what) + " is not valid JSON");
    if (has_duplicate)
        return make_error(errc::serialization_error,
                          std::string(what) + " has duplicate member \"" + duplicate + "\"");
    return j;
}

auto b64std_decode(std::string_view s) -> expected<std::vector<uint8_t>> {
    auto bad = [] { return make_error(errc::invalid_base64, "x5c entry is not valid base64"); };
    if (s.empty() || s.size() % 4 != 0) return bad();
    size_t pad = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        const bool alnum = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                           (c >= '0' && c <= '9') || c == '+' || c == '/';
        if (c == '=' && i >= s.size() - 2) {
            ++pad;
        } else if (!alnum || pad > 0) {
            return bad();
        }
    }
    std::vector<uint8_t> out(s.size() / 4 * 3);
    const int n = EVP_DecodeBlock(out.data(), reinterpret_cast<const unsigned char*>(s.data()),
                                  static_cast<int>(s.size()));
    if (n < 0) return bad();
    out.resize(static_cast<size_t>(n) - pad);
    return out;
}

auto b64std_encode(std::span<const uint8_t> in) -> std::string {
    std::string out(4 * ((in.size() + 2) / 3) + 1, '\0');
    const int n = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()), in.data(),
                                  static_cast<int>(in.size()));
    out.resize(static_cast<size_t>(n));
    return out;
}

auto is_valid_utf8(std::string_view s) -> bool {
    const auto* p = reinterpret_cast<const unsigned char*>(s.data());
    const auto* end = p + s.size();
    while (p < end) {
        const unsigned char c = *p;
        size_t n = 0;
        uint32_t cp = 0;
        if (c < 0x80) { ++p; continue; }
        if (c >= 0xC2 && c <= 0xDF) { n = 1; cp = c & 0x1F; }
        else if (c >= 0xE0 && c <= 0xEF) { n = 2; cp = c & 0x0F; }
        else if (c >= 0xF0 && c <= 0xF4) { n = 3; cp = c & 0x07; }
        else return false;
        if (static_cast<size_t>(end - p) <= n) return false;
        for (size_t i = 1; i <= n; ++i) {
            if ((p[i] & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (p[i] & 0x3F);
        }
        if ((n == 2 && cp < 0x800) || (n == 3 && (cp < 0x10000 || cp > 0x10FFFF)) ||
            (cp >= 0xD800 && cp <= 0xDFFF))
            return false;
        p += n + 1;
    }
    return true;
}

auto digest(const EVP_MD* md, std::span<const uint8_t> in) -> expected<std::vector<uint8_t>> {
    std::vector<uint8_t> out(EVP_MAX_MD_SIZE);
    unsigned int len = 0;
    if (EVP_Digest(in.data(), in.size(), out.data(), &len, md, nullptr) != 1)
        return make_openssl_error("EVP_Digest");
    out.resize(len);
    return out;
}

} // namespace jose::internal
