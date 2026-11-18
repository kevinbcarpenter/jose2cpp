// base64url (RFC 4648 §5, unpadded, strict): decoding then re-encoding
// gives back the input exactly, since only one spelling of any byte string
// is accepted; and encoding then decoding gives back the bytes.

#include "fuzz_common.hpp"

#include <algorithm>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
    const auto input = fuzz::text(data, size);

    if (auto decoded = jose::base64url::decode(input)) {
        fuzz::check(jose::base64url::encode(*decoded) == input, "decode then encode is not the identity");
    }

    const auto encoded = jose::base64url::encode(std::span(data, size));
    fuzz::check(encoded.find_first_of("+/=") == std::string::npos, "encode wrote a non-base64url character");
    auto back = jose::base64url::decode(encoded);
    fuzz::check(back.has_value(), "decode refused what encode wrote");
    fuzz::check(std::equal(back->begin(), back->end(), data, data + size), "encode then decode changed the bytes");
    return 0;
}
