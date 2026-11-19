// Raw DEFLATE inflation (JWE "zip":"DEF"), with the output caps. The
// library only inflates after a JWE has been authenticated, which a fuzzer
// can't reach by forging tokens, so the inflater gets its own target.
// Output never exceeds the cap, and what inflates deflates and inflates
// back to the same bytes.

#include "fuzz_common.hpp"

#include "internal/deflate.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
    const std::span input(data, size);
    constexpr std::size_t cap = 1 << 20;

    if (auto out = jose::internal::inflate_raw(input, cap)) {
        fuzz::check(out->size() <= cap, "inflate went past its cap");
        auto again = jose::internal::deflate_raw(*out);
        fuzz::check(again.has_value(), "deflate failed on inflated output");
        auto back = jose::internal::inflate_raw(*again, cap);
        fuzz::check(back.has_value() && *back == *out, "deflate then inflate changed the bytes");
    }
    for (const std::size_t small : {std::size_t{0}, std::size_t{1}, std::size_t{100}}) {
        if (auto out = jose::internal::inflate_raw(input, small))
            fuzz::check(out->size() <= small, "inflate went past a small cap");
    }
    return 0;
}
