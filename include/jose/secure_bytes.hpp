#pragma once

#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include <openssl/crypto.h>

namespace jose {

// Allocator that zeroes memory on deallocation. Key material and other
// crypto intermediates live in secure_bytes so secrets never linger on
// the heap after free.
template <typename T>
struct secure_allocator {
    using value_type = T;

    secure_allocator() noexcept = default;

    template <typename U>
    constexpr secure_allocator(const secure_allocator<U>&) noexcept {}

    [[nodiscard]] auto allocate(std::size_t n) -> T* {
        return std::allocator<T>{}.allocate(n);
    }

    void deallocate(T* p, std::size_t n) noexcept {
        OPENSSL_cleanse(p, n * sizeof(T));
        std::allocator<T>{}.deallocate(p, n);
    }

    template <typename U>
    auto operator==(const secure_allocator<U>&) const noexcept -> bool { return true; }
};

using secure_bytes = std::vector<uint8_t, secure_allocator<uint8_t>>;

inline auto to_span(const secure_bytes& v) -> std::span<const uint8_t> {
    return {v.data(), v.size()};
}

} // namespace jose
