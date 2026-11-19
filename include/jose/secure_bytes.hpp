#pragma once

/// @file
/// secure_bytes, a byte vector that is zeroed when freed, and the opt-in
/// OpenSSL secure heap.

#include "jose/error.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <span>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/err.h>

namespace jose {

/// Allocator for key material and other crypto intermediates.
///
/// Memory is always zeroed (OPENSSL_cleanse) before it is freed. If the
/// application has reserved a secure heap with jose::init_secure_heap(),
/// allocations come from that mlock'ed, guard-paged arena, so secrets are
/// not swapped to disk. When the arena is not initialised or is full,
/// allocation silently falls back to the ordinary heap (still zeroed on
/// free); see PLAN.md §Secure Memory.
template <typename T>
struct secure_allocator {
    using value_type = T; ///< the element type

    secure_allocator() noexcept = default; ///< stateless

    /// Rebinding copy; the allocator has no state.
    template <typename U>
    constexpr secure_allocator(const secure_allocator<U>&) noexcept {}

    /// From the secure heap if it's initialised and has room, else the
    /// ordinary heap. Throws std::bad_alloc when both fail.
    [[nodiscard]] auto allocate(std::size_t n) -> T* {
        if (n > std::numeric_limits<std::size_t>::max() / sizeof(T))
            throw std::bad_array_new_length();
        const std::size_t bytes = n * sizeof(T);

        void* p = nullptr;
        if (CRYPTO_secure_malloc_initialized()) {
            // An exhausted arena pushes an error onto the OpenSSL queue;
            // discard it so it can't be misreported by a later call.
            ERR_set_mark();
            p = CRYPTO_secure_malloc(bytes, nullptr, 0);
            ERR_pop_to_mark();
        }
        if (p == nullptr)
            p = CRYPTO_malloc(bytes, nullptr, 0);
        if (p == nullptr)
            throw std::bad_alloc();
        return static_cast<T*>(p);
    }

    /// Zeroes the memory, then frees it.
    void deallocate(T* p, std::size_t n) noexcept {
        // Frees from whichever heap `p` came from, cleansing first.
        CRYPTO_secure_clear_free(p, n * sizeof(T), nullptr, 0);
    }

    /// Always equal: any instance can free what another allocated.
    template <typename U>
    auto operator==(const secure_allocator<U>&) const noexcept -> bool { return true; }
};

/// Bytes that are zeroed when freed: keys, CEKs, decrypted plaintext.
using secure_bytes = std::vector<uint8_t, secure_allocator<uint8_t>>;

/// A read-only view of secure_bytes.
inline auto to_span(const secure_bytes& v) -> std::span<const uint8_t> {
    return {v.data(), v.size()};
}

// --- Secure heap (opt-in) ---

/// What init_secure_heap managed to set up.
enum class secure_heap_status {
    locked,     ///< arena reserved and mlock'ed
    not_locked, ///< arena reserved, but mlock failed (RLIMIT_MEMLOCK, say);
                ///< memory is still guard-paged and zeroed, but may be swapped
};

/// Reserve a process-wide secure arena of `size` bytes for secure_bytes.
/// Call once at startup, before any key material is created. `size` and
/// `min_alloc` must be powers of two with min_alloc < size. Fails if the
/// heap is already initialised or OpenSSL was built without secure memory.
auto init_secure_heap(std::size_t size, std::size_t min_alloc = 32)
    -> expected<secure_heap_status>;

} // namespace jose
