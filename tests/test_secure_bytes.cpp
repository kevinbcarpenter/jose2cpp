#include <catch2/catch_test_macros.hpp>

#include "jose/jose.hpp"

#include <openssl/crypto.h>

using namespace jose;

namespace {

constexpr std::size_t k_arena = 64 * 1024;

// The secure heap is process-wide and can only be initialised once; ctest
// runs each test case in its own process, but a direct `jose_tests` run
// shares one, so initialise lazily and remember the outcome.
auto ensure_secure_heap() -> secure_heap_status {
    static const auto status = [] {
        auto s = init_secure_heap(k_arena);
        REQUIRE(s.has_value());
        return *s;
    }();
    return status;
}

} // namespace

TEST_CASE("secure_bytes works without a secure heap", "[secure_bytes]") {
    // Holds whether or not another test in this process initialised it.
    secure_bytes b(64, 0xAB);
    b.resize(4096, 0xCD);
    REQUIRE(b.size() == 4096);
    CHECK(b.front() == 0xAB);
    CHECK(b.back() == 0xCD);
}

TEST_CASE("init_secure_heap validates arguments", "[secure_bytes]") {
    CHECK(init_secure_heap(1000).error().code == errc::invalid_argument);    // not a power of two
    CHECK(init_secure_heap(4096, 48).error().code == errc::invalid_argument); // min_alloc not a power of two
    CHECK(init_secure_heap(4096, 4096).error().code == errc::invalid_argument);
}

TEST_CASE("secure_bytes allocates from the secure heap once enabled", "[secure_bytes]") {
    const auto status = ensure_secure_heap();
    CHECK((status == secure_heap_status::locked ||
           status == secure_heap_status::not_locked));
    REQUIRE(CRYPTO_secure_malloc_initialized());

    // Second initialisation is refused.
    CHECK_FALSE(init_secure_heap(k_arena).has_value());

    // OpenSSL's DRBG keeps its own seed state in the secure heap for the
    // life of the process; instantiate it before taking the baseline.
    {
        auto warmup = random_bytes(1);
        REQUIRE(warmup.has_value());
    }

    const auto used_before = CRYPTO_secure_used();
    {
        secure_bytes key(32, 0x42);
        CHECK(CRYPTO_secure_allocated(key.data()));
        CHECK(CRYPTO_secure_used() > used_before);

        // Library code paths allocate there too.
        auto random = random_bytes(32);
        REQUIRE(random.has_value());
        CHECK(CRYPTO_secure_allocated(random->data()));
    }
    // Freed (and cleansed) back to the arena.
    CHECK(CRYPTO_secure_used() == used_before);
}

TEST_CASE("secure_bytes falls back to the normal heap when the arena is full",
          "[secure_bytes]") {
    ensure_secure_heap();
    ERR_clear_error(); // ignore anything earlier tests in this process left

    // Larger than the whole arena: must still succeed, from the normal heap.
    secure_bytes big(k_arena * 2, 0x11);
    CHECK_FALSE(CRYPTO_secure_allocated(big.data()));
    CHECK(big[k_arena] == 0x11);

    // The failed arena allocation must not leave an error on the queue.
    CHECK(ERR_peek_error() == 0);
}
