#include "jose/secure_bytes.hpp"

#include "jose/crypto/openssl_util.hpp"

#include <bit>

namespace jose {

auto init_secure_heap(std::size_t size, std::size_t min_alloc)
    -> expected<secure_heap_status> {
    if (!std::has_single_bit(size) || !std::has_single_bit(min_alloc) ||
        min_alloc >= size)
        return make_error(errc::invalid_argument,
                          "secure heap size and min_alloc must be powers of "
                          "two with min_alloc < size");

    if (CRYPTO_secure_malloc_initialized())
        return make_error(errc::openssl_error, "secure heap is already initialised");

    switch (CRYPTO_secure_malloc_init(size, min_alloc)) {
    case 1:
        return secure_heap_status::locked;
    case 2:
        return secure_heap_status::not_locked;
    default:
        return make_openssl_error("CRYPTO_secure_malloc_init");
    }
}

} // namespace jose
