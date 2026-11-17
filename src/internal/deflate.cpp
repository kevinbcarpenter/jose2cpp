#include "internal/deflate.hpp"

#include <openssl/crypto.h>
#include <zlib.h>

#include <array>
#include <limits>
#include <string>

namespace jose::internal {

namespace {

constexpr int k_raw_window_bits = -15; // negative: raw DEFLATE, no header

auto zerr(const char* what, int rc) -> unexpected {
    return make_error(errc::compression_error, std::string(what) + " failed (zlib " + std::to_string(rc) + ")");
}

} // namespace

auto deflate_raw(std::span<const uint8_t> input) -> expected<secure_bytes> {
    if (input.size() > std::numeric_limits<uInt>::max())
        return make_error(errc::compression_error, "input too large to compress");

    z_stream zs{};
    int rc = deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, k_raw_window_bits, 8, Z_DEFAULT_STRATEGY);
    if (rc != Z_OK) return zerr("deflateInit2", rc);

    secure_bytes out(deflateBound(&zs, static_cast<uLong>(input.size())));
    zs.next_in = const_cast<Bytef*>(input.data()); // zlib's API is not const-correct
    zs.avail_in = static_cast<uInt>(input.size());
    zs.next_out = out.data();
    zs.avail_out = static_cast<uInt>(out.size());

    rc = deflate(&zs, Z_FINISH);
    const auto produced = zs.total_out;
    deflateEnd(&zs);
    if (rc != Z_STREAM_END) return zerr("deflate", rc);
    out.resize(produced);
    return out;
}

auto inflate_raw(std::span<const uint8_t> input, size_t max_output) -> expected<secure_bytes> {
    if (input.size() > std::numeric_limits<uInt>::max())
        return make_error(errc::compression_error, "input too large to decompress");

    z_stream zs{};
    int rc = inflateInit2(&zs, k_raw_window_bits);
    if (rc != Z_OK) return zerr("inflateInit2", rc);

    zs.next_in = const_cast<Bytef*>(input.data());
    zs.avail_in = static_cast<uInt>(input.size());

    secure_bytes out;
    std::array<uint8_t, 16384> chunk{};
    do {
        zs.next_out = chunk.data();
        zs.avail_out = static_cast<uInt>(chunk.size());
        rc = inflate(&zs, Z_NO_FLUSH);
        if (rc != Z_OK && rc != Z_STREAM_END) {
            inflateEnd(&zs);
            return make_error(errc::compression_error, "compressed content is malformed");
        }
        const size_t n = chunk.size() - zs.avail_out;
        if (out.size() + n > max_output) {
            inflateEnd(&zs);
            OPENSSL_cleanse(chunk.data(), chunk.size());
            return make_error(errc::compression_error,
                              "decompressed content exceeds " + std::to_string(max_output) + " octets");
        }
        out.insert(out.end(), chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(n));
        // No progress with input left means the stream is truncated.
        if (rc == Z_OK && n == 0 && zs.avail_in == 0) {
            inflateEnd(&zs);
            OPENSSL_cleanse(chunk.data(), chunk.size());
            return make_error(errc::compression_error, "compressed content is truncated");
        }
    } while (rc != Z_STREAM_END);

    const bool trailing = zs.avail_in != 0;
    inflateEnd(&zs);
    OPENSSL_cleanse(chunk.data(), chunk.size());
    if (trailing) return make_error(errc::compression_error, "data after the end of the compressed content");
    return out;
}

} // namespace jose::internal
