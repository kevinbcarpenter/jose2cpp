#pragma once

/// @file
/// A JWKS fetcher: keeps an identity provider's published keys (a JWK Set
/// at a URL, RFC 7517 §5) cached and refreshed, for verifying the JWTs it
/// issues. It brings no HTTP library: you supply the transport by
/// implementing http_client over whatever you already use (libcurl,
/// Boost.Beast, cpp-httplib, your framework's client).
///
/// @code{.cpp}
/// struct curl_client final : jose::optional::http_client {
///     auto get(jose::optional::http_request request)
///         -> jose::task<jose::expected<jose::optional::http_response>> override {
///         ...   // GET request.url over TLS, honouring request.timeout and
///               // request.max_response_bytes
///     }
/// };
///
/// jose::optional::jwks_fetcher fetcher({.url = "https://auth.example.com/.well-known/jwks.json"},
///                                      std::make_unique<curl_client>());
///
/// auto parsed = jose::jwt::parse_signed(token, {jose::signing_algorithm::RS256});
/// if (!parsed) ...
/// auto kid = parsed->header().kid();
/// if (!kid) ...
/// auto keys = co_await fetcher.keys_for(std::string(*kid));
/// if (!keys) ...
/// auto claims = parsed->claims(**keys);
/// @endcode
///
/// What it does for you:
/// - Caching. keys() returns the cached set until it's refresh_interval
///   old, then fetches again. keys_for(kid) also fetches when the set has no
///   key with that "kid", which is how a key the provider just rotated in
///   gets picked up.
/// - Rate limiting. Fetches start at most once per min_refresh_interval,
///   whatever the callers ask for, so tokens with made-up "kid"s can't turn
///   the fetcher into a flood of requests to the provider.
/// - One request at a time. Callers that need a fetch while one is running
///   wait for it rather than starting their own, so http_client never sees
///   two requests at once.
/// - Riding out outages. If a fetch fails, the old set keeps being served
///   until it is refresh_interval + max_stale old. After that, callers get
///   the error. A key the provider has withdrawn is still accepted for that
///   long, so keep max_stale as short as your provider's uptime allows.
/// - Only public keys are kept. Symmetric ("oct") keys are dropped, since
///   anyone who can read the URL could sign with them, and private keys are
///   reduced to their public half. Keys jwk_set::from_json skips (an
///   unsupported "kty" or "crv") are dropped as well.
///
/// Errors:
///
/// | Error                  | When                                                    |
/// | ---------------------- | ------------------------------------------------------- |
/// | errc::invalid_argument | the config is invalid (from every call)                 |
/// | errc::key_unavailable  | http_client failed, or the status wasn't 200            |
/// | errc::invalid_key      | the response isn't a usable JWK Set: too large, not JSON, more than max_keys keys, or no public key left after filtering; or, from keys_for, no key has that "kid" even after a fetch |
/// http_client's own errors pass through unchanged.
///
/// Threads: the fetcher is safe to use from many threads at once. A task
/// that waits for another caller's fetch resumes on the thread that
/// finished it (see task.hpp); waiters resume one after another, in the
/// order they started waiting.
///
/// Lifetime: the fetcher must outlive every task it returns. A task may be
/// destroyed before it finishes (to cancel it), but only from a thread that
/// can't be finishing a fetch at the same moment, as with any coroutine
/// someone else may resume. If it was the task doing the fetch, the fetch
/// ends and its waiters get what keys() would without one: the old set
/// while it's within max_stale, otherwise errc::key_unavailable.
///
/// It ignores HTTP caching headers (Cache-Control, ETag); refresh_interval
/// alone decides when to fetch.

#include "jose/error.hpp"
#include "jose/jwk.hpp"
#include "jose/task.hpp"

#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <string>

/// Parts that need something from the application (an HTTP client) and
/// aren't included by jose/jose.hpp.
namespace jose::optional {

/// One GET the fetcher asks the http_client for.
struct http_request {
    std::string url = {}; ///< jwks_fetcher_config::url
    /// Give up after this long (connecting, waiting and reading together).
    std::chrono::seconds timeout{};
    /// Stop reading and fail once the body is larger than this. The fetcher
    /// checks the size again, but only a client that stops early saves the
    /// memory and bandwidth.
    std::size_t max_response_bytes = 0;
};

/// What the http_client got back. Only status 200 is accepted.
struct http_response {
    int status = 0;   ///< the HTTP status code
    std::string body; ///< the response body, expected to be a JWK Set
};

/// The HTTP transport the fetcher uses. jose2cpp ships none; wrap your
/// own client (libcurl, Boost.Beast, an internal one) in this interface.
class http_client {
public:
    virtual ~http_client() = default;

    /// A GET of request.url. Report transport failures (DNS, TLS, timeout,
    /// connection refused) as an error, conventionally errc::key_unavailable;
    /// return any HTTP response, whatever its status, as an http_response.
    /// Verify TLS certificates: the keys are only as trustworthy as the
    /// connection that fetched them.
    ///
    /// Don't throw. The fetcher passes an exception on to the caller that
    /// started the fetch; callers waiting for it get what keys() would
    /// without a fetch (the old set while it's within max_stale, otherwise
    /// errc::key_unavailable).
    ///
    /// The returned task may be destroyed while suspended, when the caller
    /// that started the fetch is cancelled. Cancel or detach the request
    /// when that happens, so nothing resumes the destroyed task. The next
    /// get() can then start while the abandoned request is still running in
    /// your client, and get() can also be called again from inside the
    /// resume() that finished the previous one, so keep no per-request state
    /// that outlives the task.
    virtual auto get(http_request request) -> task<expected<http_response>> = 0;
};

/// Settings for a jwks_fetcher.
struct jwks_fetcher_config {
    /// Must be https:// unless allow_http is set.
    std::string url = {};
    /// How old the cached set may get before keys() fetches a new one.
    std::chrono::seconds refresh_interval{300};
    /// The least time between two fetches starting, however they're asked
    /// for. At most refresh_interval.
    std::chrono::seconds min_refresh_interval{30};
    /// How long past refresh_interval the old set is still served while
    /// fetches fail.
    std::chrono::seconds max_stale{3600};
    /// Passed to http_client in each request.
    std::chrono::seconds timeout{10};
    /// The largest response body accepted, 1 MiB by default. Passed to
    /// http_client in each request.
    std::size_t max_response_bytes{std::size_t{1} << 20};
    /// The most entries the "keys" array may have, counting ones that are
    /// dropped.
    std::size_t max_keys{100};
    /// Allow http:// URLs, for tests and local development only.
    bool allow_http = false;
    /// The time source; unset means std::chrono::steady_clock::now. For
    /// tests. It must be safe to call from any thread using the fetcher.
    std::function<std::chrono::steady_clock::time_point()> clock = nullptr;
};

/// Keeps a JWK Set fetched from a URL and fetches it again when it gets old.
/// Only public keys are kept. Safe to use from many threads at once; see the
/// top of jwks_fetcher.hpp for how tasks resume and when it may be destroyed.
class jwks_fetcher {
public:
    /// A snapshot of the set. It never changes; a refresh makes a new one.
    using key_set = std::shared_ptr<const jwk_set>;

    /// Every duration must be between zero (exclusive for refresh_interval
    /// and timeout) and ten years, and max_keys and max_response_bytes above
    /// zero. An invalid config, or a null client, isn't reported here:
    /// every call returns the error instead.
    jwks_fetcher(jwks_fetcher_config config, std::unique_ptr<http_client> client);
    ~jwks_fetcher();
    jwks_fetcher(const jwks_fetcher&) = delete;
    jwks_fetcher& operator=(const jwks_fetcher&) = delete;
    jwks_fetcher(jwks_fetcher&&) = delete;
    jwks_fetcher& operator=(jwks_fetcher&&) = delete;

    /// The cached set, fetching a new one first if it's refresh_interval old
    /// (or there isn't one yet). Once there is a set, a caller never waits
    /// for another caller's fetch: while one is running, or within
    /// min_refresh_interval of the last attempt, the old set is returned as
    /// long as it's within max_stale.
    auto keys() -> task<expected<key_set>>;

    /// keys(), then, if no key in the set has this "kid", a fetch (subject to
    /// min_refresh_interval) and a second look. The set returned has at least
    /// one key with the "kid".
    auto keys_for(std::string kid) -> task<expected<key_set>>;

    /// Fetches now, unless one started less than min_refresh_interval ago,
    /// in which case it returns what keys() would. Waits for a fetch that's
    /// already running and returns its result. When the fetch fails, the
    /// result is what keys() would return, so while the old set is within
    /// max_stale you get it rather than the error.
    auto refresh() -> task<expected<key_set>>;

    /// The set keys() would return without fetching: the last one fetched,
    /// or nullptr if there's none or it's past max_stale. Doesn't block on
    /// a fetch.
    [[nodiscard]] auto cached() const -> key_set;

private:
    struct state;
    struct waiter;
    struct fetch_guard;
    auto obtain(bool force) -> task<expected<key_set>>;
    std::unique_ptr<state> state_;
};

} // namespace jose::optional
