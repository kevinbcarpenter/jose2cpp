#include "jose/optional/jwks_fetcher.hpp"

#include "internal/codec.hpp"

#include <algorithm>
#include <cctype>
#include <coroutine>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
#define JOSE_FETCHER_EXCEPTIONS 1
#else
#define JOSE_FETCHER_EXCEPTIONS 0
#endif

namespace jose::optional {

namespace {

using clock_type = std::chrono::steady_clock;

// Bounds every duration, so sums and conversions to the clock's
// nanoseconds can't overflow.
constexpr std::chrono::seconds ten_years{std::int64_t{10} * 366 * 24 * 3600};

auto bad_config(std::string message) -> error {
    return error(errc::invalid_argument, "jwks_fetcher: " + std::move(message));
}

auto starts_with_ignoring_case(std::string_view s, std::string_view prefix) -> bool {
    return s.size() >= prefix.size() &&
           std::equal(prefix.begin(), prefix.end(), s.begin(), [](char a, char b) {
               return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
           });
}

auto check_config(const jwks_fetcher_config& c, const http_client* client) -> std::optional<error> {
    if (!client) return bad_config("the http_client is null");
    std::string_view scheme;
    if (starts_with_ignoring_case(c.url, "https://"))
        scheme = "https://";
    else if (c.allow_http && starts_with_ignoring_case(c.url, "http://"))
        scheme = "http://";
    else
        return bad_config(c.allow_http ? "the URL must start with https:// or http://"
                                       : "the URL must start with https:// (allow_http permits http://)");
    if (c.url.size() == scheme.size()) return bad_config("the URL has no host");

    const auto in_range = [](std::chrono::seconds d, bool zero_ok) {
        return (zero_ok ? d.count() >= 0 : d.count() > 0) && d <= ten_years;
    };
    if (!in_range(c.refresh_interval, false))
        return bad_config("refresh_interval must be more than zero and at most ten years");
    if (!in_range(c.min_refresh_interval, true) || c.min_refresh_interval > c.refresh_interval)
        return bad_config("min_refresh_interval must be between zero and refresh_interval");
    if (!in_range(c.max_stale, true)) return bad_config("max_stale must be between zero and ten years");
    if (!in_range(c.timeout, false)) return bad_config("timeout must be more than zero and at most ten years");
    if (c.max_keys == 0) return bad_config("max_keys must be more than zero");
    if (c.max_response_bytes == 0) return bad_config("max_response_bytes must be more than zero");
    return std::nullopt;
}

auto bad_jwks(std::string message) -> unexpected {
    return make_error(errc::invalid_key, "JWKS response: " + std::move(message));
}

// Turns a response into the set to cache: public keys only.
auto parse_response(const http_response& response, const jwks_fetcher_config& config)
    -> expected<jwks_fetcher::key_set> {
    if (response.status != 200)
        return make_error(errc::key_unavailable,
                          "JWKS endpoint returned HTTP " + std::to_string(response.status) + ", not 200");
    if (response.body.size() > config.max_response_bytes)
        return bad_jwks(std::to_string(response.body.size()) + " bytes is more than max_response_bytes (" +
                        std::to_string(config.max_response_bytes) + ")");

    auto j = internal::parse_json_strict(response.body, "JWK Set");
    if (!j) return bad_jwks(j.error().message);
    if (j->is_object()) {
        const auto it = j->find("keys");
        if (it != j->end() && it->is_array() && it->size() > config.max_keys)
            return bad_jwks(std::to_string(it->size()) + " keys is more than max_keys (" +
                            std::to_string(config.max_keys) + ")");
    }
    auto set = jwk_set::from_json(*j);
    if (!set) return bad_jwks(set.error().message);

    std::vector<jwk> keep;
    keep.reserve(set->size());
    for (const jwk& key : set->keys()) {
        if (key.key_type() == kty::oct) continue;
        if (!key.is_private()) {
            keep.push_back(key);
            continue;
        }
        if (auto pub = key.public_key()) keep.push_back(std::move(*pub));
    }
    if (keep.empty()) {
        const auto dropped = set->size() + set->skipped().size();
        return bad_jwks("no usable public key (" + std::to_string(dropped) +
                        (dropped == 1 ? " key" : " keys") + " dropped: symmetric, or an unsupported type)");
    }
    return std::make_shared<const jwk_set>(std::move(keep));
}

} // namespace

struct jwks_fetcher::state {
    using time_point = clock_type::time_point;

    jwks_fetcher_config config;
    std::unique_ptr<http_client> client;
    std::optional<error> config_error;

    struct entry {
        waiter* w;
        std::uint64_t fetch; // which fetch it waits for
    };

    mutable std::mutex m;
    // Guarded by m:
    key_set set;                // the last set fetched, or null
    time_point fetched_at{};    // when the fetch that produced it started
    std::optional<time_point> last_attempt;
    std::optional<error> last_error; // from the last attempt, if it failed
    bool in_flight = false;
    std::uint64_t fetches = 0;  // numbers each fetch
    std::vector<entry> waiters; // in the order they started waiting

    [[nodiscard]] auto now() const -> time_point { return config.clock ? config.clock() : clock_type::now(); }

    // The rest need m held.
    [[nodiscard]] auto fresh(time_point t) const -> bool { return set && t - fetched_at < config.refresh_interval; }
    [[nodiscard]] auto usable(time_point t) const -> bool {
        return set && t - fetched_at < config.refresh_interval + config.max_stale;
    }
    [[nodiscard]] auto throttled(time_point t) const -> bool {
        return last_attempt && t - *last_attempt < config.min_refresh_interval;
    }
    // What a caller gets without a fetch.
    [[nodiscard]] auto best(time_point t) const -> expected<key_set> {
        if (usable(t)) return set;
        if (last_error) return jose::unexpected(*last_error);
        if (set) return make_error(errc::key_unavailable, "the cached JWK Set is past max_stale");
        return make_error(errc::key_unavailable, "no JWK Set has been fetched yet");
    }
};

namespace {

auto abandoned() -> unexpected {
    return make_error(errc::key_unavailable,
                      "the JWKS fetch ended without a result (http_client threw, or the fetching task was destroyed)");
}

} // namespace

// Waits for the fetch that's running; if it has finished by the time this
// suspends, takes what it left behind instead. A task destroyed while
// waiting takes itself off the list.
struct jwks_fetcher::waiter {
    state& s;
    std::optional<expected<key_set>> result = std::nullopt;
    std::coroutine_handle<> handle = nullptr;
    bool listed = false; // guarded by s.m

    explicit waiter(state& st) noexcept : s(st) {}
    waiter(const waiter&) = delete;
    waiter& operator=(const waiter&) = delete;
    ~waiter() {
        const std::lock_guard lock(s.m);
        if (listed)
            std::erase_if(s.waiters, [this](const state::entry& e) { return e.w == this; });
    }

    [[nodiscard]] auto await_ready() const noexcept -> bool { return false; }
    auto await_suspend(std::coroutine_handle<> h) -> bool {
        const std::lock_guard lock(s.m);
        if (s.in_flight) {
            handle = h;
            listed = true;
            s.waiters.push_back({this, s.fetches});
            return true; // may be resumed on another thread from here on
        }
        result = s.best(s.now());
        return false;
    }
    auto await_resume() -> expected<key_set> { return std::move(*result); }
};

// Ends a fetch exactly once: records the result, clears in_flight and
// resumes that fetch's waiters. obtain() calls finish(); if the task is
// destroyed while the fetch is suspended, the destructor ends it with an
// error so waiters aren't left hanging.
struct jwks_fetcher::fetch_guard {
    state& s;
    state::time_point started;
    std::uint64_t fetch;
    bool done = false;

    fetch_guard(state& st, state::time_point t, std::uint64_t n) noexcept : s(st), started(t), fetch(n) {}
    fetch_guard(const fetch_guard&) = delete;
    fetch_guard& operator=(const fetch_guard&) = delete;
    ~fetch_guard() {
        if (done) return;
#if JOSE_FETCHER_EXCEPTIONS
        try {
            (void)finish(abandoned());
        } catch (...) {
            // Out of memory, or a throwing clock; nothing more can be done here.
        }
#else
        (void)finish(abandoned());
#endif
    }

    auto finish(expected<key_set> fetched) -> expected<key_set> {
        done = true;
        std::optional<expected<key_set>> outcome;
        {
            const std::lock_guard lock(s.m);
            s.in_flight = false;
            if (fetched) {
                s.set = *fetched;
                s.fetched_at = started;
                s.last_error.reset();
                outcome = std::move(fetched);
            } else {
                s.last_error = fetched.error();
                outcome = s.best(s.now());
            }
        }
        // One at a time, so a waiter destroyed meanwhile (by an earlier
        // waiter's continuation, say) is never reached, and only this
        // fetch's waiters: a continuation may already have started the next.
        for (;;) {
            waiter* w = nullptr;
            {
                const std::lock_guard lock(s.m);
                const auto it = std::find_if(s.waiters.begin(), s.waiters.end(),
                                             [this](const state::entry& e) { return e.fetch == fetch; });
                if (it == s.waiters.end()) break;
                w = it->w;
                w->listed = false;
                s.waiters.erase(it);
            }
            w->result = *outcome;
            w->handle.resume();
        }
        return std::move(*outcome);
    }
};

jwks_fetcher::jwks_fetcher(jwks_fetcher_config config, std::unique_ptr<http_client> client)
    : state_(std::make_unique<state>()) {
    state_->config_error = check_config(config, client.get());
    state_->config = std::move(config);
    state_->client = std::move(client);
}

jwks_fetcher::~jwks_fetcher() = default;

auto jwks_fetcher::keys() -> task<expected<key_set>> { return obtain(false); }

auto jwks_fetcher::refresh() -> task<expected<key_set>> { return obtain(true); }

auto jwks_fetcher::keys_for(std::string kid) -> task<expected<key_set>> {
    auto first = co_await obtain(false);
    if (!first || (*first)->find(kid)) co_return first;
    auto second = co_await obtain(true);
    if (!second || (*second)->find(kid)) co_return second;
    co_return make_error(errc::invalid_key, "no key in the JWKS has \"kid\":\"" + kid + "\"");
}

auto jwks_fetcher::cached() const -> key_set {
    auto& s = *state_;
    if (s.config_error) return nullptr;
    const auto t = s.now();
    const std::lock_guard lock(s.m);
    return s.usable(t) ? s.set : nullptr;
}

auto jwks_fetcher::obtain(bool force) -> task<expected<key_set>> {
    auto& s = *state_;
    if (s.config_error) co_return jose::unexpected(*s.config_error);

    // Set in the same critical section as in_flight, so nothing can throw
    // between starting a fetch and having something that will end it.
    std::optional<fetch_guard> guard;
    std::optional<expected<key_set>> result;
    bool wait = false;
    {
        const auto t = s.now();
        const std::lock_guard lock(s.m);
        if (!force && s.fresh(t)) {
            result = s.set;
        } else if (s.in_flight) {
            if (!force && s.usable(t))
                result = s.set;
            else
                wait = true;
        } else if (s.throttled(t)) {
            result = s.best(t);
        } else {
            s.in_flight = true;
            s.last_attempt = t;
            guard.emplace(s, t, ++s.fetches);
        }
    }
    if (result) co_return std::move(*result);
    if (wait) co_return co_await waiter{s};

    std::optional<expected<key_set>> fetched;
#if JOSE_FETCHER_EXCEPTIONS
    try {
#endif
        auto response = co_await s.client->get(http_request{
            .url = s.config.url, .timeout = s.config.timeout, .max_response_bytes = s.config.max_response_bytes});
        if (response)
            fetched = parse_response(*response, s.config);
        else
            fetched = jose::unexpected(response.error());
#if JOSE_FETCHER_EXCEPTIONS
    } catch (...) {
        // Release the waiters here rather than from the guard's destructor
        // during unwinding, then pass the exception on.
        (void)guard->finish(abandoned());
        throw;
    }
#endif
    co_return guard->finish(std::move(*fetched));
}

} // namespace jose::optional
