#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include "jose/jose.hpp"
#include "jose/optional/jwks_fetcher.hpp"

#include <atomic>
#include <chrono>
#include <coroutine>
#include <deque>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace jose;
using namespace std::chrono_literals;
using json = nlohmann::json;
using Catch::Matchers::ContainsSubstring;
using optional::http_request;
using optional::http_response;
using optional::jwks_fetcher;
using optional::jwks_fetcher_config;
using key_set = jwks_fetcher::key_set;
using result = expected<key_set>;

namespace {

// Replies from a queue. With `park` set, each request suspends until
// release(), so tests can line up callers behind a fetch that's running.
struct fake_http final : optional::http_client {
    std::vector<http_request> requests;
    std::deque<expected<http_response>> replies;
    bool park = false;
    std::coroutine_handle<> parked = nullptr;
    bool throw_next = false;
    bool throw_after_park = false;

    struct park_here {
        fake_http& http;
        [[nodiscard]] auto await_ready() const noexcept -> bool { return false; }
        auto await_suspend(std::coroutine_handle<> h) noexcept -> void { http.parked = h; }
        auto await_resume() const noexcept -> void {}
    };

    auto get(http_request request) -> task<expected<http_response>> override {
        requests.push_back(request);
        if (throw_next) {
            throw_next = false;
            throw std::runtime_error("socket exploded");
        }
        if (park) co_await park_here{*this};
        if (throw_after_park) {
            throw_after_park = false;
            throw std::runtime_error("connection reset");
        }
        if (replies.empty()) co_return make_error(errc::key_unavailable, "fake_http: no reply queued");
        auto reply = std::move(replies.front());
        replies.pop_front();
        co_return reply;
    }

    auto release() -> void {
        REQUIRE(parked);
        std::exchange(parked, nullptr).resume();
    }
};

// Runs a task to its first suspension and stores its result when it ends.
struct detached {
    struct promise_type {
        auto get_return_object() noexcept -> detached { return {}; }
        auto initial_suspend() noexcept -> std::suspend_never { return {}; }
        auto final_suspend() noexcept -> std::suspend_never { return {}; }
        auto return_void() noexcept -> void {}
        auto unhandled_exception() noexcept -> void { std::terminate(); }
    };
};

auto start(task<result> t, std::optional<result>& out) -> detached { out = co_await std::move(t); }

// Like detached, but owned: destroying it destroys the suspended chain.
struct owned {
    struct promise_type {
        auto get_return_object() noexcept -> owned {
            return owned{std::coroutine_handle<promise_type>::from_promise(*this)};
        }
        auto initial_suspend() noexcept -> std::suspend_never { return {}; }
        auto final_suspend() noexcept -> std::suspend_always { return {}; }
        auto return_void() noexcept -> void {}
        auto unhandled_exception() noexcept -> void { std::terminate(); }
    };
    explicit owned(std::coroutine_handle<promise_type> handle) : h(handle) {}
    owned(owned&& o) noexcept : h(std::exchange(o.h, nullptr)) {}
    ~owned() {
        if (h) h.destroy();
    }
    std::coroutine_handle<promise_type> h;
};

auto hold(task<result> t, std::optional<result>& out) -> owned { out = co_await std::move(t); }

auto start_logged(task<result> t, std::optional<result>& out, std::vector<int>& log, int id) -> detached {
    out = co_await std::move(t);
    log.push_back(id);
}

auto start_catching(task<result> t, std::optional<result>& out, bool& threw) -> detached {
    try {
        out = co_await std::move(t);
    } catch (const std::runtime_error&) {
        threw = true;
    }
}

// When its wait ends, starts two more refreshes: the first fetches, the
// second waits for that new fetch.
auto then_refresh_twice(task<result> t, std::optional<result>& out, jwks_fetcher& f, std::optional<result>& c,
                        std::optional<result>& d) -> detached {
    out = co_await std::move(t);
    start(f.refresh(), c);
    start(f.refresh(), d);
}

auto make_key(const char* kid) -> jwk {
    auto key = jwk::generate_ec(ec_curve::P256);
    REQUIRE(key);
    key->set_key_id(kid);
    return std::move(*key);
}

auto public_of(const jwk& key) -> jwk {
    auto pub = key.public_key();
    REQUIRE(pub);
    return std::move(*pub);
}

auto jwks_json(const std::vector<jwk>& keys) -> std::string {
    json arr = json::array();
    for (const auto& k : keys) {
        auto j = k.to_json();
        REQUIRE(j);
        arr.push_back(*j);
    }
    return json{{"keys", arr}}.dump();
}

auto ok(std::string body) -> expected<http_response> { return http_response{200, std::move(body)}; }

auto kids(const key_set& set) -> std::vector<std::string> {
    std::vector<std::string> out;
    for (const auto& k : set->keys()) out.push_back(k.key_id().value_or(""));
    return out;
}

template <typename T>
auto code_of(const expected<T>& r) -> errc {
    REQUIRE_FALSE(r.has_value());
    return r.error().code;
}

struct fixture {
    std::chrono::steady_clock::time_point now{std::chrono::hours(1000)};
    fake_http* http = nullptr;
    std::unique_ptr<jwks_fetcher> fetcher;
    jwk k1 = make_key("k1");
    jwk k2 = make_key("k2");

    explicit fixture(jwks_fetcher_config config = {}) {
        if (config.url.empty()) config.url = "https://auth.example.com/.well-known/jwks.json";
        config.clock = [this] { return now; };
        auto client = std::make_unique<fake_http>();
        http = client.get();
        fetcher = std::make_unique<jwks_fetcher>(std::move(config), std::move(client));
    }

    auto keys() -> result { return sync_wait(fetcher->keys()); }
    auto refresh() -> result { return sync_wait(fetcher->refresh()); }
    auto keys_for(std::string kid) -> result { return sync_wait(fetcher->keys_for(std::move(kid))); }
    auto serve(std::vector<jwk> keys) -> void { http->replies.push_back(ok(jwks_json(keys))); }
};

} // namespace

TEST_CASE("jwks_fetcher: config is checked on every call", "[jwks]") {
    const auto bad = [](jwks_fetcher_config c, const char* why) {
        auto client = std::make_unique<fake_http>();
        auto* http = client.get();
        jwks_fetcher f(std::move(c), std::move(client));
        for (auto r : {sync_wait(f.keys()), sync_wait(f.refresh()), sync_wait(f.keys_for("k1"))}) {
            CHECK(code_of(r) == errc::invalid_argument);
            CHECK_THAT(r.error().message, ContainsSubstring(why));
        }
        CHECK(f.cached() == nullptr);
        CHECK(http->requests.empty());
    };
    const std::string url = "https://auth.example.com/jwks";
    bad({}, "https://");
    bad({.url = "http://auth.example.com/jwks"}, "allow_http");
    bad({.url = "ftp://auth.example.com/jwks", .allow_http = true}, "https:// or http://");
    bad({.url = "https://"}, "no host");
    bad({.url = url, .refresh_interval = 0s}, "refresh_interval");
    bad({.url = url, .refresh_interval = std::chrono::seconds::max()}, "refresh_interval");
    bad({.url = url, .min_refresh_interval = -1s}, "min_refresh_interval");
    bad({.url = url, .refresh_interval = 10s, .min_refresh_interval = 11s}, "min_refresh_interval");
    bad({.url = url, .max_stale = -1s}, "max_stale");
    bad({.url = url, .max_stale = std::chrono::seconds::max()}, "max_stale");
    bad({.url = url, .timeout = 0s}, "timeout");
    bad({.url = url, .max_response_bytes = 0}, "max_response_bytes");
    bad({.url = url, .max_keys = 0}, "max_keys");

    jwks_fetcher null_client({.url = url}, nullptr);
    CHECK(code_of(sync_wait(null_client.keys())) == errc::invalid_argument);

    SECTION("edges that are allowed") {
        for (auto c : {jwks_fetcher_config{.url = "HTTPS://auth.example.com/jwks"},
                       jwks_fetcher_config{.url = "http://localhost:8080/jwks", .allow_http = true},
                       jwks_fetcher_config{.url = url, .min_refresh_interval = 0s, .max_stale = 0s},
                       jwks_fetcher_config{.url = url, .refresh_interval = 30s, .min_refresh_interval = 30s}}) {
            fixture fx(c);
            fx.serve({fx.k1});
            CHECK(fx.keys());
        }
    }
}

TEST_CASE("jwks_fetcher: caching and refresh_interval", "[jwks]") {
    fixture fx({.timeout = 7s, .max_response_bytes = 4096});
    CHECK(fx.fetcher->cached() == nullptr);

    fx.serve({public_of(fx.k1)});
    auto first = fx.keys();
    REQUIRE(first);
    REQUIRE(fx.http->requests.size() == 1);
    CHECK(fx.http->requests[0].url == "https://auth.example.com/.well-known/jwks.json");
    CHECK(fx.http->requests[0].timeout == 7s);
    CHECK(fx.http->requests[0].max_response_bytes == 4096);
    CHECK(kids(*first) == std::vector<std::string>{"k1"});
    CHECK(fx.fetcher->cached() == *first);

    fx.now += 299s;
    auto again = fx.keys();
    REQUIRE(again);
    CHECK(*again == *first); // the same set, not a copy
    CHECK(fx.http->requests.size() == 1);

    fx.now += 1s; // 300s old
    fx.serve({public_of(fx.k1), public_of(fx.k2)});
    auto next = fx.keys();
    REQUIRE(next);
    CHECK(fx.http->requests.size() == 2);
    CHECK(kids(*next) == std::vector<std::string>{"k1", "k2"});

    SECTION("refresh() fetches, but not within min_refresh_interval of the last start") {
        fx.now += 29s;
        auto r = fx.refresh();
        REQUIRE(r);
        CHECK(*r == *next);
        CHECK(fx.http->requests.size() == 2);
        fx.now += 1s;
        fx.serve({public_of(fx.k2)});
        r = fx.refresh();
        REQUIRE(r);
        CHECK(kids(*r) == std::vector<std::string>{"k2"});
        CHECK(fx.http->requests.size() == 3);
    }
}

TEST_CASE("jwks_fetcher: what a response must hold", "[jwks]") {
    fixture fx({.max_response_bytes = 2048, .max_keys = 4});
    const auto refused = [&](expected<http_response> reply, errc code, const char* why) {
        fx.http->replies.push_back(std::move(reply));
        auto r = fx.refresh();
        CHECK(code_of(r) == code);
        CHECK_THAT(r.error().message, ContainsSubstring(why));
        fx.now += 30s;
    };
    refused(http_response{404, jwks_json({fx.k1})}, errc::key_unavailable, "HTTP 404");
    refused(http_response{204, ""}, errc::key_unavailable, "HTTP 204");
    refused(ok(std::string(2049, ' ')), errc::invalid_key, "max_response_bytes");
    refused(ok("{\"keys\": ["), errc::invalid_key, "JWKS response");
    refused(ok("[]"), errc::invalid_key, "JWKS response");
    refused(ok("{\"keys\": {}}"), errc::invalid_key, "\"keys\"");
    refused(ok(R"({"keys":[{"kty":"X"},{"kty":"X"},{"kty":"X"},{"kty":"X"},{"kty":"X"}]})"), errc::invalid_key, "max_keys");
    refused(ok(R"({"keys":[]})"), errc::invalid_key, "no usable public key (0 keys");
    // A symmetric key is never kept: anyone who can read the URL could sign with it.
    auto oct = jwk::generate_oct(32);
    REQUIRE(oct);
    oct->set_key_id("k1");
    refused(ok(jwks_json({*oct})), errc::invalid_key, "no usable public key (1 key dropped");
    // http_client's errors pass through unchanged.
    refused(make_error(errc::key_unavailable, "connection refused"), errc::key_unavailable, "connection refused");
    refused(make_error(errc::openssl_error, "TLS handshake"), errc::openssl_error, "TLS handshake");
    CHECK(fx.fetcher->cached() == nullptr);

    SECTION("only public keys are kept") {
        auto rsa = jwk::generate_rsa(2048);
        REQUIRE(rsa);
        rsa->set_key_id("rsa");
        const std::string body = R"({"keys":[)" + *fx.k1.to_json_string() + "," + *oct->to_json_string() +
                                 R"(,{"kty":"XYZ","kid":"odd"},)" + *public_of(*rsa).to_json_string() + "]}";
        fx.http->replies.push_back(ok(body));
        auto r = fx.refresh();
        REQUIRE(r);
        CHECK(kids(*r) == std::vector<std::string>{"k1", "rsa"});
        for (const auto& k : (*r)->keys()) CHECK(k.is_public());
    }
}

TEST_CASE("jwks_fetcher: failed fetches and max_stale", "[jwks]") {
    SECTION("the old set is served until refresh_interval + max_stale") {
        fixture fx({.max_stale = 600s});
        fx.serve({fx.k1});
        auto good = fx.keys();
        REQUIRE(good);

        fx.now += 300s;
        fx.http->replies.push_back(make_error(errc::key_unavailable, "down"));
        auto r = fx.keys();
        REQUIRE(r);
        CHECK(*r == *good);
        CHECK(fx.http->requests.size() == 2);

        // No retry within min_refresh_interval of the failed attempt.
        fx.now += 29s;
        CHECK(fx.keys());
        CHECK(fx.http->requests.size() == 2);

        fx.now += 1s;
        fx.http->replies.push_back(make_error(errc::key_unavailable, "still down"));
        CHECK(fx.keys());
        CHECK(fx.http->requests.size() == 3);
        CHECK(fx.fetcher->cached() == *good);

        fx.now = fx.now - 330s + 900s - 1ns; // just inside 300s + 600s
        fx.http->replies.push_back(make_error(errc::key_unavailable, "still down"));
        CHECK(fx.keys());
        CHECK(fx.fetcher->cached() == *good);

        fx.now += 1ns; // past max_stale: throttled, and the set is no longer served
        r = fx.keys();
        CHECK(code_of(r) == errc::key_unavailable);
        CHECK_THAT(r.error().message, ContainsSubstring("still down"));
        CHECK(fx.fetcher->cached() == nullptr);

        fx.now += 30s;
        fx.serve({fx.k2});
        r = fx.keys();
        REQUIRE(r);
        CHECK(kids(*r) == std::vector<std::string>{"k2"});
    }
    SECTION("with no set yet, the error is returned until a retry is allowed") {
        fixture fx;
        fx.http->replies.push_back(make_error(errc::key_unavailable, "dns"));
        CHECK(code_of(fx.keys()) == errc::key_unavailable);
        auto r = fx.keys();
        CHECK_THAT(r.error().message, ContainsSubstring("dns"));
        CHECK(code_of(fx.keys_for("k1")) == errc::key_unavailable);
        CHECK(fx.http->requests.size() == 1);
        fx.now += 30s;
        fx.serve({fx.k1});
        CHECK(fx.keys());
        CHECK(fx.http->requests.size() == 2);
    }
    SECTION("max_stale = 0 serves nothing past refresh_interval") {
        fixture fx({.max_stale = 0s});
        fx.serve({fx.k1});
        REQUIRE(fx.keys());
        fx.now += 300s;
        fx.http->replies.push_back(make_error(errc::key_unavailable, "down"));
        CHECK(code_of(fx.keys()) == errc::key_unavailable);
    }
}

TEST_CASE("jwks_fetcher: keys_for picks up rotated keys, rate limited", "[jwks]") {
    fixture fx;
    fx.serve({public_of(fx.k1)});
    auto r = fx.keys_for("k1");
    REQUIRE(r);
    CHECK(fx.http->requests.size() == 1);

    // k2 isn't in the set: one fetch, which has it.
    fx.now += 30s;
    fx.serve({public_of(fx.k1), public_of(fx.k2)});
    r = fx.keys_for("k2");
    REQUIRE(r);
    CHECK((*r)->find("k2"));
    CHECK(fx.http->requests.size() == 2);

    // Made-up kids don't cause more fetches until min_refresh_interval passes.
    for (int i = 0; i < 100; ++i) {
        auto miss = fx.keys_for("forged-" + std::to_string(i));
        CHECK(code_of(miss) == errc::invalid_key);
    }
    CHECK(fx.http->requests.size() == 2);
    auto miss = fx.keys_for("nope");
    CHECK_THAT(miss.error().message, ContainsSubstring("\"kid\":\"nope\""));

    fx.now += 30s;
    fx.serve({public_of(fx.k1), public_of(fx.k2)});
    CHECK(code_of(fx.keys_for("nope")) == errc::invalid_key);
    CHECK(fx.http->requests.size() == 3);
    // Known kids still don't fetch.
    CHECK(fx.keys_for("k1"));
    CHECK(fx.http->requests.size() == 3);
}

TEST_CASE("jwks_fetcher: one fetch at a time", "[jwks]") {
    fixture fx;
    fx.http->park = true;

    SECTION("callers with no set wait for the fetch that's running") {
        std::optional<result> a, b, c;
        start(fx.fetcher->keys(), a);
        start(fx.fetcher->keys_for("k1"), b);
        start(fx.fetcher->refresh(), c);
        CHECK(fx.http->requests.size() == 1);
        CHECK_FALSE(a);
        CHECK_FALSE(b);
        CHECK_FALSE(c);
        fx.serve({fx.k1});
        fx.http->release();
        REQUIRE(a);
        REQUIRE(b);
        REQUIRE(c);
        REQUIRE(*a);
        CHECK(**b == **a);
        CHECK(**c == **a);
        CHECK(fx.http->requests.size() == 1);
    }
    SECTION("a failure reaches every waiter") {
        std::optional<result> a, b;
        start(fx.fetcher->keys(), a);
        start(fx.fetcher->keys(), b);
        fx.http->replies.push_back(make_error(errc::key_unavailable, "down"));
        fx.http->release();
        CHECK(code_of(*a) == errc::key_unavailable);
        CHECK(code_of(*b) == errc::key_unavailable);
        CHECK_THAT(b->error().message, ContainsSubstring("down"));
    }
    SECTION("with an old set, keys() doesn't wait but refresh() does") {
        fx.http->park = false;
        fx.serve({fx.k1});
        auto old = fx.keys();
        REQUIRE(old);
        fx.http->park = true;
        fx.now += 300s;
        std::optional<result> a, b, c;
        start(fx.fetcher->keys(), a);
        start(fx.fetcher->keys(), b);
        start(fx.fetcher->refresh(), c);
        CHECK_FALSE(a);
        REQUIRE(b);
        CHECK(**b == *old);
        CHECK_FALSE(c);
        fx.serve({fx.k2});
        fx.http->release();
        REQUIRE(a);
        REQUIRE(c);
        CHECK(kids(**a) == std::vector<std::string>{"k2"});
        CHECK(**c == **a);
        CHECK(fx.http->requests.size() == 2);
    }
    SECTION("an abandoned fetch releases its waiters") {
        std::optional<result> a, b;
        {
            auto fetching = hold(fx.fetcher->keys(), a);
            start(fx.fetcher->keys(), b);
            CHECK_FALSE(b);
            fx.http->parked = nullptr; // destroyed with `fetching`
        }
        CHECK_FALSE(a);
        REQUIRE(b);
        CHECK(code_of(*b) == errc::key_unavailable);
        CHECK_THAT(b->error().message, ContainsSubstring("ended without a result"));

        fx.http->park = false;
        fx.now += 30s;
        fx.serve({fx.k1});
        CHECK(fx.keys());
    }
    SECTION("an exception from http_client goes to the caller that fetched") {
        fx.http->park = false;
        fx.http->throw_next = true;
        CHECK_THROWS_AS(fx.keys(), std::runtime_error);
        auto r = fx.keys(); // throttled: the recorded error
        CHECK_THAT(r.error().message, ContainsSubstring("ended without a result"));
        fx.now += 30s;
        fx.serve({fx.k1});
        CHECK(fx.keys());
    }
    SECTION("an exception after suspending still releases the waiters") {
        fx.http->throw_after_park = true;
        std::optional<result> a, b;
        bool threw = false;
        start_catching(fx.fetcher->keys(), a, threw);
        start(fx.fetcher->keys(), b);
        fx.http->release();
        CHECK(threw);
        CHECK_FALSE(a);
        REQUIRE(b);
        CHECK(code_of(*b) == errc::key_unavailable);
        CHECK_THAT(b->error().message, ContainsSubstring("ended without a result"));
    }
    SECTION("waiters resume in the order they started waiting") {
        std::vector<int> order;
        std::optional<result> a, w1, w2, w3;
        start_logged(fx.fetcher->keys(), a, order, 0);
        start_logged(fx.fetcher->keys(), w1, order, 1);
        start_logged(fx.fetcher->refresh(), w2, order, 2);
        start_logged(fx.fetcher->keys_for("k1"), w3, order, 3);
        fx.serve({fx.k1});
        fx.http->release();
        // The fetching caller finishes last: it hands out the result first.
        CHECK(order == std::vector<int>{1, 2, 3, 0});
    }
    SECTION("a waiting task can be destroyed") {
        std::optional<result> a, b, c;
        start(fx.fetcher->keys(), a);
        {
            auto waiting = hold(fx.fetcher->keys(), b);
        }
        start(fx.fetcher->keys(), c);
        fx.serve({fx.k1});
        fx.http->release();
        REQUIRE(a);
        CHECK(*a);
        CHECK_FALSE(b);
        REQUIRE(c);
        CHECK(*c);
    }
}

TEST_CASE("jwks_fetcher: a waiter that starts the next fetch", "[jwks]") {
    fixture fx({.min_refresh_interval = 0s});
    fx.http->park = true;
    std::optional<result> a, w, late, c, d;
    start(fx.fetcher->keys(), a);
    then_refresh_twice(fx.fetcher->keys(), w, *fx.fetcher, c, d);
    start(fx.fetcher->keys(), late);
    fx.serve({fx.k1});
    fx.http->release();
    // w's continuation started a second fetch (c) and a wait for it (d).
    // `late` waited for the first fetch and gets its result; d must not.
    REQUIRE(w);
    REQUIRE(late);
    CHECK(kids(**late) == std::vector<std::string>{"k1"});
    CHECK_FALSE(c);
    CHECK_FALSE(d);
    CHECK(fx.http->requests.size() == 2);
    fx.serve({fx.k2});
    fx.http->release();
    REQUIRE(c);
    REQUIRE(d);
    CHECK(kids(**d) == std::vector<std::string>{"k2"});
    CHECK(**d == **c);
}

TEST_CASE("jwks_fetcher: verifying JWTs end to end", "[jwks]") {
    fixture fx;
    const auto issue = [](const jwk& key) {
        auto token = jwt::signed_token({signing_algorithm::ES256, key})
                         .claims(jwt::registered_claims{.issuer = "https://auth.example.com"})
                         .serialize();
        REQUIRE(token);
        return *token;
    };
    const auto verify = [&](const std::string& token) -> expected<nlohmann::json> {
        auto parsed = jwt::parse_signed(token, {signing_algorithm::ES256});
        REQUIRE(parsed);
        auto kid = parsed->header().kid();
        REQUIRE(kid);
        auto keys = fx.keys_for(std::string(*kid));
        if (!keys) return jose::unexpected(keys.error());
        return parsed->claims(**keys);
    };

    fx.serve({public_of(fx.k1)});
    auto claims = verify(issue(fx.k1));
    REQUIRE(claims);
    CHECK((*claims)["iss"] == "https://auth.example.com");

    // The provider rotates to k2.
    fx.now += 60s;
    fx.serve({public_of(fx.k1), public_of(fx.k2)});
    CHECK(verify(issue(fx.k2)));
    CHECK(fx.http->requests.size() == 2);

    // A token signed by a key the provider never published.
    auto stranger = make_key("k2");
    CHECK(code_of(verify(issue(stranger))) == errc::invalid_signature);
}

namespace {

// Each request finishes on a new thread; flags overlapping requests.
struct threaded_http final : optional::http_client {
    std::string body;
    std::mutex m;
    std::vector<std::thread> threads;
    std::atomic<int> active{0};
    std::atomic<int> overlaps{0};
    std::atomic<int> count{0};

    struct hop {
        threaded_http& http;
        [[nodiscard]] auto await_ready() const noexcept -> bool { return false; }
        auto await_suspend(std::coroutine_handle<> h) -> void {
            const std::lock_guard lock(http.m);
            http.threads.emplace_back([h] { h.resume(); });
        }
        auto await_resume() const noexcept -> void {}
    };

    ~threaded_http() override {
        for (;;) {
            std::vector<std::thread> done;
            {
                const std::lock_guard lock(m);
                if (threads.empty()) break;
                done.swap(threads);
            }
            for (auto& t : done) t.join();
        }
    }

    auto get(http_request) -> task<expected<http_response>> override {
        if (active.fetch_add(1) != 0) overlaps.fetch_add(1);
        count.fetch_add(1);
        co_await hop{*this};
        active.fetch_sub(1);
        co_return http_response{200, body};
    }
};

} // namespace

TEST_CASE("jwks_fetcher: many threads", "[jwks][async]") {
    auto client = std::make_unique<threaded_http>();
    auto* http = client.get();
    http->body = jwks_json({public_of(make_key("k1"))});
    {
        jwks_fetcher fetcher({.url = "https://auth.example.com/jwks", .min_refresh_interval = 0s}, std::move(client));
        std::atomic<int> failures{0};
        std::vector<std::thread> callers;
        for (int t = 0; t < 8; ++t) {
            callers.emplace_back([&, t] {
                for (int i = 0; i < 100; ++i) {
                    auto r = (i + t) % 3 == 0 ? sync_wait(fetcher.keys_for("k1"))
                             : (i + t) % 3 == 1 ? sync_wait(fetcher.refresh())
                                                : sync_wait(fetcher.keys());
                    if (!r || !(*r)->find("k1")) failures.fetch_add(1);
                }
            });
        }
        for (auto& c : callers) c.join();
        CHECK(failures == 0);
        CHECK(http->overlaps == 0);
        CHECK(http->count >= 1);
        // http_client and its threads go with the fetcher.
    }
}
