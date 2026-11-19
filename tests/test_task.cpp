#include <catch2/catch_test_macros.hpp>

#include "jose/jose.hpp"

#include <atomic>
#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace jose;

namespace {

// Counts live instances, to check that results and frames are destroyed.
struct tracked {
    static inline int live = 0;
    int value;
    explicit tracked(int v) : value(v) { ++live; }
    tracked(tracked&& o) noexcept : value(o.value) { ++live; }
    tracked(const tracked&) = delete;
    tracked& operator=(const tracked&) = delete;
    tracked& operator=(tracked&&) = delete;
    ~tracked() { --live; }
};

// Not default-constructible, like expected<jwk>.
struct no_default {
    explicit no_default(int v) : value(v) {}
    int value;
};

auto answer() -> task<int> {
    co_return 42;
}

auto add(int a, int b) -> task<int> {
    co_return co_await answer() + a + b - 42;
}

auto nothing(int& counter) -> task<> {
    ++counter;
    co_return;
}

auto make_tracked(int v) -> task<tracked> {
    co_return tracked(v);
}

auto make_unique(int v) -> task<std::unique_ptr<int>> {
    co_return std::make_unique<int>(v);
}

auto make_expected(bool ok) -> task<expected<no_default>> {
    if (ok) co_return no_default(7);
    co_return make_error(errc::key_unavailable, "offline");
}

auto throws() -> task<int> {
    throw std::runtime_error("boom");
    co_return 0;
}

auto rethrows() -> task<std::string> {
    try {
        co_await throws();
    } catch (const std::runtime_error& e) {
        co_return std::string("caught ") + e.what();
    }
    co_return "not reached";
}

auto sum_sync(int n) -> task<long> {
    long total = 0;
    for (int i = 0; i < n; ++i) total += co_await answer();
    co_return total;
}

auto depth(int n) -> task<int> {
    if (n == 0) co_return 0;
    co_return 1 + co_await depth(n - 1);
}

// An awaitable that completes on another thread, like a network call.
struct on_other_thread {
    std::thread* worker;
    std::thread::id resumed_on{};

    auto await_ready() const noexcept -> bool { return false; }
    auto await_suspend(std::coroutine_handle<> h) -> void {
        *worker = std::thread([h] {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            h.resume();
        });
    }
    auto await_resume() -> std::thread::id { return std::this_thread::get_id(); }
};

auto remote_call(std::thread& worker) -> task<std::thread::id> {
    co_return co_await on_other_thread{&worker};
}

auto chain_remote(std::thread& worker) -> task<std::thread::id> {
    auto id = co_await remote_call(worker);
    co_return id; // resumed on the worker thread
}

} // namespace

TEST_CASE("task returns values", "[task]") {
    CHECK(sync_wait(answer()) == 42);
    CHECK(sync_wait(add(1, 2)) == 3);

    int counter = 0;
    sync_wait(nothing(counter));
    CHECK(counter == 1);

    auto p = sync_wait(make_unique(5));
    REQUIRE(p);
    CHECK(*p == 5);

    auto ok = sync_wait(make_expected(true));
    REQUIRE(ok);
    CHECK(ok->value == 7);
    auto bad = sync_wait(make_expected(false));
    REQUIRE_FALSE(bad);
    CHECK(bad.error().code == errc::key_unavailable);
}

TEST_CASE("task is lazy and cleans up", "[task]") {
    int counter = 0;
    {
        auto t = nothing(counter);
        CHECK(t.valid());
        CHECK_FALSE(t.is_ready());
        CHECK(counter == 0); // not started
    }
    CHECK(counter == 0); // destroyed without running

    {
        auto t = make_tracked(1);
        CHECK(tracked::live == 0); // body hasn't run
        CHECK(sync_wait(std::move(t)).value == 1);
    }
    CHECK(tracked::live == 0);

    SECTION("move assignment destroys the old task") {
        auto a = nothing(counter);
        auto b = nothing(counter);
        a = std::move(b);
        CHECK_FALSE(b.valid()); // NOLINT(bugprone-use-after-move)
        sync_wait(std::move(a));
        CHECK(counter == 1);
    }
    SECTION("the moved-from result lives until its task is destroyed") {
        auto outer = []() -> task<int> {
            int during = 0;
            {
                auto inner = make_tracked(3);
                co_await inner; // the result is moved out and the temporary dies...
                during = tracked::live; // ...leaving the moved-from value in inner's frame
            }
            co_return during * 10 + tracked::live;
        };
        CHECK(sync_wait(outer()) == 10);
        CHECK(tracked::live == 0);
    }
}

TEST_CASE("task propagates exceptions", "[task]") {
    CHECK_THROWS_AS(sync_wait(throws()), std::runtime_error);
    CHECK(sync_wait(rethrows()) == "caught boom");
}

TEST_CASE("task loops run in constant stack", "[task]") {
    // A million synchronous co_awaits: each would nest a resume() call if
    // the awaiter were resumed from inside the finished task.
    CHECK(sync_wait(sum_sync(1'000'000)) == 42'000'000L);
    // Recursion uses stack like ordinary recursion.
    CHECK(sync_wait(depth(1'000)) == 1'000);
}

TEST_CASE("task resumes on the thread that completes it", "[task]") {
    std::thread worker;
    const auto resumed_on = sync_wait(chain_remote(worker));
    const auto worker_id = worker.get_id();
    worker.join();
    CHECK(resumed_on == worker_id);
    CHECK(resumed_on != std::this_thread::get_id());
}

TEST_CASE("sync_wait works from many threads at once", "[task]") {
    std::atomic<int> total{0};
    std::vector<std::thread> threads;
    for (int i = 0; i < 8; ++i)
        threads.emplace_back([&total, i] {
            for (int j = 0; j < 1000; ++j) total += sync_wait(add(i, j)) - i - j;
        });
    for (auto& t : threads) t.join();
    CHECK(total == 0);
}
