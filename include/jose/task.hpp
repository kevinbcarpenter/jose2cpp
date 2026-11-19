#pragma once

/// @file
/// jose::task<T>: a minimal lazy coroutine type, header-only and with no
/// dependencies beyond the standard library (PLAN.md §8).
///
/// It exists for the library's few I/O-bound extension points: async
/// opaque signers and key decrypters (HSMs and KMSs over the network) and
/// the JWKS fetcher. The core crypto stays synchronous.
///
/// @code{.cpp}
/// auto fetch_key(kms_client& kms) -> jose::task<jose::expected<jose::jwk>> {
///     auto pem = co_await kms.get_public_key();       // any awaitable
///     co_return jose::jwk::from_pem(pem);
/// }
///
/// auto use_it(kms_client& kms) -> jose::task<void> {
///     auto key = co_await fetch_key(kms);             // tasks compose
///     ...
/// }
///
/// jose::sync_wait(use_it(kms));                       // drive from plain code
/// @endcode
///
/// Semantics:
/// - Lazy: the body doesn't run until the task is awaited (or passed to
///   sync_wait). Discarding an unawaited task destroys it without running it.
/// - Single consumer and move-only: a task is awaited at most once, and
///   co_await moves the result out.
/// - Awaiting resumes the awaiter on whichever thread the task finishes on;
///   task never schedules or switches threads itself.
/// - Stack use: a loop awaiting tasks that finish synchronously runs in
///   constant stack on every compiler and optimization level. (This doesn't
///   rely on symmetric transfer, which GCC doesn't compile to a tail call at
///   -O0 or under sanitizers; an atomic flag decides who continues instead,
///   as in cppcoro.) Recursion through co_await uses stack like ordinary
///   recursion.
/// - An exception escaping the body is rethrown by co_await (or sync_wait).
///   Built with -fno-exceptions, it terminates instead.

#include <atomic>
#include <condition_variable>
#include <coroutine>
#include <exception>
#include <memory>
#include <mutex>
#include <new>
#include <type_traits>
#include <utility>

namespace jose {

template <typename T = void>
class task;

namespace detail {

/// Who continues when a task finishes: the task and its awaiter each set
/// `done_` when they reach the hand-off point (the end of the body, and the
/// end of await_suspend), and whichever gets there second resumes the
/// awaiter. A task that finished synchronously therefore returns straight
/// into the awaiter's await_suspend, which declines to suspend, and no
/// stack builds up across a loop.
class task_promise_base {
public:
    struct final_awaiter {
        [[nodiscard]] auto await_ready() const noexcept -> bool { return false; }
        template <typename Promise>
        auto await_suspend(std::coroutine_handle<Promise> self) const noexcept -> void {
            auto& p = self.promise();
            // Reading continuation_ first: once resumed, the awaiter may
            // destroy this frame.
            const auto continuation = p.continuation_;
            if (p.done_.exchange(true, std::memory_order_acq_rel)) continuation.resume();
        }
        auto await_resume() const noexcept -> void {}
    };

    [[nodiscard]] auto initial_suspend() const noexcept -> std::suspend_always { return {}; }
    [[nodiscard]] auto final_suspend() const noexcept -> final_awaiter { return {}; }

    auto unhandled_exception() noexcept -> void {
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        exception_ = std::current_exception();
#else
        std::terminate();
#endif
    }

    /// Called by the awaiter: starts the task and returns true if the
    /// awaiter must suspend (the task is still running elsewhere).
    template <typename Promise>
    static auto start(std::coroutine_handle<Promise> task, std::coroutine_handle<> awaiting) noexcept -> bool {
        auto& p = task.promise();
        p.continuation_ = awaiting;
        task.resume();
        return !p.done_.exchange(true, std::memory_order_acq_rel);
    }

protected:
    auto rethrow_if_failed() -> void {
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        if (exception_) std::rethrow_exception(exception_);
#endif
    }

private:
    std::coroutine_handle<> continuation_;
    std::atomic<bool> done_{false};
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
    std::exception_ptr exception_;
#endif
};

template <typename T>
class task_promise final : public task_promise_base {
public:
    task_promise() noexcept {}
    task_promise(const task_promise&) = delete;
    task_promise& operator=(const task_promise&) = delete;
    ~task_promise() {
        if (has_value_) std::destroy_at(std::addressof(value_));
    }

    auto get_return_object() noexcept -> task<T>;

    template <typename U = T>
        requires std::is_constructible_v<T, U&&>
    auto return_value(U&& v) noexcept(std::is_nothrow_constructible_v<T, U&&>) -> void {
        std::construct_at(std::addressof(value_), std::forward<U>(v));
        has_value_ = true;
    }

    /// The result, moved out (single consumer).
    auto take() -> T {
        rethrow_if_failed();
        return std::move(value_);
    }

private:
    /// A union, so T needn't be default-constructible (expected<jwk> isn't).
    union {
        T value_;
    };
    bool has_value_ = false;
};

template <>
class task_promise<void> final : public task_promise_base {
public:
    auto get_return_object() noexcept -> task<void>;
    auto return_void() noexcept -> void {}
    auto take() -> void { rethrow_if_failed(); }
};

} // namespace detail

/// A lazy, move-only coroutine returning `T`. See the top of task.hpp for
/// the semantics and an example.
template <typename T>
class [[nodiscard]] task {
    static_assert(!std::is_reference_v<T>, "task<T&> is not supported; return a pointer or reference_wrapper");

public:
    using promise_type = detail::task_promise<T>; ///< for the compiler's coroutine machinery
    using value_type = T;                         ///< what co_await yields

    task() noexcept = default; ///< an invalid task, for assigning to later
    /// Moves the coroutine; `other` becomes invalid. Assigning destroys the
    /// coroutine this task held, without running it if it never started.
    ///@{
    task(task&& other) noexcept : handle_(std::exchange(other.handle_, {})) {}
    task& operator=(task&& other) noexcept {
        if (this != &other) {
            destroy();
            handle_ = std::exchange(other.handle_, {});
        }
        return *this;
    }
    ///@}
    task(const task&) = delete;
    task& operator=(const task&) = delete;
    ~task() { destroy(); } ///< destroys the coroutine frame

    /// false for a default-constructed or moved-from task.
    [[nodiscard]] auto valid() const noexcept -> bool { return static_cast<bool>(handle_); }
    /// The body has finished (only after it has been awaited).
    [[nodiscard]] auto is_ready() const noexcept -> bool { return handle_ && handle_.done(); }

    /// Starts the task and suspends the awaiter until it finishes; yields the
    /// co_returned value (moved out) or rethrows its exception. Awaiting an
    /// invalid task is undefined behaviour, as is awaiting one twice.
    ///@{
    auto operator co_await() & noexcept { return awaiter{handle_}; }
    auto operator co_await() && noexcept { return awaiter{handle_}; }
    ///@}

private:
    friend class detail::task_promise<T>;
    explicit task(std::coroutine_handle<promise_type> h) noexcept : handle_(h) {}

    struct awaiter {
        std::coroutine_handle<promise_type> handle;

        [[nodiscard]] auto await_ready() const noexcept -> bool { return handle.done(); }
        /// Runs the task's body now, on this thread, until it finishes or
        /// suspends on something else.
        auto await_suspend(std::coroutine_handle<> awaiting) noexcept -> bool {
            return detail::task_promise_base::start(handle, awaiting);
        }
        auto await_resume() -> T { return handle.promise().take(); }
    };

    auto destroy() noexcept -> void {
        if (handle_) handle_.destroy();
        handle_ = {};
    }

    std::coroutine_handle<promise_type> handle_;
};

namespace detail {

template <typename T>
auto task_promise<T>::get_return_object() noexcept -> task<T> {
    return task<T>(std::coroutine_handle<task_promise>::from_promise(*this));
}

inline auto task_promise<void>::get_return_object() noexcept -> task<void> {
    return task<void>(std::coroutine_handle<task_promise>::from_promise(*this));
}

// --- sync_wait plumbing ---

/// One-shot event; set() may come from any thread.
class sync_wait_event {
public:
    auto set() noexcept -> void {
        std::lock_guard lock(mutex_);
        set_ = true;
        cv_.notify_one(); // under the lock: wait() can't return (and destroy us) first
    }
    auto wait() -> void {
        std::unique_lock lock(mutex_);
        cv_.wait(lock, [this] { return set_; });
    }

private:
    std::mutex mutex_;
    std::condition_variable cv_;
    bool set_ = false;
};

/// A driver coroutine: runs eagerly once started, signals the event when it
/// finishes, and is destroyed by sync_wait.
class sync_wait_driver {
public:
    struct promise_type {
        sync_wait_event* event = nullptr;
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        std::exception_ptr exception;
#endif

        auto get_return_object() noexcept -> sync_wait_driver {
            return sync_wait_driver(std::coroutine_handle<promise_type>::from_promise(*this));
        }
        [[nodiscard]] auto initial_suspend() const noexcept -> std::suspend_always { return {}; }
        [[nodiscard]] auto final_suspend() const noexcept {
            struct signal {
                [[nodiscard]] auto await_ready() const noexcept -> bool { return false; }
                auto await_suspend(std::coroutine_handle<promise_type> self) const noexcept -> void {
                    self.promise().event->set(); // the frame is suspended; sync_wait destroys it
                }
                auto await_resume() const noexcept -> void {}
            };
            return signal{};
        }
        auto return_void() noexcept -> void {}
        auto unhandled_exception() noexcept -> void {
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
            exception = std::current_exception();
#else
            std::terminate();
#endif
        }
    };

    sync_wait_driver(sync_wait_driver&& other) noexcept : handle_(std::exchange(other.handle_, {})) {}
    sync_wait_driver(const sync_wait_driver&) = delete;
    sync_wait_driver& operator=(const sync_wait_driver&) = delete;
    sync_wait_driver& operator=(sync_wait_driver&&) = delete;
    ~sync_wait_driver() {
        if (handle_) handle_.destroy();
    }

    auto run() -> void {
        sync_wait_event event;
        handle_.promise().event = &event;
        handle_.resume();
        event.wait();
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        if (auto e = handle_.promise().exception) std::rethrow_exception(e);
#endif
    }

private:
    explicit sync_wait_driver(std::coroutine_handle<promise_type> h) noexcept : handle_(h) {}
    std::coroutine_handle<promise_type> handle_;
};

/// Stores the result in a union so T needn't be default-constructible.
template <typename T>
class sync_wait_slot {
public:
    sync_wait_slot() noexcept {}
    sync_wait_slot(const sync_wait_slot&) = delete;
    sync_wait_slot& operator=(const sync_wait_slot&) = delete;
    ~sync_wait_slot() {
        if (full_) std::destroy_at(std::addressof(value_));
    }
    auto emplace(T&& v) -> void {
        std::construct_at(std::addressof(value_), std::move(v));
        full_ = true;
    }
    auto take() -> T { return std::move(value_); }

private:
    union {
        T value_;
    };
    bool full_ = false;
};

template <typename T>
auto sync_wait_body(task<T>& t, sync_wait_slot<T>& out) -> sync_wait_driver {
    out.emplace(co_await t);
}

inline auto sync_wait_body(task<void>& t) -> sync_wait_driver {
    co_await t;
}

} // namespace detail

/// Runs `t` to completion, blocking the calling thread until it finishes
/// (on this thread or any other), and returns its result or rethrows its
/// exception. For use from code that isn't a coroutine: main(), tests,
/// synchronous wrappers. Don't call it from inside an event loop the task
/// itself needs, or it will wait forever.
template <typename T>
auto sync_wait(task<T> t) -> T {
    if constexpr (std::is_void_v<T>) {
        detail::sync_wait_body(t).run();
    } else {
        detail::sync_wait_slot<T> out;
        detail::sync_wait_body(t, out).run();
        return out.take();
    }
}

} // namespace jose
