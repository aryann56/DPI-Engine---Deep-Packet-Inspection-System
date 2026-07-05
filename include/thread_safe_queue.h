#pragma once

#include <queue>
#include <mutex>
#include <condition_variable>
#include <optional>
#include <utility>

// ============================================================
// ThreadSafeQueue<T> - generic producer/consumer queue.
// Used to hand packets from the capture/dispatch thread to the
// worker threads that parse + classify them (see dpi_mt.cpp).
// ============================================================
template <typename T>
class ThreadSafeQueue {
public:
    ThreadSafeQueue() = default;

    // Push an item and wake exactly one waiting consumer.
    void push(T item) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            queue_.push(std::move(item));
        }
        cv_.notify_one();
    }

    // Blocking pop. Returns std::nullopt once shutdown() has been
    // called and the queue has been fully drained - this is how
    // worker threads know it's time to exit.
    std::optional<T> pop() {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [this] { return !queue_.empty() || shutdown_; });

        if (queue_.empty()) {
            return std::nullopt;
        }

        T item = std::move(queue_.front());
        queue_.pop();
        return item;
    }

    // Non-blocking pop. Returns false immediately if the queue is empty.
    bool tryPop(T& out) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.empty()) return false;
        out = std::move(queue_.front());
        queue_.pop();
        return true;
    }

    // Wakes every thread blocked in pop() so they can notice shutdown
    // and exit once the queue is empty. Call this once producing is done.
    void shutdown() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            shutdown_ = true;
        }
        cv_.notify_all();
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }

    bool empty() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.empty();
    }

private:
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::queue<T> queue_;
    bool shutdown_ = false;
};
