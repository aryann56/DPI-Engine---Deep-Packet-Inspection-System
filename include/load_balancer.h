#pragma once

#include "types.h"
#include "thread_safe_queue.h"
#include <vector>
#include <cstdint>

// ============================================================
// PacketJob - one unit of work handed to a worker thread: the raw
// captured bytes plus its original-on-wire length (for byte counts).
// ============================================================
struct PacketJob {
    std::vector<uint8_t> data;
    uint32_t orig_len = 0;
};

// ============================================================
// LoadBalancer - decides which worker queue a packet goes to.
//
// Packets belonging to the same flow (FiveTuple) must always land on
// the same worker thread, otherwise two threads could race to create/
// classify the same Flow. So we hash the tuple and mod by worker count
// rather than round-robin - same flow always -> same queue.
// ============================================================
class LoadBalancer {
public:
    explicit LoadBalancer(size_t worker_count)
        : queues_(worker_count > 0 ? worker_count : 1) {}

    // Returns which worker index a given flow tuple is pinned to.
    size_t workerFor(const FiveTuple& tuple) const {
        return FiveTupleHash{}(tuple) % queues_.size();
    }

    // Pushes a job onto the queue owned by the worker responsible
    // for this tuple's flow.
    void dispatch(const FiveTuple& tuple, PacketJob job) {
        size_t idx = workerFor(tuple);
        queues_[idx].push(std::move(job));
    }

    // Pushes a job onto an explicit worker index (used for packets
    // that couldn't be parsed into a tuple, e.g. round-robin fallback).
    void dispatchToWorker(size_t worker_idx, PacketJob job) {
        queues_[worker_idx % queues_.size()].push(std::move(job));
    }

    ThreadSafeQueue<PacketJob>& queueFor(size_t worker_idx) {
        return queues_[worker_idx % queues_.size()];
    }

    size_t workerCount() const { return queues_.size(); }

    // Signals every worker queue to shut down (called once capture is done).
    void shutdownAll() {
        for (auto& q : queues_) {
            q.shutdown();
        }
    }

private:
    std::vector<ThreadSafeQueue<PacketJob>> queues_;
};
