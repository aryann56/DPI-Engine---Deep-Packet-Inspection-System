#pragma once

#include "types.h"
#include <unordered_map>
#include <vector>
#include <mutex>
#include <string>

// ============================================================
// ConnectionTracker - thread-safe table of active flows.
// Multiple worker threads call recordPacket()/setClassification()
// concurrently as they process packets in parallel; one mutex
// protects the underlying map. Header-only, same reasoning as
// rule_manager.h (inline members, no separate .cpp needed).
// ============================================================
class ConnectionTracker {
public:
    ConnectionTracker() = default;

    // Records one packet belonging to `tuple`, creating a new Flow
    // entry the first time a tuple is seen.
    void recordPacket(const FiveTuple& tuple, uint64_t packet_bytes) {
        std::lock_guard<std::mutex> lock(mutex_);
        Flow& flow = flows_[tuple];
        flow.tuple = tuple;
        flow.packet_count++;
        flow.byte_count += packet_bytes;
    }

    // True if this tuple already has a non-empty SNI recorded, so
    // callers can skip re-parsing TLS/HTTP for already-classified flows.
    bool hasSni(const FiveTuple& tuple) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = flows_.find(tuple);
        return it != flows_.end() && !it->second.sni.empty();
    }

    // Records the SNI/app classification for a flow. First writer wins
    // (later packets on the same flow won't overwrite an existing SNI).
    void setClassification(const FiveTuple& tuple, const std::string& sni, AppType app_type) {
        std::lock_guard<std::mutex> lock(mutex_);
        Flow& flow = flows_[tuple];
        flow.tuple = tuple;
        if (flow.sni.empty()) {
            flow.sni = sni;
            flow.app_type = app_type;
        }
    }

    void setBlocked(const FiveTuple& tuple, bool blocked) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = flows_.find(tuple);
        if (it != flows_.end()) {
            it->second.blocked = blocked;
        }
    }

    // Snapshot copy of every tracked flow - safe to iterate without
    // holding the lock (e.g. while printing a report on the main thread).
    std::vector<Flow> snapshot() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<Flow> result;
        result.reserve(flows_.size());
        for (const auto& kv : flows_) {
            result.push_back(kv.second);
        }
        return result;
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return flows_.size();
    }

private:
    mutable std::mutex mutex_;
    std::unordered_map<FiveTuple, Flow, FiveTupleHash> flows_;
};
