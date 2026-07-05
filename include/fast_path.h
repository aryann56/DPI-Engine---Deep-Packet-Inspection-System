#pragma once

#include "types.h"
#include <unordered_map>

// ============================================================
// FastPathCache - per-worker decision cache.
//
// The first few packets of a flow go through the "slow path": full
// header parse + SNI/HTTP-Host extraction + rule matching. Once a
// flow is classified, every later packet of that same flow can skip
// straight to the cached decision - this is the "fast path".
//
// LoadBalancer pins each FiveTuple to exactly one worker thread, so
// each worker can own its own FastPathCache with NO locking at all -
// it's only ever touched by the single thread that owns it.
// ============================================================
struct FastPathDecision {
    bool classified   = false;  // SNI/app type already determined?
    AppType app_type  = AppType::UNKNOWN;
    bool rule_checked = false;  // have we run RuleManager on this flow yet?
    bool blocked      = false;  // cached rule verdict
};

class FastPathCache {
public:
    // Returns a pointer to the cached decision for `tuple`, or nullptr
    // if this worker hasn't seen this flow before (i.e. take the slow path).
    FastPathDecision* lookup(const FiveTuple& tuple) {
        auto it = cache_.find(tuple);
        return it == cache_.end() ? nullptr : &it->second;
    }

    // Gets-or-creates the decision slot for `tuple`.
    FastPathDecision& getOrCreate(const FiveTuple& tuple) {
        return cache_[tuple];
    }

    void clear() { cache_.clear(); }
    size_t size() const { return cache_.size(); }

private:
    std::unordered_map<FiveTuple, FastPathDecision, FiveTupleHash> cache_;
};
