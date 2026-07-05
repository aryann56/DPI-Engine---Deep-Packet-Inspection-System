#pragma once

#include "types.h"
#include "rule_manager.h"
#include "connection_tracker.h"
#include "load_balancer.h"
#include "fast_path.h"

#include <string>
#include <vector>
#include <thread>
#include <atomic>

// ============================================================
// DpiEngine - multi-threaded deep packet inspection pipeline.
//
// Pipeline:
//   [capture thread] reads the pcap file, parses just enough of each
//   packet to get its FiveTuple, then hands the raw bytes to the
//   LoadBalancer, which pins the packet to one of N worker queues
//   by hashing the flow tuple (so one flow always -> one worker).
//
//   [worker threads] each pull jobs from their own queue. The first
//   packet of a flow takes the "slow path" (full parse + SNI/HTTP-Host
//   extraction + rule check via RuleManager); every later packet on
//   that flow reuses the cached FastPathDecision instead.
//
// ConnectionTracker is the single shared, mutex-protected place where
// final flow stats/classifications land, so the main thread can print
// a report once every worker has drained its queue.
//
// Implementation lives in src/dpi_mt.cpp (declarations only here).
// ============================================================
class DpiEngine {
public:
    explicit DpiEngine(size_t num_workers = std::thread::hardware_concurrency());

    // Loads block rules from a config file (see RuleManager for format).
    // Safe to skip - with zero rules loaded, nothing gets blocked.
    bool loadRules(const std::string& rules_file);

    // Runs the full pipeline against a pcap file: spins up worker
    // threads, reads+dispatches every packet, then joins all workers.
    // Blocks until the whole file has been processed.
    // Returns false if the pcap file couldn't be opened.
    bool run(const std::string& pcap_file);

    // Prints a summary report (flows, apps, block verdicts) built
    // from what's accumulated in the ConnectionTracker.
    void printReport() const;

    uint64_t totalPackets() const { return total_packets_.load(); }
    uint64_t totalBytes()   const { return total_bytes_.load(); }
    uint64_t blockedPackets() const { return blocked_packets_.load(); }
    size_t   totalFlows()   const { return tracker_.size(); }

private:
    void workerLoop(size_t worker_idx);

    size_t num_workers_;
    LoadBalancer balancer_;
    RuleManager rules_;
    ConnectionTracker tracker_;
    std::vector<FastPathCache> worker_caches_; // one cache per worker, no locking needed
    std::vector<std::thread> workers_;

    std::atomic<uint64_t> total_packets_{0};
    std::atomic<uint64_t> total_bytes_{0};
    std::atomic<uint64_t> blocked_packets_{0};
};
