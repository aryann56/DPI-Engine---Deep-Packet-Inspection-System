// Multi-threaded DPI engine: capture thread reads + dispatches packets,
// N worker threads each own a lock-free FastPathCache and do the actual
// parsing/classification/blocking, ConnectionTracker collects results.
//
// Build:  g++ -std=c++17 -O2 -pthread -Iinclude \
//             src/types.cpp src/pcap_reader.cpp src/packet_parser.cpp \
//             src/sni_extractor.cpp src/dpi_mt.cpp -o dpi_mt
// Run:    ./dpi_mt capture.pcap [rules.txt] [num_workers]

#include "dpi_engine.h"
#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"

#include <iostream>
#include <iomanip>
#include <algorithm>
#include <string>

namespace {

// Attempts to pull an SNI/Host out of `pkt` and classify the flow.
// No-op if `decision` is already classified, or there's no payload to
// look at. On success, updates both the per-worker decision and the
// shared ConnectionTracker.
void tryClassify(const ParsedPacket& pkt, const FiveTuple& tuple,
                  FastPathDecision& decision, ConnectionTracker& tracker,
                  const RuleManager& rules) {
    if (decision.classified) return;
    if (!pkt.has_tcp || pkt.payload == nullptr || pkt.payload_length == 0) return;

    std::string sni;
    bool found = SniExtractor::extractTlsSni(pkt.payload, pkt.payload_length, sni);
    if (!found) {
        found = SniExtractor::extractHttpHost(pkt.payload, pkt.payload_length, sni);
    }
    if (!found) return;

    decision.app_type  = sniToAppType(sni);
    decision.classified = true;
    tracker.setClassification(tuple, sni, decision.app_type);

    Flow probe;
    probe.tuple    = tuple;
    probe.sni      = sni;
    probe.app_type = decision.app_type;
    decision.blocked      = rules.shouldBlock(probe);
    decision.rule_checked = true;
    if (decision.blocked) {
        tracker.setBlocked(tuple, true);
    }
}

} // namespace

// ============================================================
// DpiEngine implementation
// ============================================================
DpiEngine::DpiEngine(size_t num_workers)
    : num_workers_(num_workers == 0 ? 4 : num_workers),
      balancer_(num_workers_),
      worker_caches_(num_workers_) {}

bool DpiEngine::loadRules(const std::string& rules_file) {
    return rules_.loadFromFile(rules_file);
}

void DpiEngine::workerLoop(size_t worker_idx) {
    ThreadSafeQueue<PacketJob>& queue = balancer_.queueFor(worker_idx);
    FastPathCache& cache = worker_caches_[worker_idx];

    while (auto job = queue.pop()) {
        ParsedPacket pkt;
        if (!PacketParser::parse(job->data.data(), job->data.size(), pkt)) {
            continue; // couldn't even parse Ethernet, drop
        }
        if (!pkt.has_ip || !(pkt.has_tcp || pkt.has_udp)) {
            continue; // nothing classifiable here
        }

        FiveTuple tuple{};
        tuple.src_ip   = ipStringToUint32(pkt.src_ip);
        tuple.dst_ip   = ipStringToUint32(pkt.dest_ip);
        tuple.src_port = pkt.src_port;
        tuple.dst_port = pkt.dest_port;
        tuple.protocol = pkt.protocol;

        tracker_.recordPacket(tuple, job->orig_len);

        // getOrCreate: first packet of a flow makes a fresh (unclassified)
        // decision here - that's the "slow path" moment. Every later packet
        // for the same tuple gets the same slot back instantly - "fast path".
        FastPathDecision& decision = cache.getOrCreate(tuple);
        tryClassify(pkt, tuple, decision, tracker_, rules_);

        if (decision.blocked) {
            blocked_packets_.fetch_add(1, std::memory_order_relaxed);
        }
    }
}

bool DpiEngine::run(const std::string& pcap_file) {
    PcapReader reader;
    if (!reader.open(pcap_file)) {
        return false;
    }

    workers_.reserve(num_workers_);
    for (size_t i = 0; i < num_workers_; ++i) {
        workers_.emplace_back(&DpiEngine::workerLoop, this, i);
    }

    std::vector<uint8_t> raw_data;
    PcapRecordHeader record_header{};

    while (reader.readNextPacket(raw_data, record_header)) {
        total_packets_.fetch_add(1, std::memory_order_relaxed);
        total_bytes_.fetch_add(record_header.orig_len, std::memory_order_relaxed);

        // A light parse here just to get the FiveTuple for routing -
        // the worker thread will parse again for the real work. This
        // repeat cost buys us "same flow always same thread", which is
        // what keeps ConnectionTracker/FastPathCache race-free.
        ParsedPacket pkt;
        if (!PacketParser::parse(raw_data.data(), raw_data.size(), pkt) ||
            !pkt.has_ip || !(pkt.has_tcp || pkt.has_udp)) {
            continue; // not classifiable, don't bother a worker with it
        }

        FiveTuple tuple{};
        tuple.src_ip   = ipStringToUint32(pkt.src_ip);
        tuple.dst_ip   = ipStringToUint32(pkt.dest_ip);
        tuple.src_port = pkt.src_port;
        tuple.dst_port = pkt.dest_port;
        tuple.protocol = pkt.protocol;

        PacketJob job;
        job.data     = raw_data; // copy: raw_data gets reused next loop iteration
        job.orig_len = record_header.orig_len;

        balancer_.dispatch(tuple, std::move(job));
    }

    reader.close();
    balancer_.shutdownAll();

    for (auto& t : workers_) {
        if (t.joinable()) t.join();
    }
    workers_.clear();

    return true;
}

void DpiEngine::printReport() const {
    std::vector<Flow> flows = tracker_.snapshot();
    std::sort(flows.begin(), flows.end(),
              [](const Flow& a, const Flow& b) { return a.byte_count > b.byte_count; });

    std::cout << "==================================================\n";
    std::cout << " DPI Report (multi-threaded, " << num_workers_ << " workers)\n";
    std::cout << "==================================================\n";
    std::cout << "Total packets : " << total_packets_.load() << "\n";
    std::cout << "Total bytes   : " << total_bytes_.load() << "\n";
    std::cout << "Total flows   : " << flows.size() << "\n";
    std::cout << "Blocked pkts  : " << blocked_packets_.load() << "\n\n";

    std::cout << std::left
              << std::setw(22) << "SRC IP:PORT"
              << std::setw(22) << "DST IP:PORT"
              << std::setw(8)  << "PROTO"
              << std::setw(10) << "PACKETS"
              << std::setw(28) << "SNI / HOST"
              << std::setw(12) << "APP"
              << "STATUS\n";
    std::cout << std::string(112, '-') << "\n";

    for (const auto& flow : flows) {
        std::string src = ipUint32ToString(flow.tuple.src_ip) + ":" + std::to_string(flow.tuple.src_port);
        std::string dst = ipUint32ToString(flow.tuple.dst_ip) + ":" + std::to_string(flow.tuple.dst_port);
        std::string proto = (flow.tuple.protocol == IP_PROTO_TCP) ? "TCP" : "UDP";

        std::cout << std::left
                  << std::setw(22) << src
                  << std::setw(22) << dst
                  << std::setw(8)  << proto
                  << std::setw(10) << flow.packet_count
                  << std::setw(28) << (flow.sni.empty() ? "-" : flow.sni)
                  << std::setw(12) << appTypeToString(flow.app_type)
                  << (flow.blocked ? "BLOCKED" : "allowed") << "\n";
    }
}

// ============================================================
// main - CLI entry point
// ============================================================
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <capture.pcap> [rules.txt] [num_workers]\n";
        return 1;
    }

    std::string pcap_file  = argv[1];
    std::string rules_file = (argc >= 3) ? argv[2] : "";
    size_t num_workers = (argc >= 4)
        ? static_cast<size_t>(std::stoul(argv[3]))
        : std::thread::hardware_concurrency();

    DpiEngine engine(num_workers);

    if (!rules_file.empty()) {
        if (!engine.loadRules(rules_file)) {
            std::cerr << "Warning: could not load rules file '" << rules_file
                      << "' - continuing with no block rules\n";
        }
    }

    if (!engine.run(pcap_file)) {
        std::cerr << "Error: could not open pcap file: " << pcap_file << "\n";
        return 1;
    }

    engine.printReport();
    return 0;
}
