// Simple, single-threaded DPI engine.
// Reads a .pcap file, parses each packet, tracks flows, extracts
// SNI/Host, classifies the app, and prints a summary report.
//
// Build:  g++ -std=c++17 -Iinclude src/types.cpp src/pcap_reader.cpp \
//             src/packet_parser.cpp src/sni_extractor.cpp \
//             src/main_working.cpp -o dpi_simple
// Run:    ./dpi_simple capture.pcap

#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "types.h"

#include <iostream>
#include <iomanip>
#include <unordered_map>
#include <vector>
#include <algorithm>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <capture.pcap>\n";
        return 1;
    }

    PcapReader reader;
    if (!reader.open(argv[1])) {
        std::cerr << "Error: could not open pcap file: " << argv[1] << "\n";
        return 1;
    }

    std::unordered_map<FiveTuple, Flow, FiveTupleHash> flows;
    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;

    std::vector<uint8_t> raw_data;
    PcapRecordHeader record_header{};

    while (reader.readNextPacket(raw_data, record_header)) {
        ++total_packets;
        total_bytes += record_header.orig_len;

        ParsedPacket pkt;
        if (!PacketParser::parse(raw_data.data(), raw_data.size(), pkt)) {
            continue; // couldn't parse even the Ethernet header, skip
        }
        if (!pkt.has_ip || !(pkt.has_tcp || pkt.has_udp)) {
            continue; // not an IPv4 TCP/UDP packet, nothing to classify
        }

        FiveTuple tuple{};
        tuple.src_ip   = ipStringToUint32(pkt.src_ip);
        tuple.dst_ip   = ipStringToUint32(pkt.dest_ip);
        tuple.src_port = pkt.src_port;
        tuple.dst_port = pkt.dest_port;
        tuple.protocol = pkt.protocol;

        Flow& flow = flows[tuple]; // creates a new Flow if not seen before
        flow.tuple = tuple;
        flow.packet_count++;
        flow.byte_count += record_header.orig_len;

        // Only bother extracting SNI/Host if we don't already have one
        // for this flow and there is a payload to look at.
        if (flow.sni.empty() && pkt.has_tcp && pkt.payload != nullptr && pkt.payload_length > 0) {
            std::string sni;
            if (SniExtractor::extractTlsSni(pkt.payload, pkt.payload_length, sni)) {
                flow.sni = sni;
            } else if (SniExtractor::extractHttpHost(pkt.payload, pkt.payload_length, sni)) {
                flow.sni = sni;
            }
            if (!flow.sni.empty()) {
                flow.app_type = sniToAppType(flow.sni);
            }
        }
    }

    reader.close();

    // ---------------- Report ----------------
    std::cout << "==================================================\n";
    std::cout << " DPI Report: " << argv[1] << "\n";
    std::cout << "==================================================\n";
    std::cout << "Total packets : " << total_packets << "\n";
    std::cout << "Total bytes   : " << total_bytes << "\n";
    std::cout << "Total flows   : " << flows.size() << "\n\n";

    std::cout << std::left
              << std::setw(22) << "SRC IP:PORT"
              << std::setw(22) << "DST IP:PORT"
              << std::setw(8)  << "PROTO"
              << std::setw(10) << "PACKETS"
              << std::setw(28) << "SNI / HOST"
              << "APP\n";
    std::cout << std::string(100, '-') << "\n";

    // Sort flows by byte count, descending, for a more useful report
    std::vector<Flow> sorted_flows;
    sorted_flows.reserve(flows.size());
    for (auto& kv : flows) sorted_flows.push_back(kv.second);
    std::sort(sorted_flows.begin(), sorted_flows.end(),
              [](const Flow& a, const Flow& b) { return a.byte_count > b.byte_count; });

    for (const auto& flow : sorted_flows) {
        std::string src = ipUint32ToString(flow.tuple.src_ip) + ":" + std::to_string(flow.tuple.src_port);
        std::string dst = ipUint32ToString(flow.tuple.dst_ip) + ":" + std::to_string(flow.tuple.dst_port);
        std::string proto = (flow.tuple.protocol == IP_PROTO_TCP) ? "TCP" : "UDP";

        std::cout << std::left
                  << std::setw(22) << src
                  << std::setw(22) << dst
                  << std::setw(8)  << proto
                  << std::setw(10) << flow.packet_count
                  << std::setw(28) << (flow.sni.empty() ? "-" : flow.sni)
                  << appTypeToString(flow.app_type) << "\n";
    }

    return 0;
}
