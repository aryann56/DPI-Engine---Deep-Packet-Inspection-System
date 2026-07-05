#pragma once

#include <cstdint>
#include <string>
#include <cstddef>

// ============================================================
// FiveTuple - uniquely identifies a network connection (flow)
// ============================================================
struct FiveTuple {
    uint32_t src_ip = 0;
    uint32_t dst_ip = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t  protocol = 0;   // 6 = TCP, 17 = UDP

    bool operator==(const FiveTuple& other) const {
        return src_ip == other.src_ip &&
               dst_ip == other.dst_ip &&
               src_port == other.src_port &&
               dst_port == other.dst_port &&
               protocol == other.protocol;
    }
};

// Hash functor so FiveTuple can key an unordered_map
struct FiveTupleHash {
    std::size_t operator()(const FiveTuple& t) const noexcept {
        std::size_t seed = std::hash<uint32_t>()(t.src_ip);
        auto mix = [&seed](std::size_t v) {
            seed ^= v + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        };
        mix(std::hash<uint32_t>()(t.dst_ip));
        mix(std::hash<uint16_t>()(t.src_port));
        mix(std::hash<uint16_t>()(t.dst_port));
        mix(std::hash<uint8_t>()(t.protocol));
        return seed;
    }
};

// ============================================================
// AppType - application/service classification result
// ============================================================
enum class AppType {
    UNKNOWN,
    HTTP,
    HTTPS,
    DNS,
    GOOGLE,
    YOUTUBE,
    FACEBOOK,
    TIKTOK,
    NETFLIX,
    TWITTER,
    INSTAGRAM,
    WHATSAPP,
    GITHUB,
    AMAZON,
    TWITCH
};

std::string appTypeToString(AppType type);
AppType sniToAppType(const std::string& sni);

// ============================================================
// ParsedPacket - fields extracted after parsing Ethernet/IP/TCP/UDP
// ============================================================
struct ParsedPacket {
    std::string src_mac;
    std::string dest_mac;
    uint16_t ether_type = 0;

    std::string src_ip;
    std::string dest_ip;
    uint8_t protocol = 0;   // 6 = TCP, 17 = UDP
    uint8_t ttl = 0;

    uint16_t src_port = 0;
    uint16_t dest_port = 0;
    uint8_t tcp_flags = 0;

    bool has_ip = false;
    bool has_tcp = false;
    bool has_udp = false;

    const uint8_t* payload = nullptr;
    size_t payload_length = 0;
};

// ============================================================
// Flow - per-connection state tracked across packets
// ============================================================
struct Flow {
    FiveTuple tuple{};
    std::string sni;
    AppType app_type = AppType::UNKNOWN;
    bool blocked = false;
    uint64_t packet_count = 0;
    uint64_t byte_count = 0;
};

// ============================================================
// Helper functions (implemented in types.cpp)
// ============================================================
uint32_t ipStringToUint32(const std::string& ip);
std::string ipUint32ToString(uint32_t ip);
uint16_t readUint16BE(const uint8_t* data);
uint32_t readUint32BE(const uint8_t* data);
