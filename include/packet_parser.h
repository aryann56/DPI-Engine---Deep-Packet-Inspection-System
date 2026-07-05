#pragma once

#include "types.h"
#include <cstdint>
#include <cstddef>
#include <string>

// Ethernet header: 6 bytes dest MAC, 6 bytes src MAC, 2 bytes ethertype
constexpr size_t   ETHERNET_HEADER_LEN = 14;
constexpr uint16_t ETHERTYPE_IPV4      = 0x0800;

constexpr uint8_t IP_PROTO_TCP = 6;
constexpr uint8_t IP_PROTO_UDP = 17;

// ============================================================
// PacketParser - turns a raw captured frame into a ParsedPacket
// Every parse step bounds-checks against `length` before reading,
// so malformed/truncated captures never read out of bounds.
// ============================================================
class PacketParser {
public:
    // Parses raw Ethernet frame bytes (as captured from pcap) into `out`.
    // Returns false if the frame is too short/malformed to parse safely.
    // Even on false, whatever layers were successfully parsed remain set.
    static bool parse(const uint8_t* data, size_t length, ParsedPacket& out);

private:
    static bool parseEthernet(const uint8_t* data, size_t length,
                               ParsedPacket& out, size_t& offset);

    static bool parseIPv4(const uint8_t* data, size_t length, size_t offset,
                           ParsedPacket& out, size_t& ip_header_len);

    static bool parseTCP(const uint8_t* data, size_t length, size_t offset,
                          ParsedPacket& out, size_t& tcp_header_len);

    static bool parseUDP(const uint8_t* data, size_t length, size_t offset,
                          ParsedPacket& out);

    static std::string macToString(const uint8_t* mac);
};
