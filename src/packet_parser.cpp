#include "packet_parser.h"
#include <cstdio>

// ============================================================
// macToString - "aa:bb:cc:dd:ee:ff"
// ============================================================
std::string PacketParser::macToString(const uint8_t* mac) {
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

// ============================================================
// parseEthernet - reads the 14-byte Ethernet header
// ============================================================
bool PacketParser::parseEthernet(const uint8_t* data, size_t length,
                                  ParsedPacket& out, size_t& offset) {
    if (length < ETHERNET_HEADER_LEN) {
        return false; // too short to even hold an Ethernet header
    }

    out.dest_mac  = macToString(data);
    out.src_mac   = macToString(data + 6);
    out.ether_type = readUint16BE(data + 12);

    offset = ETHERNET_HEADER_LEN;
    return true;
}

// ============================================================
// parseIPv4 - reads the (variable-length) IPv4 header
// ============================================================
bool PacketParser::parseIPv4(const uint8_t* data, size_t length, size_t offset,
                              ParsedPacket& out, size_t& ip_header_len) {
    // Need at least the fixed 20-byte minimum IPv4 header
    if (offset + 20 > length) {
        return false;
    }

    uint8_t version_ihl = data[offset];
    uint8_t version = (version_ihl >> 4) & 0x0F;
    uint8_t ihl     = version_ihl & 0x0F;      // header length in 32-bit words
    ip_header_len   = static_cast<size_t>(ihl) * 4;

    if (version != 4) {
        return false; // not IPv4 (IPv6 not handled by this parser)
    }
    if (ip_header_len < 20 || offset + ip_header_len > length) {
        return false; // malformed/truncated header
    }

    out.ttl      = data[offset + 8];
    out.protocol = data[offset + 9];

    uint32_t src_ip_raw  = readUint32BE(data + offset + 12);
    uint32_t dest_ip_raw = readUint32BE(data + offset + 16);
    out.src_ip  = ipUint32ToString(src_ip_raw);
    out.dest_ip = ipUint32ToString(dest_ip_raw);

    out.has_ip = true;
    return true;
}

// ============================================================
// parseTCP - reads the (variable-length) TCP header
// ============================================================
bool PacketParser::parseTCP(const uint8_t* data, size_t length, size_t offset,
                             ParsedPacket& out, size_t& tcp_header_len) {
    // Need at least the fixed 20-byte minimum TCP header
    if (offset + 20 > length) {
        return false;
    }

    out.src_port  = readUint16BE(data + offset);
    out.dest_port = readUint16BE(data + offset + 2);

    uint8_t data_offset_byte = data[offset + 12];
    uint8_t data_offset = (data_offset_byte >> 4) & 0x0F; // in 32-bit words
    tcp_header_len = static_cast<size_t>(data_offset) * 4;

    if (tcp_header_len < 20 || offset + tcp_header_len > length) {
        return false; // malformed/truncated header
    }

    out.tcp_flags = data[offset + 13];
    out.has_tcp = true;
    return true;
}

// ============================================================
// parseUDP - reads the fixed 8-byte UDP header
// ============================================================
bool PacketParser::parseUDP(const uint8_t* data, size_t length, size_t offset,
                             ParsedPacket& out) {
    if (offset + 8 > length) {
        return false;
    }

    out.src_port  = readUint16BE(data + offset);
    out.dest_port = readUint16BE(data + offset + 2);
    out.has_udp = true;
    return true;
}

// ============================================================
// parse - top-level entry point, walks Ethernet -> IPv4 -> TCP/UDP
// ============================================================
bool PacketParser::parse(const uint8_t* data, size_t length, ParsedPacket& out) {
    out = ParsedPacket{}; // reset any stale state

    if (data == nullptr || length == 0) {
        return false;
    }

    size_t offset = 0;
    if (!parseEthernet(data, length, out, offset)) {
        return false;
    }

    if (out.ether_type != ETHERTYPE_IPV4) {
        return true; // parsed what we could (Ethernet only); not an error
    }

    size_t ip_header_len = 0;
    if (!parseIPv4(data, length, offset, out, ip_header_len)) {
        return true; // Ethernet parsed ok, IPv4 layer malformed/absent
    }
    offset += ip_header_len;

    if (out.protocol == IP_PROTO_TCP) {
        size_t tcp_header_len = 0;
        if (parseTCP(data, length, offset, out, tcp_header_len)) {
            offset += tcp_header_len;
        }
    } else if (out.protocol == IP_PROTO_UDP) {
        parseUDP(data, length, offset, out);
        offset += 8;
    }

    // Whatever bytes remain after the parsed headers are payload
    if (offset < length) {
        out.payload = data + offset;
        out.payload_length = length - offset;
    }

    return true;
}
