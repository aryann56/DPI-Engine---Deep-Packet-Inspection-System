#pragma once

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

// ============================================================
// PCAP file format structures (see libpcap file format spec)
// packed so sizeof() matches on-disk byte layout exactly
// ============================================================
#pragma pack(push, 1)

struct PcapGlobalHeader {
    uint32_t magic_number;   // 0xa1b2c3d4 (or swapped / nsec variant)
    uint16_t version_major;  // 2
    uint16_t version_minor;  // 4
    int32_t  thiszone;       // GMT offset, usually 0
    uint32_t sigfigs;        // timestamp accuracy, usually 0
    uint32_t snaplen;        // max length of captured packets
    uint32_t network;        // link-layer type, 1 = Ethernet
};

struct PcapRecordHeader {
    uint32_t ts_sec;    // timestamp seconds
    uint32_t ts_usec;   // timestamp microseconds
    uint32_t incl_len;  // number of bytes actually captured/saved
    uint32_t orig_len;  // original length of packet on the wire
};

#pragma pack(pop)

// Standard pcap magic number (little-endian writer, native reader)
constexpr uint32_t PCAP_MAGIC_NATIVE  = 0xa1b2c3d4;
// Same file but byte-swapped (written on opposite-endian machine)
constexpr uint32_t PCAP_MAGIC_SWAPPED = 0xd4c3b2a1;

// ============================================================
// PcapReader - opens a .pcap file and yields raw packets one by one
// ============================================================
class PcapReader {
public:
    PcapReader() = default;
    ~PcapReader();

    // Opens file and validates the global header. Returns false on failure.
    bool open(const std::string& filename);
    void close();

    // Reads the next packet record into out_data (raw bytes, incl_len long)
    // and out_header (record metadata). Returns false at EOF or read error.
    bool readNextPacket(std::vector<uint8_t>& out_data, PcapRecordHeader& out_header);

    bool isOpen() const { return file_ != nullptr; }
    bool isSwapped() const { return swapped_; }
    uint32_t linkType() const { return global_header_.network; }

private:
    FILE* file_ = nullptr;
    bool swapped_ = false;   // true if file endianness != host endianness
    PcapGlobalHeader global_header_{};

    uint32_t swap32(uint32_t v) const;
    uint16_t swap16(uint16_t v) const;
};
