#include "pcap_reader.h"
#include <cstring>

PcapReader::~PcapReader() {
    close();
}

uint32_t PcapReader::swap32(uint32_t v) const {
    return ((v & 0x000000FF) << 24) |
           ((v & 0x0000FF00) << 8)  |
           ((v & 0x00FF0000) >> 8)  |
           ((v & 0xFF000000) >> 24);
}

uint16_t PcapReader::swap16(uint16_t v) const {
    return static_cast<uint16_t>(((v & 0x00FF) << 8) | ((v & 0xFF00) >> 8));
}

bool PcapReader::open(const std::string& filename) {
    close(); // in case reused

    file_ = std::fopen(filename.c_str(), "rb");
    if (!file_) {
        return false;
    }

    size_t read = std::fread(&global_header_, sizeof(PcapGlobalHeader), 1, file_);
    if (read != 1) {
        close();
        return false;
    }

    if (global_header_.magic_number == PCAP_MAGIC_NATIVE) {
        swapped_ = false;
    } else if (global_header_.magic_number == PCAP_MAGIC_SWAPPED) {
        swapped_ = true;
        global_header_.version_major = swap16(global_header_.version_major);
        global_header_.version_minor = swap16(global_header_.version_minor);
        global_header_.thiszone      = static_cast<int32_t>(swap32(static_cast<uint32_t>(global_header_.thiszone)));
        global_header_.sigfigs       = swap32(global_header_.sigfigs);
        global_header_.snaplen       = swap32(global_header_.snaplen);
        global_header_.network       = swap32(global_header_.network);
    } else {
        // Not a recognized pcap file (could be pcapng - not supported here)
        close();
        return false;
    }

    return true;
}

void PcapReader::close() {
    if (file_) {
        std::fclose(file_);
        file_ = nullptr;
    }
    swapped_ = false;
    global_header_ = PcapGlobalHeader{};
}

bool PcapReader::readNextPacket(std::vector<uint8_t>& out_data, PcapRecordHeader& out_header) {
    if (!file_) return false;

    PcapRecordHeader hdr{};
    size_t read = std::fread(&hdr, sizeof(PcapRecordHeader), 1, file_);
    if (read != 1) {
        return false; // EOF or truncated file
    }

    if (swapped_) {
        hdr.ts_sec   = swap32(hdr.ts_sec);
        hdr.ts_usec  = swap32(hdr.ts_usec);
        hdr.incl_len = swap32(hdr.incl_len);
        hdr.orig_len = swap32(hdr.orig_len);
    }

    // Sanity check to avoid huge bogus allocations on corrupt files
    if (hdr.incl_len == 0 || hdr.incl_len > global_header_.snaplen + 65536) {
        return false;
    }

    out_data.resize(hdr.incl_len);
    size_t bytes_read = std::fread(out_data.data(), 1, hdr.incl_len, file_);
    if (bytes_read != hdr.incl_len) {
        return false; // truncated packet at end of file
    }

    out_header = hdr;
    return true;
}
