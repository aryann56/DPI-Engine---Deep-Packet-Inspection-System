#include "sni_extractor.h"
#include "types.h"
#include <cstring>
#include <cctype>

// TLS record/handshake constants (RFC 8446 / RFC 5246)
constexpr uint8_t  TLS_CONTENT_TYPE_HANDSHAKE = 0x16;
constexpr uint8_t  TLS_HANDSHAKE_CLIENT_HELLO = 0x01;
constexpr uint16_t TLS_EXTENSION_SERVER_NAME  = 0x0000;
constexpr uint8_t  SNI_NAME_TYPE_HOSTNAME     = 0x00;

// ============================================================
// isTlsHandshakeRecord - does this payload start with a TLS
// Handshake record header?
// ============================================================
bool SniExtractor::isTlsHandshakeRecord(const uint8_t* payload, size_t length) {
    // Record header is 5 bytes: content_type(1) version(2) length(2)
    if (length < 5) return false;
    return payload[0] == TLS_CONTENT_TYPE_HANDSHAKE;
}

// ============================================================
// isClientHello - is the handshake message inside a ClientHello?
// ============================================================
bool SniExtractor::isClientHello(const uint8_t* payload, size_t length) {
    // Byte 5 (right after the 5-byte record header) is the handshake type
    if (length < 6) return false;
    return payload[5] == TLS_HANDSHAKE_CLIENT_HELLO;
}

// ============================================================
// extractTlsSni - manually walk ClientHello -> extensions -> SNI
//
// Layout after the 5-byte record header + 4-byte handshake header:
//   client_version   (2 bytes)
//   random           (32 bytes)
//   session_id_len   (1 byte)   + session_id
//   cipher_suites_len(2 bytes)  + cipher_suites
//   compression_len  (1 byte)   + compression_methods
//   extensions_len   (2 bytes)  + extensions...
//
// Each extension: type(2) length(2) data(length)
// SNI extension data: list_len(2) [name_type(1) name_len(2) name(name_len)]
// ============================================================
bool SniExtractor::extractTlsSni(const uint8_t* payload, size_t length, std::string& out_sni) {
    if (!isTlsHandshakeRecord(payload, length) || !isClientHello(payload, length)) {
        return false;
    }

    // Position right after: record header(5) + handshake type(1) + handshake len(3)
    size_t pos = 5 + 4;
    if (pos + 2 + 32 > length) return false; // client_version + random

    pos += 2;   // skip client_version
    pos += 32;  // skip random

    if (pos + 1 > length) return false;
    uint8_t session_id_len = payload[pos];
    pos += 1 + session_id_len;
    if (pos > length) return false;

    if (pos + 2 > length) return false;
    uint16_t cipher_suites_len = readUint16BE(payload + pos);
    pos += 2 + cipher_suites_len;
    if (pos > length) return false;

    if (pos + 1 > length) return false;
    uint8_t compression_len = payload[pos];
    pos += 1 + compression_len;
    if (pos > length) return false;

    if (pos + 2 > length) return false;
    uint16_t extensions_len = readUint16BE(payload + pos);
    pos += 2;
    if (pos + extensions_len > length) return false;

    size_t ext_end = pos + extensions_len;

    while (pos + 4 <= ext_end) {
        uint16_t ext_type = readUint16BE(payload + pos);
        uint16_t ext_len  = readUint16BE(payload + pos + 2);
        size_t ext_data_start = pos + 4;

        if (ext_data_start + ext_len > ext_end) {
            return false; // malformed extension length
        }

        if (ext_type == TLS_EXTENSION_SERVER_NAME) {
            // server_name_list: list_len(2) then entries
            size_t sp = ext_data_start;
            if (sp + 2 > ext_data_start + ext_len) return false;
            uint16_t list_len = readUint16BE(payload + sp);
            sp += 2;
            size_t list_end = sp + list_len;
            if (list_end > ext_data_start + ext_len) return false;

            while (sp + 3 <= list_end) {
                uint8_t name_type = payload[sp];
                uint16_t name_len = readUint16BE(payload + sp + 1);
                size_t name_start = sp + 3;

                if (name_start + name_len > list_end) return false;

                if (name_type == SNI_NAME_TYPE_HOSTNAME) {
                    out_sni.assign(reinterpret_cast<const char*>(payload + name_start), name_len);
                    return true;
                }
                sp = name_start + name_len;
            }
        }

        pos = ext_data_start + ext_len;
    }

    return false; // no SNI extension found
}

// ============================================================
// extractHttpHost - find "Host: <value>\r\n" in a plaintext HTTP
// request. Case-insensitive match on the header name only.
// ============================================================
bool SniExtractor::extractHttpHost(const uint8_t* payload, size_t length, std::string& out_host) {
    if (payload == nullptr || length < 6) return false;

    const char* text = reinterpret_cast<const char*>(payload);
    const std::string haystack(text, length);

    // Search case-insensitively for "host:"
    static const std::string needle = "host:";
    size_t pos = std::string::npos;
    for (size_t i = 0; i + needle.size() <= haystack.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < needle.size(); ++j) {
            if (std::tolower(static_cast<unsigned char>(haystack[i + j])) != needle[j]) {
                match = false;
                break;
            }
        }
        // Header name must start at a line boundary (start of buffer or after \n)
        if (match && (i == 0 || haystack[i - 1] == '\n')) {
            pos = i;
            break;
        }
    }
    if (pos == std::string::npos) return false;

    size_t value_start = pos + needle.size();
    while (value_start < haystack.size() && haystack[value_start] == ' ') {
        ++value_start;
    }

    size_t line_end = haystack.find("\r\n", value_start);
    if (line_end == std::string::npos) {
        line_end = haystack.find('\n', value_start);
    }
    if (line_end == std::string::npos || line_end <= value_start) return false;

    out_host = haystack.substr(value_start, line_end - value_start);
    return !out_host.empty();
}
