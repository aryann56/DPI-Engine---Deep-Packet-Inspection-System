#pragma once

#include <cstdint>
#include <cstddef>
#include <string>

// ============================================================
// SniExtractor - pulls a hostname out of a TCP payload so a flow
// can be classified (e.g. "youtube.com" -> AppType::YOUTUBE).
//
// Two sources are supported:
//   1. TLS ClientHello SNI extension (for HTTPS traffic)
//   2. Plaintext HTTP "Host:" header   (for HTTP traffic)
// ============================================================
class SniExtractor {
public:
    // Attempts to extract the TLS ClientHello SNI hostname from `payload`.
    // Returns true and fills out_sni on success.
    static bool extractTlsSni(const uint8_t* payload, size_t length, std::string& out_sni);

    // Attempts to extract the HTTP "Host:" header value from a plaintext
    // HTTP request. Returns true and fills out_host on success.
    static bool extractHttpHost(const uint8_t* payload, size_t length, std::string& out_host);

private:
    // TLS record layer: byte[0] == 0x16 (Handshake)
    static bool isTlsHandshakeRecord(const uint8_t* payload, size_t length);

    // TLS handshake message: byte[5] == 0x01 (ClientHello)
    static bool isClientHello(const uint8_t* payload, size_t length);
};
