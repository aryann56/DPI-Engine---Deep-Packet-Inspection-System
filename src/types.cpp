#include "types.h"
#include <sstream>
#include <cstdio>
#include <cstring>

// ============================================================
// appTypeToString - human-readable label for reports
// ============================================================
std::string appTypeToString(AppType type) {
    switch (type) {
        case AppType::HTTP:      return "HTTP";
        case AppType::HTTPS:     return "HTTPS";
        case AppType::DNS:       return "DNS";
        case AppType::GOOGLE:    return "Google";
        case AppType::YOUTUBE:   return "YouTube";
        case AppType::FACEBOOK:  return "Facebook";
        case AppType::TIKTOK:    return "TikTok";
        case AppType::NETFLIX:   return "Netflix";
        case AppType::TWITTER:   return "Twitter";
        case AppType::INSTAGRAM: return "Instagram";
        case AppType::WHATSAPP:  return "WhatsApp";
        case AppType::GITHUB:    return "GitHub";
        case AppType::AMAZON:    return "Amazon";
        case AppType::TWITCH:    return "Twitch";
        case AppType::UNKNOWN:
        default:                 return "Unknown";
    }
}

// ============================================================
// sniToAppType - substring match on TLS SNI / HTTP Host value
// Add new services here as needed (see README section 12).
// ============================================================
AppType sniToAppType(const std::string& sni) {
    if (sni.find("youtube") != std::string::npos)   return AppType::YOUTUBE;
    if (sni.find("ytimg")   != std::string::npos)   return AppType::YOUTUBE;
    if (sni.find("facebook")!= std::string::npos)   return AppType::FACEBOOK;
    if (sni.find("fbcdn")   != std::string::npos)   return AppType::FACEBOOK;
    if (sni.find("tiktok")  != std::string::npos)   return AppType::TIKTOK;
    if (sni.find("netflix") != std::string::npos)   return AppType::NETFLIX;
    if (sni.find("twitter") != std::string::npos)   return AppType::TWITTER;
    if (sni.find("x.com")   != std::string::npos)   return AppType::TWITTER;
    if (sni.find("instagram")!= std::string::npos)  return AppType::INSTAGRAM;
    if (sni.find("whatsapp")!= std::string::npos)   return AppType::WHATSAPP;
    if (sni.find("github")  != std::string::npos)   return AppType::GITHUB;
    if (sni.find("amazon")  != std::string::npos)   return AppType::AMAZON;
    if (sni.find("twitch")  != std::string::npos)   return AppType::TWITCH;
    if (sni.find("google")  != std::string::npos)   return AppType::GOOGLE;
    return AppType::UNKNOWN;
}

// ============================================================
// ipStringToUint32 - "192.168.1.100" -> packed uint32 (network order)
// ============================================================
uint32_t ipStringToUint32(const std::string& ip) {
    unsigned int a = 0, b = 0, c = 0, d = 0;
    if (std::sscanf(ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
        return 0;
    }
    return (static_cast<uint32_t>(a) << 24) |
           (static_cast<uint32_t>(b) << 16) |
           (static_cast<uint32_t>(c) << 8)  |
            static_cast<uint32_t>(d);
}

// ============================================================
// ipUint32ToString - packed uint32 -> "192.168.1.100"
// ============================================================
std::string ipUint32ToString(uint32_t ip) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                  (ip >> 24) & 0xFF,
                  (ip >> 16) & 0xFF,
                  (ip >> 8)  & 0xFF,
                   ip        & 0xFF);
    return std::string(buf);
}

// ============================================================
// Network byte order readers (big-endian wire format -> host value)
// ============================================================
uint16_t readUint16BE(const uint8_t* data) {
    return static_cast<uint16_t>((data[0] << 8) | data[1]);
}

uint32_t readUint32BE(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 24) |
           (static_cast<uint32_t>(data[1]) << 16) |
           (static_cast<uint32_t>(data[2]) << 8)  |
            static_cast<uint32_t>(data[3]);
}
