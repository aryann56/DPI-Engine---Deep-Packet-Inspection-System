#pragma once

#include "types.h"
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>

// ============================================================
// BlockRule - one condition a flow can be matched against.
// Three kinds supported: by classified app, by SNI/Host substring,
// or by raw destination IP address.
// ============================================================
struct BlockRule {
    enum class MatchKind { APP_TYPE, SNI_CONTAINS, IP_ADDRESS };

    MatchKind kind;
    AppType app_type = AppType::UNKNOWN;   // used when kind == APP_TYPE
    std::string sni_pattern;               // used when kind == SNI_CONTAINS
    uint32_t ip_address = 0;               // used when kind == IP_ADDRESS
};

// ============================================================
// RuleManager - holds a list of BlockRules and decides whether a
// given Flow should be blocked.
//
// Header-only: every member is defined inline here (no matching .cpp),
// safe because `inline` on class member functions avoids ODR violations
// even if this header is included from multiple translation units.
// ============================================================
class RuleManager {
public:
    RuleManager() = default;

    // Loads rules from a simple text config file, one rule per line:
    //   APP <NAME>        e.g. "APP YOUTUBE"   (matches AppType by name)
    //   SNI <substring>   e.g. "SNI doubleclick"
    //   IP  <a.b.c.d>     e.g. "IP 93.184.216.34"
    // Blank lines and lines starting with '#' are ignored.
    // Returns false if the file could not be opened.
    bool loadFromFile(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) return false;

        std::string line;
        while (std::getline(file, line)) {
            size_t start = line.find_first_not_of(" \t\r\n");
            if (start == std::string::npos) continue; // blank line
            size_t end = line.find_last_not_of(" \t\r\n");
            line = line.substr(start, end - start + 1);

            if (line.empty() || line[0] == '#') continue;

            std::istringstream iss(line);
            std::string keyword, value;
            iss >> keyword;
            std::getline(iss, value);
            size_t vstart = value.find_first_not_of(" \t");
            value = (vstart == std::string::npos) ? "" : value.substr(vstart);

            if (keyword == "APP") {
                addAppRule(appTypeFromName(value));
            } else if (keyword == "SNI") {
                addSniRule(value);
            } else if (keyword == "IP") {
                addIpRule(value);
            }
            // unrecognized keywords are silently skipped
        }
        return true;
    }

    void addAppRule(AppType type) {
        BlockRule rule;
        rule.kind = BlockRule::MatchKind::APP_TYPE;
        rule.app_type = type;
        rules_.push_back(rule);
    }

    void addSniRule(const std::string& substring) {
        BlockRule rule;
        rule.kind = BlockRule::MatchKind::SNI_CONTAINS;
        rule.sni_pattern = substring;
        rules_.push_back(rule);
    }

    void addIpRule(const std::string& ip) {
        BlockRule rule;
        rule.kind = BlockRule::MatchKind::IP_ADDRESS;
        rule.ip_address = ipStringToUint32(ip);
        rules_.push_back(rule);
    }

    // Returns true if `flow` matches any loaded rule (i.e. should be blocked).
    bool shouldBlock(const Flow& flow) const {
        for (const auto& rule : rules_) {
            switch (rule.kind) {
                case BlockRule::MatchKind::APP_TYPE:
                    if (flow.app_type == rule.app_type) return true;
                    break;
                case BlockRule::MatchKind::SNI_CONTAINS:
                    if (!flow.sni.empty() && !rule.sni_pattern.empty() &&
                        flow.sni.find(rule.sni_pattern) != std::string::npos) {
                        return true;
                    }
                    break;
                case BlockRule::MatchKind::IP_ADDRESS:
                    if (flow.tuple.dst_ip == rule.ip_address) return true;
                    break;
            }
        }
        return false;
    }

    size_t ruleCount() const { return rules_.size(); }
    void clear() { rules_.clear(); }

private:
    std::vector<BlockRule> rules_;

    static AppType appTypeFromName(const std::string& name) {
        std::string upper = name;
        std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

        if (upper == "YOUTUBE")   return AppType::YOUTUBE;
        if (upper == "FACEBOOK")  return AppType::FACEBOOK;
        if (upper == "TIKTOK")    return AppType::TIKTOK;
        if (upper == "NETFLIX")   return AppType::NETFLIX;
        if (upper == "TWITTER")   return AppType::TWITTER;
        if (upper == "INSTAGRAM") return AppType::INSTAGRAM;
        if (upper == "WHATSAPP")  return AppType::WHATSAPP;
        if (upper == "GITHUB")    return AppType::GITHUB;
        if (upper == "AMAZON")    return AppType::AMAZON;
        if (upper == "TWITCH")    return AppType::TWITCH;
        if (upper == "GOOGLE")    return AppType::GOOGLE;
        if (upper == "HTTP")      return AppType::HTTP;
        if (upper == "HTTPS")     return AppType::HTTPS;
        if (upper == "DNS")       return AppType::DNS;
        return AppType::UNKNOWN;
    }
};
