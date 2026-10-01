// A small DNS message parser: enough to learn which hostname each address
// belongs to. Handles name compression and rejects malformed messages without
// reading out of bounds or looping.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "core/Packet.h"

namespace pm {

struct DnsAnswer {
    std::string name;
    uint16_t type = 0;
    uint32_t ttl = 0;
    IpAddr addr;         // A and AAAA
    std::string target;  // CNAME
};

struct DnsMessage {
    uint16_t id = 0;
    bool response = false;
    uint8_t rcode = 0;
    std::string question;  // first question's name, lower case, no trailing dot
    uint16_t qtype = 0;
    std::vector<DnsAnswer> answers;
};

enum : uint16_t { kDnsA = 1, kDnsCname = 5, kDnsAaaa = 28, kDnsHttps = 65 };

bool parseDns(const uint8_t* data, size_t len, DnsMessage& out);

/** For DNS over TCP: the message after the two-byte length, if it is all here. */
bool parseDnsTcp(const uint8_t* data, size_t len, DnsMessage& out);

/** Name of a query type, e.g. "AAAA". */
const char* dnsTypeName(uint16_t type);

}  // namespace pm
