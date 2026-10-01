#include "analysis/Dns.h"

namespace pm {
namespace {

inline uint16_t be16(const uint8_t* p) { return uint16_t(p[0] << 8 | p[1]); }
inline uint32_t be32(const uint8_t* p) {
    return uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | p[3];
}

/**
 * Reads a possibly compressed name starting at pos, leaving pos after the
 * name's bytes in place. Limits jumps and length, so pointer loops fail.
 */
bool readName(const uint8_t* d, size_t len, size_t& pos, std::string& out) {
    out.clear();
    size_t p = pos;
    bool jumped = false;
    int jumps = 0;
    size_t total = 0;
    for (;;) {
        if (p >= len) return false;
        uint8_t l = d[p];
        if ((l & 0xc0) == 0xc0) {
            if (p + 1 >= len) return false;
            size_t target = size_t(l & 0x3f) << 8 | d[p + 1];
            if (!jumped) pos = p + 2;
            jumped = true;
            if (++jumps > 16 || target >= len) return false;
            p = target;
            continue;
        }
        if (l & 0xc0) return false;  // reserved label types
        if (l == 0) {
            if (!jumped) pos = p + 1;
            return true;
        }
        if (p + 1 + l > len) return false;
        total += l + 1;
        if (total > 255) return false;
        if (!out.empty()) out += '.';
        for (size_t i = 0; i < l; i++) {
            uint8_t c = d[p + 1 + i];
            if (c >= 'A' && c <= 'Z') c = uint8_t(c - 'A' + 'a');
            out += (c >= 0x21 && c < 0x7f) ? char(c) : '?';
        }
        p += 1 + l;
    }
}

}  // namespace

bool parseDns(const uint8_t* d, size_t len, DnsMessage& out) {
    out = DnsMessage{};
    if (len < 12) return false;
    uint16_t flags = be16(d + 2);
    if (((flags >> 11) & 0xf) != 0) return false;  // only standard queries
    out.id = be16(d);
    out.response = flags & 0x8000;
    out.rcode = flags & 0xf;
    uint16_t qd = be16(d + 4), an = be16(d + 6);
    if (qd > 4) return false;  // real resolvers send one question

    size_t pos = 12;
    std::string name;
    for (uint16_t i = 0; i < qd; i++) {
        if (!readName(d, len, pos, name) || pos + 4 > len) return false;
        if (i == 0) {
            out.question = name;
            out.qtype = be16(d + pos);
        }
        pos += 4;
    }

    for (uint16_t i = 0; i < an && i < 64; i++) {
        DnsAnswer a;
        if (!readName(d, len, pos, a.name) || pos + 10 > len) return i > 0;
        a.type = be16(d + pos);
        a.ttl = be32(d + pos + 4);
        uint16_t rdlen = be16(d + pos + 8);
        pos += 10;
        if (pos + rdlen > len) return i > 0;  // cut off by the snap length: keep what we have
        if (a.type == kDnsA && rdlen == 4) {
            a.addr = IpAddr::v4(d + pos);
        } else if (a.type == kDnsAaaa && rdlen == 16) {
            a.addr = IpAddr::v6(d + pos);
        } else if (a.type == kDnsCname) {
            size_t rp = pos;
            if (!readName(d, pos + rdlen, rp, a.target)) return false;
        }
        pos += rdlen;
        out.answers.push_back(std::move(a));
    }
    return true;
}

bool parseDnsTcp(const uint8_t* d, size_t len, DnsMessage& out) {
    if (len < 2) return false;
    size_t msgLen = be16(d);
    if (msgLen + 2 > len) return false;
    return parseDns(d + 2, msgLen, out);
}

const char* dnsTypeName(uint16_t type) {
    switch (type) {
    case 1: return "A";
    case 2: return "NS";
    case 5: return "CNAME";
    case 6: return "SOA";
    case 12: return "PTR";
    case 15: return "MX";
    case 16: return "TXT";
    case 28: return "AAAA";
    case 33: return "SRV";
    case 64: return "SVCB";
    case 65: return "HTTPS";
    case 255: return "ANY";
    default: return "?";
    }
}

}  // namespace pm
