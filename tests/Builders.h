// Helpers that build packets byte by byte for the tests.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "core/Packet.h"

namespace pmtest {

using Bytes = std::vector<uint8_t>;

inline void put16(Bytes& b, uint16_t v) {
    b.push_back(uint8_t(v >> 8));
    b.push_back(uint8_t(v));
}
inline void put32(Bytes& b, uint32_t v) {
    put16(b, uint16_t(v >> 16));
    put16(b, uint16_t(v));
}
inline void append(Bytes& b, const Bytes& more) { b.insert(b.end(), more.begin(), more.end()); }
inline Bytes text(const std::string& s) { return Bytes(s.begin(), s.end()); }
inline pm::IpAddr ip(const char* s) { return *pm::IpAddr::parse(s); }

inline Bytes tcp(uint16_t sport, uint16_t dport, uint32_t seq, uint32_t ack, uint8_t flags, const Bytes& payload,
                 int optionBytes = 0) {
    Bytes b;
    put16(b, sport);
    put16(b, dport);
    put32(b, seq);
    put32(b, ack);
    b.push_back(uint8_t(((20 + optionBytes) / 4) << 4));
    b.push_back(flags);
    put16(b, 65535);
    put16(b, 0);
    put16(b, 0);
    for (int i = 0; i < optionBytes; i++) b.push_back(1);  // NOPs
    append(b, payload);
    return b;
}

inline Bytes udp(uint16_t sport, uint16_t dport, const Bytes& payload, int lengthOverride = -1) {
    Bytes b;
    put16(b, sport);
    put16(b, dport);
    put16(b, uint16_t(lengthOverride >= 0 ? lengthOverride : int(8 + payload.size())));
    put16(b, 0);
    append(b, payload);
    return b;
}

inline Bytes ipv4(const pm::IpAddr& src, const pm::IpAddr& dst, uint8_t proto, const Bytes& l4,
                  uint16_t fragField = 0x4000, int totalOverride = -1) {
    Bytes b = {0x45, 0};
    put16(b, uint16_t(totalOverride >= 0 ? totalOverride : int(20 + l4.size())));
    put16(b, 0x1234);
    put16(b, fragField);
    b.push_back(64);
    b.push_back(proto);
    put16(b, 0);
    b.insert(b.end(), src.bytes.begin(), src.bytes.begin() + 4);
    b.insert(b.end(), dst.bytes.begin(), dst.bytes.begin() + 4);
    append(b, l4);
    return b;
}

/** IPv6 with a chain of extension headers already encoded in body. */
inline Bytes ipv6(const pm::IpAddr& src, const pm::IpAddr& dst, uint8_t next, const Bytes& body) {
    Bytes b;
    put32(b, 0x60000000);
    put16(b, uint16_t(body.size()));
    b.push_back(next);
    b.push_back(64);
    b.insert(b.end(), src.bytes.begin(), src.bytes.end());
    b.insert(b.end(), dst.bytes.begin(), dst.bytes.end());
    append(b, body);
    return b;
}

inline Bytes ethernet(uint16_t type, const Bytes& payload) {
    Bytes b = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
    put16(b, type);
    append(b, payload);
    return b;
}

inline void dnsName(Bytes& b, const std::string& name) {
    size_t start = 0;
    while (start < name.size()) {
        size_t dot = name.find('.', start);
        if (dot == std::string::npos) dot = name.size();
        b.push_back(uint8_t(dot - start));
        b.insert(b.end(), name.begin() + long(start), name.begin() + long(dot));
        start = dot + 1;
    }
    b.push_back(0);
}

/** A DNS response: name -> (optional CNAME) -> the given IPv4 addresses. */
inline Bytes dnsResponse(const std::string& name, const std::vector<pm::IpAddr>& addrs, const std::string& cname = "",
                         uint16_t rcode = 0) {
    Bytes r;
    put16(r, 0xbeef);
    put16(r, uint16_t(0x8180 | rcode));
    put16(r, 1);
    put16(r, uint16_t(addrs.size() + (cname.empty() ? 0 : 1)));
    put16(r, 0);
    put16(r, 0);
    dnsName(r, name);
    put16(r, 1);
    put16(r, 1);
    uint16_t owner = 0xc00c;
    if (!cname.empty()) {
        put16(r, 0xc00c);
        put16(r, 5);
        put16(r, 1);
        put32(r, 300);
        Bytes target;
        dnsName(target, cname);
        put16(r, uint16_t(target.size()));
        owner = uint16_t(0xc000 | r.size());
        append(r, target);
    }
    for (const auto& a : addrs) {
        put16(r, owner);
        put16(r, 1);
        put16(r, 1);
        put32(r, 60);
        put16(r, 4);
        r.insert(r.end(), a.bytes.begin(), a.bytes.begin() + 4);
    }
    return r;
}

/**
 * A TLS ClientHello. padBefore adds an extension of that many bytes ahead of
 * the server name, as a large key share would.
 */
inline Bytes clientHello(const std::string& host, size_t padBefore = 0, bool withSni = true) {
    Bytes ext;
    if (padBefore) {
        put16(ext, 0x0033);
        put16(ext, uint16_t(padBefore));
        ext.insert(ext.end(), padBefore, 0xab);
    }
    if (withSni) {
        put16(ext, 0x0000);
        put16(ext, uint16_t(host.size() + 5));
        put16(ext, uint16_t(host.size() + 3));
        ext.push_back(0);
        put16(ext, uint16_t(host.size()));
        append(ext, text(host));
    }
    put16(ext, 0x002b);
    put16(ext, 3);
    ext.push_back(2);
    put16(ext, 0x0304);

    Bytes body;
    put16(body, 0x0303);
    body.insert(body.end(), 32, 0x11);
    body.push_back(32);
    body.insert(body.end(), 32, 0x22);
    put16(body, 4);
    put16(body, 0x1301);
    put16(body, 0x1302);
    body.push_back(1);
    body.push_back(0);
    put16(body, uint16_t(ext.size()));
    append(body, ext);

    Bytes hs = {1, uint8_t(body.size() >> 16)};
    put16(hs, uint16_t(body.size()));
    append(hs, body);
    Bytes rec = {0x16, 0x03, 0x01};
    put16(rec, uint16_t(hs.size()));
    append(rec, hs);
    return rec;
}

}  // namespace pmtest
