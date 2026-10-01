#include "core/Packet.h"

#include <arpa/inet.h>

namespace pm {

std::optional<IpAddr> IpAddr::parse(std::string_view text) {
    std::string s(text);
    IpAddr a;
    if (inet_pton(AF_INET, s.c_str(), a.bytes.data()) == 1) {
        a.family = 4;
        return a;
    }
    if (inet_pton(AF_INET6, s.c_str(), a.bytes.data()) == 1) {
        a.family = 6;
        return a;
    }
    return std::nullopt;
}

std::string IpAddr::str() const {
    char buf[INET6_ADDRSTRLEN] = {};
    if (family == 4) inet_ntop(AF_INET, bytes.data(), buf, sizeof buf);
    else if (family == 6) inet_ntop(AF_INET6, bytes.data(), buf, sizeof buf);
    else return "-";
    return buf;
}

IpAddr IpAddr::unmapped() const {
    static const uint8_t prefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    if (family == 6 && std::memcmp(bytes.data(), prefix, 12) == 0) return v4(bytes.data() + 12);
    return *this;
}

bool IpAddr::isLoopback() const {
    IpAddr a = unmapped();
    if (a.family == 4) return a.bytes[0] == 127;
    if (a.family == 6) {
        static const uint8_t one[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        return std::memcmp(a.bytes.data(), one, 16) == 0;
    }
    return false;
}

bool IpAddr::isPrivate() const {
    IpAddr a = unmapped();
    const auto& b = a.bytes;
    if (a.family == 4) {
        return b[0] == 10 || b[0] == 127 || (b[0] == 172 && (b[1] & 0xf0) == 16) ||
               (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254) ||
               (b[0] == 100 && (b[1] & 0xc0) == 64);
    }
    if (a.family == 6) {
        return a.isLoopback() || (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) || (b[0] & 0xfe) == 0xfc;
    }
    return false;
}

bool IpAddr::isMulticastOrBroadcast() const {
    IpAddr a = unmapped();
    if (a.family == 4) {
        return (a.bytes[0] & 0xf0) == 0xe0 ||
               (a.bytes[0] == 255 && a.bytes[1] == 255 && a.bytes[2] == 255 && a.bytes[3] == 255);
    }
    if (a.family == 6) return a.bytes[0] == 0xff;
    return false;
}

FlowKey FlowKey::of(const PacketView& p, bool& srcIsA) {
    FlowKey k;
    k.proto = p.proto;
    uint16_t sp = p.hasL4 ? p.sport : 0, dp = p.hasL4 ? p.dport : 0;
    if (p.proto == kProtoIcmp || p.proto == kProtoIcmp6) sp = dp = 0;
    srcIsA = p.src < p.dst || (p.src == p.dst && sp <= dp);
    if (srcIsA) {
        k.a = p.src, k.pa = sp, k.b = p.dst, k.pb = dp;
    } else {
        k.a = p.dst, k.pa = dp, k.b = p.src, k.pb = sp;
    }
    return k;
}

}  // namespace pm
