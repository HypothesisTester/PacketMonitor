// Basic network types shared by every stage: addresses, decoded packets and
// flow keys.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace pm {

/** An IPv4 or IPv6 address. IPv4 uses the first four bytes. */
struct IpAddr {
    uint8_t family = 0;  // 4, 6, or 0 when unset
    std::array<uint8_t, 16> bytes{};

    static IpAddr v4(const uint8_t* b) {
        IpAddr a;
        a.family = 4;
        std::memcpy(a.bytes.data(), b, 4);
        return a;
    }
    static IpAddr v6(const uint8_t* b) {
        IpAddr a;
        a.family = 6;
        std::memcpy(a.bytes.data(), b, 16);
        return a;
    }
    /** Parses dotted IPv4 or textual IPv6. */
    static std::optional<IpAddr> parse(std::string_view text);

    bool valid() const { return family == 4 || family == 6; }
    std::string str() const;

    /** Private, loopback, link-local or unique-local: addresses that are "ours" rather than the internet's. */
    bool isPrivate() const;
    bool isLoopback() const;
    bool isMulticastOrBroadcast() const;
    /** For ::ffff:a.b.c.d, the IPv4 address; otherwise the address itself. */
    IpAddr unmapped() const;

    friend bool operator==(const IpAddr& a, const IpAddr& b) {
        return a.family == b.family && a.bytes == b.bytes;
    }
    friend bool operator!=(const IpAddr& a, const IpAddr& b) { return !(a == b); }
    friend bool operator<(const IpAddr& a, const IpAddr& b) {
        if (a.family != b.family) return a.family < b.family;
        return a.bytes < b.bytes;
    }
};

inline uint64_t mix64(uint64_t x) {
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}

inline uint64_t hashAddr(const IpAddr& a) {
    uint64_t lo, hi;
    std::memcpy(&lo, a.bytes.data(), 8);
    std::memcpy(&hi, a.bytes.data() + 8, 8);
    return mix64(lo ^ mix64(hi ^ a.family));
}

struct IpAddrHash {
    size_t operator()(const IpAddr& a) const { return static_cast<size_t>(hashAddr(a)); }
};

enum : uint8_t {
    kProtoIcmp = 1,
    kProtoTcp = 6,
    kProtoUdp = 17,
    kProtoIcmp6 = 58,
};

enum : uint8_t {
    kTcpFin = 0x01,
    kTcpSyn = 0x02,
    kTcpRst = 0x04,
    kTcpPsh = 0x08,
    kTcpAck = 0x10,
};

/**
 * A decoded packet. Payload points into the captured bytes, so a PacketView is
 * valid only while those bytes are.
 */
struct PacketView {
    int64_t tsUsec = 0;     // capture time, microseconds since the epoch
    uint32_t wireLen = 0;   // length on the wire
    uint32_t capLen = 0;    // bytes captured

    uint8_t ipVersion = 0;  // 4 or 6; 0 if not IP
    IpAddr src, dst;
    uint8_t proto = 0;      // IP protocol number of the transport header
    bool fragment = false;  // a non-first fragment: no transport header
    bool hasL4 = false;     // ports/flags below are valid

    uint16_t sport = 0, dport = 0;
    uint8_t tcpFlags = 0;
    uint32_t seq = 0, ack = 0;
    uint8_t icmpType = 0, icmpCode = 0;

    const uint8_t* payload = nullptr;
    uint32_t payloadLen = 0;    // payload bytes available in the capture
    uint32_t payloadTotal = 0;  // payload length according to the headers

    bool payloadTruncated() const { return payloadLen < payloadTotal; }
};

/** A flow key that is the same for both directions of a conversation. */
struct FlowKey {
    IpAddr a, b;
    uint16_t pa = 0, pb = 0;
    uint8_t proto = 0;

    /** Builds the key and reports whether the packet's source is side a. */
    static FlowKey of(const PacketView& p, bool& srcIsA);

    friend bool operator==(const FlowKey& x, const FlowKey& y) {
        return x.proto == y.proto && x.pa == y.pa && x.pb == y.pb && x.a == y.a && x.b == y.b;
    }
};

struct FlowKeyHash {
    size_t operator()(const FlowKey& k) const {
        uint64_t h = hashAddr(k.a) * 31 + hashAddr(k.b);
        h ^= (uint64_t(k.pa) << 24) | (uint64_t(k.pb) << 8) | k.proto;
        return static_cast<size_t>(mix64(h));
    }
};

}  // namespace pm
