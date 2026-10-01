#include "core/Decoder.h"

#include <algorithm>

namespace pm {
namespace {

inline uint16_t be16(const uint8_t* p) { return uint16_t(p[0] << 8 | p[1]); }
inline uint32_t be32(const uint8_t* p) {
    return uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | p[3];
}
inline uint32_t le32(const uint8_t* p) {
    return uint32_t(p[3]) << 24 | uint32_t(p[2]) << 16 | uint32_t(p[1]) << 8 | p[0];
}

constexpr uint16_t kEtherIpv4 = 0x0800;
constexpr uint16_t kEtherIpv6 = 0x86DD;

/** Decodes the transport header. avail is what was captured, total what the IP header claims. */
DecodeResult decodeTransport(const uint8_t* p, uint32_t avail, uint32_t total, PacketView& out) {
    switch (out.proto) {
    case kProtoTcp: {
        if (avail < 20) return DecodeResult::Ok;  // header cut off by the snap length
        uint32_t doff = uint32_t(p[12] >> 4) * 4;
        if (doff < 20 || total < doff) return DecodeResult::Malformed;
        out.hasL4 = true;
        out.sport = be16(p);
        out.dport = be16(p + 2);
        out.seq = be32(p + 4);
        out.ack = be32(p + 8);
        out.tcpFlags = p[13];
        out.payloadTotal = total - doff;
        if (doff <= avail) {
            out.payload = p + doff;
            out.payloadLen = std::min(avail - doff, out.payloadTotal);
        }
        return DecodeResult::Ok;
    }
    case kProtoUdp: {
        if (avail < 8) return DecodeResult::Ok;
        uint32_t ulen = be16(p + 4);
        if (ulen == 0) ulen = total;  // jumbogram: the IP layer carries the length
        if (ulen < 8 || total < 8) return DecodeResult::Malformed;
        out.hasL4 = true;
        out.sport = be16(p);
        out.dport = be16(p + 2);
        out.payloadTotal = std::min(ulen, total) - 8;
        out.payload = p + 8;
        out.payloadLen = std::min(avail - 8, out.payloadTotal);
        return DecodeResult::Ok;
    }
    case kProtoIcmp:
    case kProtoIcmp6:
        if (avail < 2) return DecodeResult::Ok;
        out.hasL4 = true;
        out.icmpType = p[0];
        out.icmpCode = p[1];
        return DecodeResult::Ok;
    default:
        return DecodeResult::Ok;
    }
}

DecodeResult decodeIpv4(const uint8_t* p, uint32_t n, PacketView& out) {
    if (n < 20 || (p[0] >> 4) != 4) return DecodeResult::Malformed;
    uint32_t ihl = uint32_t(p[0] & 0x0f) * 4;
    if (ihl < 20 || ihl > n) return DecodeResult::Malformed;
    uint32_t totalLen = be16(p + 2);
    // Segmentation offload can leave the length as 0 in outbound captures.
    if (totalLen == 0) totalLen = n;
    if (totalLen < ihl) return DecodeResult::Malformed;
    uint32_t end = std::min(n, totalLen);  // drops Ethernet padding

    out.ipVersion = 4;
    out.src = IpAddr::v4(p + 12);
    out.dst = IpAddr::v4(p + 16);
    out.proto = p[9];
    out.fragment = (be16(p + 6) & 0x1fff) != 0;
    if (out.fragment) return DecodeResult::Ok;
    return decodeTransport(p + ihl, end - ihl, totalLen - ihl, out);
}

DecodeResult decodeIpv6(const uint8_t* p, uint32_t n, PacketView& out) {
    if (n < 40 || (p[0] >> 4) != 6) return DecodeResult::Malformed;
    uint32_t payloadLen = be16(p + 4);
    if (payloadLen == 0) payloadLen = n - 40;  // jumbogram or offload: use what we have
    uint32_t totalLen = 40 + payloadLen;
    uint32_t end = std::min(n, totalLen);

    out.ipVersion = 6;
    out.src = IpAddr::v6(p + 8);
    out.dst = IpAddr::v6(p + 24);

    uint8_t next = p[6];
    uint32_t off = 40;
    for (int i = 0; i < 8; i++) {
        if (next == 0 || next == 43 || next == 60 || next == 51) {  // hop-by-hop, routing, destination, AH
            if (off + 2 > end) return DecodeResult::Malformed;
            uint32_t len = next == 51 ? (uint32_t(p[off + 1]) + 2) * 4 : (uint32_t(p[off + 1]) + 1) * 8;
            next = p[off];
            off += len;
            if (off > end) return DecodeResult::Malformed;
        } else if (next == 44) {  // fragment
            if (off + 8 > end) return DecodeResult::Malformed;
            uint16_t fragOff = be16(p + off + 2) >> 3;
            next = p[off];
            off += 8;
            if (fragOff != 0) {
                out.proto = next;
                out.fragment = true;
                return DecodeResult::Ok;
            }
        } else {
            break;
        }
    }
    out.proto = next;
    return decodeTransport(p + off, end - off, totalLen - off, out);
}

DecodeResult decodeIp(const uint8_t* p, uint32_t n, PacketView& out) {
    if (n < 1) return DecodeResult::Malformed;
    switch (p[0] >> 4) {
    case 4: return decodeIpv4(p, n, out);
    case 6: return decodeIpv6(p, n, out);
    default: return DecodeResult::NotIp;
    }
}

DecodeResult decodeEtherType(uint16_t type, const uint8_t* p, uint32_t n, PacketView& out) {
    if (type == kEtherIpv4) return decodeIpv4(p, n, out);
    if (type == kEtherIpv6) return decodeIpv6(p, n, out);
    return DecodeResult::NotIp;
}

}  // namespace

bool linkTypeSupported(int t) {
    switch (t) {
    case kLinkNull: case kLinkEthernet: case kLinkRaw: case kLinkRawOpenBsd: case kLinkRawFile:
    case kLinkLoop: case kLinkLinuxSll: case kLinkIpv4: case kLinkIpv6: case kLinkLinuxSll2:
        return true;
    default:
        return false;
    }
}

const char* linkTypeName(int t) {
    switch (t) {
    case kLinkNull: return "loopback";
    case kLinkEthernet: return "Ethernet";
    case kLinkRaw: case kLinkRawOpenBsd: case kLinkRawFile: case kLinkIpv4: case kLinkIpv6: return "raw IP";
    case kLinkLoop: return "loopback";
    case kLinkLinuxSll: case kLinkLinuxSll2: return "Linux cooked";
    default: return "unknown";
    }
}

DecodeResult decode(int linkType, const uint8_t* data, uint32_t capLen, uint32_t wireLen, int64_t tsUsec,
                    PacketView& out) {
    out = PacketView{};
    out.tsUsec = tsUsec;
    out.capLen = capLen;
    out.wireLen = wireLen;
    const uint8_t* p = data;
    uint32_t n = capLen;

    switch (linkType) {
    case kLinkEthernet: {
        if (n < 14) return DecodeResult::Malformed;
        uint16_t type = be16(p + 12);
        uint32_t off = 14;
        // Up to two VLAN tags (802.1Q, 802.1ad, and the old QinQ value).
        for (int i = 0; i < 2 && (type == 0x8100 || type == 0x88a8 || type == 0x9100); i++) {
            if (off + 4 > n) return DecodeResult::Malformed;
            type = be16(p + off + 2);
            off += 4;
        }
        return decodeEtherType(type, p + off, n - off, out);
    }
    case kLinkNull:
    case kLinkLoop: {
        if (n < 4) return DecodeResult::Malformed;
        // The family is in the writer's byte order; accept either.
        uint32_t le = le32(p), be = be32(p);
        auto isV6 = [](uint32_t f) { return f == 24 || f == 28 || f == 30; };
        if (le == 2 || be == 2) return decodeIpv4(p + 4, n - 4, out);
        if (isV6(le) || isV6(be)) return decodeIpv6(p + 4, n - 4, out);
        return DecodeResult::NotIp;
    }
    case kLinkRaw:
    case kLinkRawOpenBsd:
    case kLinkRawFile:
    case kLinkIpv4:
    case kLinkIpv6:
        return decodeIp(p, n, out);
    case kLinkLinuxSll:
        if (n < 16) return DecodeResult::Malformed;
        return decodeEtherType(be16(p + 14), p + 16, n - 16, out);
    case kLinkLinuxSll2:
        if (n < 20) return DecodeResult::Malformed;
        return decodeEtherType(be16(p), p + 20, n - 20, out);
    default:
        return DecodeResult::NotIp;
    }
}

}  // namespace pm
