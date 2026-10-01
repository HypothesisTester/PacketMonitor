#include <gtest/gtest.h>

#include "Builders.h"
#include "core/Decoder.h"

using namespace pm;
using namespace pmtest;

namespace {

PacketView decodeOk(int link, const Bytes& b, uint32_t wire = 0) {
    PacketView p;
    EXPECT_EQ(decode(link, b.data(), uint32_t(b.size()), wire ? wire : uint32_t(b.size()), 42, p), DecodeResult::Ok);
    return p;
}

}  // namespace

TEST(Decoder, TcpOverEthernetWithOptions) {
    Bytes seg = tcp(51234, 443, 1000, 2000, kTcpPsh | kTcpAck, text("hello"), 12);
    Bytes pkt = ethernet(0x0800, ipv4(ip("10.0.0.2"), ip("93.184.216.34"), kProtoTcp, seg));
    PacketView p = decodeOk(kLinkEthernet, pkt);
    EXPECT_EQ(p.ipVersion, 4);
    EXPECT_EQ(p.src.str(), "10.0.0.2");
    EXPECT_EQ(p.dst.str(), "93.184.216.34");
    EXPECT_TRUE(p.hasL4);
    EXPECT_EQ(p.sport, 51234);
    EXPECT_EQ(p.dport, 443);
    EXPECT_EQ(p.seq, 1000u);
    EXPECT_EQ(p.ack, 2000u);
    EXPECT_EQ(p.tcpFlags, kTcpPsh | kTcpAck);
    // The payload starts after the 32-byte header, not a fixed 20 bytes.
    ASSERT_EQ(p.payloadLen, 5u);
    EXPECT_EQ(std::string(reinterpret_cast<const char*>(p.payload), 5), "hello");
    EXPECT_EQ(p.tsUsec, 42);
}

TEST(Decoder, EthernetPaddingIsNotPayload) {
    Bytes pkt = ethernet(0x0800, ipv4(ip("10.0.0.2"), ip("10.0.0.3"), kProtoTcp, tcp(1, 2, 0, 0, kTcpAck, {})));
    pkt.resize(60, 0);  // minimum Ethernet frame
    PacketView p = decodeOk(kLinkEthernet, pkt);
    EXPECT_EQ(p.payloadLen, 0u);
    EXPECT_EQ(p.payloadTotal, 0u);
}

TEST(Decoder, UdpOverVlan) {
    Bytes inner = ipv4(ip("192.168.1.5"), ip("8.8.8.8"), kProtoUdp, udp(5353, 53, text("abc")));
    Bytes tagged;
    put16(tagged, 0x0064);  // VLAN 100
    put16(tagged, 0x0800);
    append(tagged, inner);
    PacketView p = decodeOk(kLinkEthernet, ethernet(0x8100, tagged));
    EXPECT_EQ(p.proto, kProtoUdp);
    EXPECT_EQ(p.dport, 53);
    EXPECT_EQ(p.payloadLen, 3u);
}

TEST(Decoder, Ipv6ExtensionHeaders) {
    Bytes body;
    // Hop-by-hop options (8 bytes), then a first fragment, then UDP.
    body.push_back(44);
    body.push_back(0);
    body.insert(body.end(), 6, 0);
    body.push_back(kProtoUdp);
    body.push_back(0);
    put16(body, 0x0001);  // offset 0, more fragments
    put32(body, 7);
    append(body, udp(1000, 2000, text("xyz")));
    PacketView p = decodeOk(kLinkRaw, ipv6(ip("2001:db8::1"), ip("2001:db8::2"), 0, body));
    EXPECT_EQ(p.ipVersion, 6);
    EXPECT_FALSE(p.fragment);
    EXPECT_EQ(p.proto, kProtoUdp);
    EXPECT_EQ(p.sport, 1000);
    EXPECT_EQ(p.payloadLen, 3u);
}

TEST(Decoder, NonFirstFragmentsHaveNoPorts) {
    Bytes v4 = ipv4(ip("1.2.3.4"), ip("5.6.7.8"), kProtoUdp, text("continuation"), 0x0010);
    PacketView p = decodeOk(kLinkRaw, v4);
    EXPECT_TRUE(p.fragment);
    EXPECT_FALSE(p.hasL4);

    Bytes body;
    body.push_back(kProtoTcp);
    body.push_back(0);
    put16(body, 0x0100);  // offset 32
    put32(body, 9);
    append(body, text("more data"));
    PacketView q = decodeOk(kLinkRaw, ipv6(ip("::1"), ip("::2"), 44, body));
    EXPECT_TRUE(q.fragment);
    EXPECT_EQ(q.proto, kProtoTcp);
}

TEST(Decoder, LinkTypes) {
    Bytes ip4 = ipv4(ip("127.0.0.1"), ip("127.0.0.1"), kProtoTcp, tcp(5000, 6000, 1, 0, kTcpSyn, {}));
    Bytes ip6 = ipv6(ip("::1"), ip("::1"), kProtoUdp, udp(1, 2, text("v6")));

    // BSD loopback: the family in host order; macOS uses 30 for IPv6.
    Bytes nullLe = {2, 0, 0, 0};
    append(nullLe, ip4);
    EXPECT_EQ(decodeOk(kLinkNull, nullLe).dport, 6000);
    Bytes loopBe = {0, 0, 0, 30};
    append(loopBe, ip6);
    EXPECT_EQ(decodeOk(kLinkLoop, loopBe).payloadLen, 2u);

    // Linux cooked captures.
    Bytes sll(14, 0);
    put16(sll, 0x86dd);
    append(sll, ip6);
    EXPECT_EQ(decodeOk(kLinkLinuxSll, sll).ipVersion, 6);
    Bytes sll2;
    put16(sll2, 0x0800);
    sll2.insert(sll2.end(), 18, 0);
    append(sll2, ip4);
    EXPECT_EQ(decodeOk(kLinkLinuxSll2, sll2).sport, 5000);

    EXPECT_EQ(decodeOk(kLinkRawFile, ip4).ipVersion, 4);
    EXPECT_EQ(decodeOk(kLinkIpv6, ip6).ipVersion, 6);
}

TEST(Decoder, NotIpAndMalformed) {
    PacketView p;
    Bytes arp = ethernet(0x0806, Bytes(28, 0));
    EXPECT_EQ(decode(kLinkEthernet, arp.data(), uint32_t(arp.size()), uint32_t(arp.size()), 0, p), DecodeResult::NotIp);

    Bytes badIhl = ipv4(ip("1.1.1.1"), ip("2.2.2.2"), kProtoTcp, tcp(1, 2, 0, 0, 0, {}));
    badIhl[0] = 0x44;  // header length 16
    EXPECT_EQ(decode(kLinkRaw, badIhl.data(), uint32_t(badIhl.size()), uint32_t(badIhl.size()), 0, p),
              DecodeResult::Malformed);

    Bytes badOffset = ipv4(ip("1.1.1.1"), ip("2.2.2.2"), kProtoTcp, tcp(1, 2, 0, 0, 0, {}));
    badOffset[20 + 12] = 0x30;  // data offset 12 bytes
    EXPECT_EQ(decode(kLinkRaw, badOffset.data(), uint32_t(badOffset.size()), uint32_t(badOffset.size()), 0, p),
              DecodeResult::Malformed);

    EXPECT_EQ(decode(kLinkEthernet, arp.data(), 10, 10, 0, p), DecodeResult::Malformed);
}

TEST(Decoder, TruncatedCaptureKeepsTrueLength) {
    Bytes data(1000, 'x');
    Bytes pkt = ethernet(0x0800, ipv4(ip("10.1.1.1"), ip("10.1.1.2"), kProtoTcp, tcp(80, 5555, 7, 9, kTcpAck, data)));
    const uint32_t snap = 14 + 20 + 20 + 100;
    PacketView p;
    ASSERT_EQ(decode(kLinkEthernet, pkt.data(), snap, uint32_t(pkt.size()), 0, p), DecodeResult::Ok);
    EXPECT_EQ(p.payloadLen, 100u);
    EXPECT_EQ(p.payloadTotal, 1000u);
    EXPECT_TRUE(p.payloadTruncated());
    EXPECT_EQ(p.wireLen, pkt.size());
}

TEST(Decoder, UdpJumbogramLengthFallsBackToIp) {
    Bytes pkt = ipv4(ip("10.0.0.1"), ip("10.0.0.2"), kProtoUdp, udp(1, 2, text("12345"), 0));
    PacketView p = decodeOk(kLinkRaw, pkt);
    EXPECT_EQ(p.payloadLen, 5u);
}

TEST(Decoder, EveryPrefixStaysInBounds) {
    Bytes pkt = ethernet(0x0800, ipv4(ip("10.0.0.2"), ip("10.0.0.3"), kProtoTcp,
                                      tcp(1234, 80, 1, 1, kTcpAck, text("GET / HTTP/1.1\r\n"), 8)));
    for (size_t n = 0; n <= pkt.size(); n++) {
        Bytes copy(pkt.begin(), pkt.begin() + long(n));  // exact-size buffer, so ASan catches overreads
        PacketView p;
        decode(kLinkEthernet, copy.data(), uint32_t(n), uint32_t(pkt.size()), 0, p);
        if (p.payloadLen) {
            EXPECT_GE(p.payload, copy.data());
            EXPECT_LE(p.payload + p.payloadLen, copy.data() + n);
        }
    }
}

TEST(FlowKey, SameForBothDirections) {
    PacketView a, b;
    a.src = ip("10.0.0.1"), a.dst = ip("10.0.0.2"), a.sport = 1111, a.dport = 443, a.proto = kProtoTcp, a.hasL4 = true;
    b.src = a.dst, b.dst = a.src, b.sport = 443, b.dport = 1111, b.proto = kProtoTcp, b.hasL4 = true;
    bool aIsA, bIsA;
    FlowKey ka = FlowKey::of(a, aIsA), kb = FlowKey::of(b, bIsA);
    EXPECT_EQ(ka, kb);
    EXPECT_NE(aIsA, bIsA);
    EXPECT_EQ(FlowKeyHash{}(ka), FlowKeyHash{}(kb));
}

TEST(IpAddr, Classification) {
    EXPECT_TRUE(ip("192.168.1.9").isPrivate());
    EXPECT_TRUE(ip("172.20.0.1").isPrivate());
    EXPECT_FALSE(ip("172.32.0.1").isPrivate());
    EXPECT_TRUE(ip("fe80::1").isPrivate());
    EXPECT_TRUE(ip("fd12::1").isPrivate());
    EXPECT_FALSE(ip("2a00:1450::1").isPrivate());
    EXPECT_TRUE(ip("::ffff:10.0.0.1").isPrivate());
    EXPECT_EQ(ip("::ffff:10.0.0.1").unmapped(), ip("10.0.0.1"));
    EXPECT_TRUE(ip("224.0.0.251").isMulticastOrBroadcast());
    EXPECT_TRUE(ip("::1").isLoopback());
    EXPECT_FALSE(IpAddr::parse("300.1.1.1").has_value());
}
