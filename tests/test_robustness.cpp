// Feeds random and mutated bytes to every parser. Run under AddressSanitizer
// (cmake -DPM_SANITIZE=ON, as CI does), any read out of bounds fails the test.
#include <gtest/gtest.h>

#include <random>

#include "Builders.h"
#include "analysis/Dns.h"
#include "analysis/Engine.h"
#include "analysis/Tls.h"
#include "core/Decoder.h"

namespace pm {
extern const char* const kDefaultSignatures;
}

using namespace pm;
using namespace pmtest;

namespace {

Bytes mutate(Bytes b, std::mt19937& rng) {
    int edits = 1 + int(rng() % 4);
    for (int i = 0; i < edits && !b.empty(); i++) {
        switch (rng() % 3) {
        case 0: b[rng() % b.size()] = uint8_t(rng()); break;
        case 1: b.resize(rng() % (b.size() + 1)); break;
        default: b[rng() % b.size()] ^= uint8_t(1u << (rng() % 8)); break;
        }
    }
    return b;
}

std::vector<Bytes> seeds() {
    std::vector<Bytes> s;
    s.push_back(ethernet(0x0800, ipv4(ip("10.0.0.1"), ip("1.1.1.1"), kProtoTcp,
                                      tcp(5000, 443, 1, 0, kTcpSyn, {}, 12))));
    s.push_back(ethernet(0x0800, ipv4(ip("10.0.0.1"), ip("1.1.1.1"), kProtoTcp,
                                      tcp(5000, 443, 2, 1, kTcpAck | kTcpPsh, clientHello("x.example", 300)))));
    s.push_back(ethernet(0x0800, ipv4(ip("1.1.1.1"), ip("10.0.0.1"), kProtoUdp,
                                      udp(53, 5000, dnsResponse("a.example", {ip("1.2.3.4")}, "b.example")))));
    s.push_back(ethernet(0x86dd, ipv6(ip("2001:db8::1"), ip("2001:db8::2"), kProtoUdp, udp(1, 443, Bytes(40, 7)))));
    return s;
}

}  // namespace

TEST(Robustness, DecoderSurvivesRandomAndMutatedInput) {
    std::mt19937 rng(11);
    const int links[] = {kLinkEthernet, kLinkNull, kLinkRaw, kLinkLinuxSll, kLinkLinuxSll2, kLinkLoop};
    auto base = seeds();
    for (int i = 0; i < 100000; i++) {
        Bytes b = i % 2 ? mutate(base[size_t(i) % base.size()], rng) : Bytes(rng() % 128);
        if (i % 2 == 0) {
            for (auto& x : b) x = uint8_t(rng());
        }
        PacketView p;
        int link = links[size_t(i) % 6];
        decode(link, b.data(), uint32_t(b.size()), uint32_t(b.size() + rng() % 100), 0, p);
        if (p.payloadLen) {
            ASSERT_LE(p.payload + p.payloadLen, b.data() + b.size());
        }
    }
}

TEST(Robustness, DnsAndTlsParsersSurviveMutations) {
    std::mt19937 rng(12);
    Bytes dns = dnsResponse("www.example.com", {ip("1.2.3.4"), ip("5.6.7.8")}, "cdn.example.net");
    Bytes hello = clientHello("www.example.com", 200);
    for (int i = 0; i < 100000; i++) {
        Bytes d = mutate(dns, rng);
        DnsMessage m;
        parseDns(d.data(), d.size(), m);
        parseDnsTcp(d.data(), d.size(), m);
        Bytes h = mutate(hello, rng);
        std::string host;
        extractSni(h.data(), h.size(), host);
        ASSERT_LE(host.size(), 253u);
    }
}

TEST(Robustness, EngineSurvivesGarbage) {
    SignatureSet sigs;
    std::string error;
    ASSERT_TRUE(sigs.parse(kDefaultSignatures, error));
    EngineConfig cfg;
    Engine engine(cfg, &sigs, nullptr);
    std::mt19937 rng(13);
    auto base = seeds();
    int64_t ts = 1'800'000'000LL * 1000000;
    for (int i = 0; i < 50000; i++) {
        Bytes b = mutate(base[size_t(i) % base.size()], rng);
        PacketRecordHeader h{0, uint32_t(b.size()), uint32_t(b.size()), 0, ts};
        engine.process(h, b.data());
        ts += rng() % 3000;
    }
    engine.finish();
    EXPECT_EQ(engine.packets(), 50000u);
    EXPECT_NE(engine.snapshot(), nullptr);
}
