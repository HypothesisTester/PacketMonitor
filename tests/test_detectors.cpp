#include <gtest/gtest.h>

#include <cmath>
#include <random>

#include "Builders.h"
#include "analysis/Detectors.h"

using namespace pm;
using namespace pmtest;

namespace {
constexpr int64_t kSec = 1000000;
const int64_t kT0 = 1'800'000'000LL * kSec;
}  // namespace

TEST(PortScan, AlertsAtTheThresholdOnce) {
    DetectorConfig cfg;
    PortScanDetector d(cfg);
    AlertList out;
    const IpAddr scanner = ip("10.0.0.66"), target = ip("10.0.0.5");
    for (int p = 1; p < cfg.scanPorts; p++) d.onAttempt(kT0 + p * 1000, scanner, target, uint16_t(p));
    d.tick(kT0 + kSec, out);
    EXPECT_TRUE(out.empty()) << "one port short of a scan";

    d.onAttempt(kT0 + kSec + 5, scanner, target, 9999);
    d.tick(kT0 + 2 * kSec, out);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0].kind, AlertKind::PortScan);
    EXPECT_EQ(out[0].src, "10.0.0.66");
    EXPECT_NE(out[0].message.find("tried 20 ports"), std::string::npos) << out[0].message;

    // Still scanning, but within the cooldown: no repeat.
    for (int p = 100; p < 200; p++) d.onAttempt(kT0 + 3 * kSec, scanner, target, uint16_t(p));
    d.tick(kT0 + 4 * kSec, out);
    EXPECT_EQ(out.size(), 1u);

    // Old attempts age out and the state is dropped.
    d.tick(kT0 + 30 * kSec, out);
    EXPECT_EQ(d.tracked(), 0u);
}

TEST(PortScan, SourcesAndTargetsDoNotAddUp) {
    DetectorConfig cfg;
    PortScanDetector d(cfg);
    AlertList out;
    // A browser opening many connections to port 443 on many hosts is not a scan.
    for (int h = 0; h < 200; h++) {
        IpAddr dst = ip("93.184.0.0");
        dst.bytes[3] = uint8_t(h);
        d.onAttempt(kT0 + h, ip("192.168.1.2"), dst, 443);
    }
    // Nor are ten machines each trying ten ports.
    for (int s = 0; s < 10; s++) {
        IpAddr src = ip("10.0.0.0");
        src.bytes[3] = uint8_t(s);
        for (int p = 0; p < 10; p++) d.onAttempt(kT0 + p, src, ip("10.0.0.99"), uint16_t(p));
    }
    d.tick(kT0 + kSec, out);
    EXPECT_TRUE(out.empty());
}

TEST(SynFlood, AttemptsThatNeverCompleteAlert) {
    DetectorConfig cfg;
    SynFloodDetector d(cfg);
    AlertList out;
    const IpAddr server = ip("10.0.0.5");
    for (int i = 0; i < 1500; i++) d.onAttempt(kT0 + i * 1000, server, 80);  // 1000 a second
    d.tick(kT0 + 2 * kSec, out);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0].kind, AlertKind::SynFlood);
    EXPECT_EQ(out[0].dst, "10.0.0.5:80");
    EXPECT_NE(out[0].message.find("0% completed"), std::string::npos) << out[0].message;
}

TEST(SynFlood, BusyButHealthyServersDoNotAlert) {
    DetectorConfig cfg;
    SynFloodDetector d(cfg);
    AlertList out;
    const IpAddr server = ip("10.0.0.5");
    for (int i = 0; i < 1500; i++) {
        d.onAttempt(kT0 + i * 1000, server, 443);
        if (i % 10 != 0) d.onCompleted(kT0 + i * 1000 + 500, server, 443);  // 90% complete
    }
    for (int i = 0; i < 200; i++) d.onAttempt(kT0 + i * 20000, server, 25);  // 50 a second, none complete
    d.tick(kT0 + 2 * kSec, out);
    EXPECT_TRUE(out.empty());
}

TEST(Spike, SustainedJumpAlertsOnceAfterWarmUp) {
    DetectorConfig cfg;
    SpikeDetector d(cfg, "Inbound");
    AlertList out;
    std::mt19937 rng(3);
    std::uniform_real_distribution<double> noise(0.9, 1.1);
    int64_t t = kT0;
    for (int s = 0; s < 120; s++, t += kSec) {
        // A few silent seconds must not ruin the baseline.
        d.onSecond(t, s < 3 ? 0 : 2e6 * noise(rng), out);
    }
    EXPECT_TRUE(out.empty());
    EXPECT_NEAR(d.usualBytesPerSec(), 2e6, 2e5);
    d.onSecond(t += kSec, 40e6, out);
    d.onSecond(t += kSec, 40e6, out);
    EXPECT_TRUE(out.empty()) << "needs three seconds in a row";
    d.onSecond(t += kSec, 40e6, out);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0].kind, AlertKind::TrafficSpike);
    EXPECT_NE(out[0].message.find("20× the usual"), std::string::npos) << out[0].message;
    for (int s = 0; s < 20; s++) d.onSecond(t += kSec, 40e6, out);
    EXPECT_EQ(out.size(), 1u) << "one alert per spike";
}

TEST(Spike, NoAlertDuringWarmUpOrForGradualGrowthOrTinyTraffic) {
    DetectorConfig cfg;
    AlertList out;
    {
        SpikeDetector d(cfg, "Inbound");
        for (int s = 0; s < 10; s++) d.onSecond(kT0 + s * kSec, 1e3, out);
        for (int s = 10; s < 20; s++) d.onSecond(kT0 + s * kSec, 50e6, out);
    }
    {
        SpikeDetector d(cfg, "Inbound");
        for (int s = 0; s < 600; s++) d.onSecond(kT0 + s * kSec, 1e6 * std::pow(2.0, s / 300.0), out);
    }
    {
        SpikeDetector d(cfg, "Outbound");
        for (int s = 0; s < 120; s++) d.onSecond(kT0 + s * kSec, 2e3, out);
        for (int s = 120; s < 130; s++) d.onSecond(kT0 + s * kSec, 400e3, out);  // 200×, but under 1 MB/s
    }
    EXPECT_TRUE(out.empty());
}

TEST(Alerts, JsonIsEscaped) {
    Alert a;
    a.tsUsec = 0;
    a.kind = AlertKind::Signature;
    a.severity = Severity::High;
    a.title = "Quote \" and backslash \\";
    a.message = "line\nbreak";
    a.src = "1.2.3.4:5";
    EXPECT_EQ(alertToJson(a),
              "{\"time\":\"1970-01-01T00:00:00.000Z\",\"type\":\"signature\",\"severity\":\"high\","
              "\"title\":\"Quote \\\" and backslash \\\\\",\"message\":\"line\\nbreak\",\"src\":\"1.2.3.4:5\"}");
}
