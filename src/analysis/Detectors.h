// Detectors that look at traffic patterns rather than payloads.
//
// Each detector takes events with their capture timestamps and is ticked once
// a second, so replaying a capture gives the same alerts as watching it live.
#pragma once

#include <cmath>
#include <cstdint>
#include <deque>
#include <unordered_map>
#include <vector>

#include "analysis/Alert.h"
#include "core/Packet.h"

namespace pm {

struct DetectorConfig {
    // Port scan: one source trying many ports on one host.
    int scanPorts = 20;          // distinct ports within the window
    int scanWindowSec = 10;
    // SYN flood: many connection attempts to one service that never complete.
    double floodSynPerSec = 100;
    double floodMaxCompleted = 0.2;  // fraction of attempts that finished the handshake
    int floodWindowSec = 5;
    // Traffic spike: a second far above the usual level for this network.
    double spikeSigma = 4.0;         // robust standard deviations, on a log scale
    double spikeMinBytesPerSec = 1e6;
    int spikeWarmupSec = 60;
    int spikeSustainSec = 3;
    int spikeWindowSec = 300;        // what "usual" is measured over
    // Repeat alerts about the same thing at most this often.
    int cooldownSec = 60;
};

using AlertList = std::vector<Alert>;

class PortScanDetector {
public:
    explicit PortScanDetector(const DetectorConfig& c) : cfg_(c) {}
    /** A connection attempt: TCP SYN without ACK. */
    void onAttempt(int64_t tsUsec, const IpAddr& src, const IpAddr& dst, uint16_t dport);
    void tick(int64_t nowUsec, AlertList& out);
    void reset() { pairs_.clear(); }
    size_t tracked() const { return pairs_.size(); }

private:
    struct PairKey {
        IpAddr src, dst;
        bool operator==(const PairKey& o) const { return src == o.src && dst == o.dst; }
    };
    struct PairHash {
        size_t operator()(const PairKey& k) const { return size_t(mix64(hashAddr(k.src) * 3 + hashAddr(k.dst))); }
    };
    struct State {
        std::unordered_map<uint16_t, int64_t> lastTry;  // port -> last attempt
        int64_t lastAlert = INT64_MIN / 2;
    };
    DetectorConfig cfg_;
    std::unordered_map<PairKey, State, PairHash> pairs_;
};

class SynFloodDetector {
public:
    explicit SynFloodDetector(const DetectorConfig& c) : cfg_(c) {}
    void onAttempt(int64_t tsUsec, const IpAddr& dst, uint16_t dport);
    void onCompleted(int64_t tsUsec, const IpAddr& dst, uint16_t dport);
    void tick(int64_t nowUsec, AlertList& out);
    void reset() { targets_.clear(); }

private:
    struct Key {
        IpAddr addr;
        uint16_t port;
        bool operator==(const Key& o) const { return port == o.port && addr == o.addr; }
    };
    struct KeyHash {
        size_t operator()(const Key& k) const { return size_t(mix64(hashAddr(k.addr) ^ k.port)); }
    };
    struct Second {
        int64_t sec = 0;
        uint32_t attempts = 0, completed = 0;
    };
    struct State {
        std::deque<Second> seconds;
        int64_t lastAlert = INT64_MIN / 2;
    };
    Second& bucket(int64_t tsUsec, const Key& k);

    DetectorConfig cfg_;
    std::unordered_map<Key, State, KeyHash> targets_;
};

/**
 * Flags traffic far above this network's usual level. Works on
 * log(1 + bytes per second), so a jump from 1 MB/s to 20 MB/s counts the same
 * as one from 10 kB/s to 200 kB/s. "Usual" is the median of the last five
 * minutes and the spread is the median absolute deviation, which quiet
 * seconds and short bursts barely move, unlike a mean and variance. Alerts
 * when the level stays several spreads above the median for a few seconds.
 */
class SpikeDetector {
public:
    SpikeDetector(const DetectorConfig& c, const char* direction) : cfg_(c), direction_(direction) {}
    void onSecond(int64_t tsUsec, double bytes, AlertList& out);

    /** Median bytes per second over the window. */
    double usualBytesPerSec() const { return std::expm1(median_); }
    double lastZ() const { return lastZ_; }

private:
    DetectorConfig cfg_;
    const char* direction_;
    std::deque<double> window_;  // log(1 + bytes) per second, oldest first
    std::vector<double> scratch_;
    double median_ = 0;
    int highRun_ = 0;
    double lastZ_ = 0;
    int64_t lastAlert_ = INT64_MIN / 2;
};

}  // namespace pm
