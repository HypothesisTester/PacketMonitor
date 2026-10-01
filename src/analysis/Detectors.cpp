#include "analysis/Detectors.h"

#include <algorithm>
#include <cmath>
#include <cstdio>

#include "core/Format.h"

namespace pm {
namespace {

constexpr int64_t kSec = 1000000;
constexpr size_t kMaxTracked = 100000;

}  // namespace

const char* alertKindId(AlertKind k) {
    switch (k) {
    case AlertKind::Signature: return "signature";
    case AlertKind::PortScan: return "port_scan";
    case AlertKind::SynFlood: return "syn_flood";
    case AlertKind::TrafficSpike: return "traffic_spike";
    }
    return "unknown";
}

std::string alertToJson(const Alert& a) {
    std::string s = "{\"time\":\"" + formatIsoUtc(a.tsUsec) + "\",\"type\":\"" + alertKindId(a.kind) +
                    "\",\"severity\":\"" + severityName(a.severity) + "\",\"title\":\"" + jsonEscape(a.title) +
                    "\",\"message\":\"" + jsonEscape(a.message) + "\"";
    if (!a.src.empty()) s += ",\"src\":\"" + jsonEscape(a.src) + "\"";
    if (!a.dst.empty()) s += ",\"dst\":\"" + jsonEscape(a.dst) + "\"";
    return s + "}";
}

// ---- Port scan ------------------------------------------------------------

void PortScanDetector::onAttempt(int64_t ts, const IpAddr& src, const IpAddr& dst, uint16_t dport) {
    PairKey key{src, dst};
    auto it = pairs_.find(key);
    if (it == pairs_.end()) {
        if (pairs_.size() >= kMaxTracked) return;
        it = pairs_.emplace(key, State{}).first;
    }
    auto& ports = it->second.lastTry;
    if (ports.size() < 65536) ports[dport] = ts;
}

void PortScanDetector::tick(int64_t now, AlertList& out) {
    const int64_t cutoff = now - int64_t(cfg_.scanWindowSec) * kSec;
    for (auto it = pairs_.begin(); it != pairs_.end();) {
        auto& st = it->second;
        for (auto p = st.lastTry.begin(); p != st.lastTry.end();) {
            p = p->second < cutoff ? st.lastTry.erase(p) : std::next(p);
        }
        if (st.lastTry.empty()) {
            it = pairs_.erase(it);
            continue;
        }
        if (st.lastTry.size() >= size_t(cfg_.scanPorts) && now - st.lastAlert >= int64_t(cfg_.cooldownSec) * kSec) {
            st.lastAlert = now;
            Alert a;
            a.tsUsec = now;
            a.kind = AlertKind::PortScan;
            a.severity = Severity::High;
            a.title = "Port scan";
            a.src = it->first.src.str();
            a.dst = it->first.dst.str();
            int64_t first = INT64_MAX, last = INT64_MIN;
            for (const auto& [port, when] : st.lastTry) {
                first = std::min(first, when);
                last = std::max(last, when);
            }
            char span[32];
            const double secs = double(last - first) / 1e6;
            if (secs < 0.9995) std::snprintf(span, sizeof span, "%.0f ms", secs * 1000);
            else std::snprintf(span, sizeof span, "%.1f s", secs);
            a.message = a.src + " tried " + formatCount(st.lastTry.size()) + " ports on " + a.dst + " in " + span;
            out.push_back(std::move(a));
        }
        ++it;
    }
}

// ---- SYN flood ------------------------------------------------------------

SynFloodDetector::Second& SynFloodDetector::bucket(int64_t ts, const Key& k) {
    static Second dummy;
    auto it = targets_.find(k);
    if (it == targets_.end()) {
        if (targets_.size() >= kMaxTracked) {
            dummy = Second{};
            return dummy;
        }
        it = targets_.emplace(k, State{}).first;
    }
    auto& secs = it->second.seconds;
    int64_t sec = ts / kSec;
    if (secs.empty() || secs.back().sec < sec) {
        secs.push_back(Second{sec, 0, 0});
        if (secs.size() > size_t(cfg_.floodWindowSec) + 2) secs.pop_front();
    }
    return secs.back();
}

void SynFloodDetector::onAttempt(int64_t ts, const IpAddr& dst, uint16_t dport) {
    bucket(ts, Key{dst, dport}).attempts++;
}

void SynFloodDetector::onCompleted(int64_t ts, const IpAddr& dst, uint16_t dport) {
    bucket(ts, Key{dst, dport}).completed++;
}

void SynFloodDetector::tick(int64_t now, AlertList& out) {
    const int64_t nowSec = now / kSec;
    for (auto it = targets_.begin(); it != targets_.end();) {
        auto& st = it->second;
        while (!st.seconds.empty() && st.seconds.front().sec < nowSec - cfg_.floodWindowSec) st.seconds.pop_front();
        if (st.seconds.empty()) {
            it = targets_.erase(it);
            continue;
        }
        uint64_t attempts = 0, completed = 0;
        for (const auto& s : st.seconds) {
            attempts += s.attempts;
            completed += s.completed;
        }
        const double perSec = double(attempts) / cfg_.floodWindowSec;
        if (perSec >= cfg_.floodSynPerSec && double(completed) <= cfg_.floodMaxCompleted * double(attempts) &&
            now - st.lastAlert >= int64_t(cfg_.cooldownSec) * kSec) {
            st.lastAlert = now;
            Alert a;
            a.tsUsec = now;
            a.kind = AlertKind::SynFlood;
            a.severity = Severity::High;
            a.title = "SYN flood";
            a.dst = it->first.addr.str() + ":" + std::to_string(it->first.port);
            char pct[16];
            std::snprintf(pct, sizeof pct, "%.0f%%", 100.0 * double(completed) / double(attempts));
            // The rate over the seconds the attempts arrived in, not the whole window.
            const int64_t busy = std::max<int64_t>(1, st.seconds.back().sec - st.seconds.front().sec + 1);
            a.message = a.dst + " got " + formatCount(attempts / uint64_t(busy)) + " connection attempts a second, " +
                        pct + " completed";
            out.push_back(std::move(a));
        }
        ++it;
    }
}

// ---- Traffic spike --------------------------------------------------------

void SpikeDetector::onSecond(int64_t ts, double bytes, AlertList& out) {
    const double x = std::log1p(std::max(0.0, bytes));
    const bool warm = int(window_.size()) >= cfg_.spikeWarmupSec;
    double z = 0;
    if (!window_.empty()) {
        scratch_.assign(window_.begin(), window_.end());
        auto mid = scratch_.begin() + long(scratch_.size() / 2);
        std::nth_element(scratch_.begin(), mid, scratch_.end());
        median_ = *mid;
        for (auto& v : scratch_) v = std::fabs(v - median_);
        std::nth_element(scratch_.begin(), mid, scratch_.end());
        // 1.4826 × MAD estimates the standard deviation of normal data. The
        // floor keeps a perfectly steady network from making small changes
        // look extreme: 0.25 on this scale is about a 28% change.
        const double sd = std::max(1.4826 * *mid, 0.25);
        z = (x - median_) / sd;
    }
    lastZ_ = z;

    const bool high = warm && z >= cfg_.spikeSigma && bytes >= cfg_.spikeMinBytesPerSec;
    highRun_ = high ? highRun_ + 1 : 0;
    if (highRun_ == cfg_.spikeSustainSec) {
        const int64_t cooldown = int64_t(std::max(cfg_.cooldownSec, 300)) * kSec;
        if (ts - lastAlert_ >= cooldown) {
            lastAlert_ = ts;
            const double usual = usualBytesPerSec();
            char detail[96];
            std::snprintf(detail, sizeof detail, ", %.0f× the usual %s (%.1fσ)", bytes / std::max(usual, 1.0),
                          formatRate(usual).c_str(), z);
            Alert a;
            a.tsUsec = ts;
            a.kind = AlertKind::TrafficSpike;
            a.severity = Severity::Medium;
            a.title = "Traffic spike";
            a.message = std::string(direction_) + " " + formatRate(bytes) + " for " +
                        std::to_string(cfg_.spikeSustainSec) + " s" + detail;
            out.push_back(std::move(a));
        }
    }

    window_.push_back(x);
    if (int(window_.size()) > cfg_.spikeWindowSec) window_.pop_front();
}

}  // namespace pm
