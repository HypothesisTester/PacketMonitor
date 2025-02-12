// src/AnomalyDetector.cpp
#include "AnomalyDetector.h"
#include <chrono>

AnomalyDetector::AnomalyDetector(int threshold, int timeWindowSeconds)
    : threshold_(threshold), timeWindowSeconds_(timeWindowSeconds) {}

void AnomalyDetector::trackPacket(const Packet &packet) {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(mtx_);
    packetRecords_.push_back(PacketRecord{now, packet.srcIP});
    packetCounts_[packet.srcIP]++;
}

std::vector<Anomaly> AnomalyDetector::detectAnomalies() {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<Anomaly> anomalies;
    auto now = std::chrono::steady_clock::now();
    // Clean up records outside the sliding window.
    while (!packetRecords_.empty()) {
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - packetRecords_.front().timestamp).count();
        if (duration > timeWindowSeconds_) {
            packetCounts_[packetRecords_.front().srcIP]--;
            packetRecords_.pop_front();
        } else {
            break;
        }
    }
    // Check for anomalies.
    for (const auto &entry : packetCounts_) {
        if (entry.second > threshold_) {
            anomalies.push_back(Anomaly{entry.first, entry.second});
        }
    }
    return anomalies;
}