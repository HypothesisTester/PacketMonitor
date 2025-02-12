// src/AnomalyDetector.h
#ifndef ANOMALYDETECTOR_H
#define ANOMALYDETECTOR_H

#include <unordered_map>
#include <string>
#include <vector>
#include <mutex>
#include <deque>
#include <chrono>
#include "PacketCapture.h"

// Structure to hold anomaly details.
struct Anomaly {
    std::string ip;
    int packetCount;
};

// Each packet record includes the timestamp and source IP.
struct PacketRecord {
    std::chrono::steady_clock::time_point timestamp;
    std::string srcIP;
};

class AnomalyDetector {
public:
    // threshold: number of packets; timeWindowSeconds: sliding window length.
    AnomalyDetector(int threshold, int timeWindowSeconds);
    void trackPacket(const Packet &packet);
    std::vector<Anomaly> detectAnomalies();

private:
    int threshold_;
    int timeWindowSeconds_; // In seconds
    std::deque<PacketRecord> packetRecords_;
    std::unordered_map<std::string, int> packetCounts_;
    std::mutex mtx_;
};

#endif // ANOMALYDETECTOR_H