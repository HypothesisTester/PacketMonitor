// src/UI.h
#ifndef UI_H
#define UI_H

#include <vector>
#include <string>
#include <mutex>
#include <thread>
#include <atomic>
#include "PacketCapture.h"        // For Packet and FlaggedPacket
#include "AnomalyDetector.h"      // For Anomaly

class UI {
public:
    UI();
    ~UI();

    void start();
    void stop();

    // Update functions to add data for display.
    void addFlaggedPacket(const FlaggedPacket &flaggedPkt);
    void addAnomaly(const Anomaly &anomaly);

private:
    void run();
    void refreshDisplay();

    std::thread uiThread_;
    std::atomic<bool> running_;

    std::vector<FlaggedPacket> flaggedPackets_;
    std::vector<Anomaly> anomalies_;

    std::mutex dataMutex_;
};

#endif // UI_H