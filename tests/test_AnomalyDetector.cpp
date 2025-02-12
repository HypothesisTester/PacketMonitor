// tests/test_AnomalyDetector.cpp
#include <gtest/gtest.h>
#include "../src/AnomalyDetector.h"
#include "../src/PacketCapture.h"  // For the Packet struct

TEST(AnomalyDetectorTest, NoAnomalyWhenBelowThreshold) {
    // Create an anomaly detector with threshold 5 and a 10-second window.
    AnomalyDetector detector(5, 10);
    
    Packet pkt;
    pkt.srcIP = "192.168.1.1";
    pkt.payload = "test";
    
    // Track 3 packets (below threshold)
    for (int i = 0; i < 3; i++) {
        detector.trackPacket(pkt);
    }
    
    auto anomalies = detector.detectAnomalies();
    EXPECT_TRUE(anomalies.empty());
}

TEST(AnomalyDetectorTest, AnomalyWhenAboveThreshold) {
    // Create an anomaly detector with threshold 5.
    AnomalyDetector detector(5, 10);
    
    Packet pkt;
    pkt.srcIP = "192.168.1.2";
    pkt.payload = "test";
    
    // Track 6 packets (above threshold)
    for (int i = 0; i < 6; i++) {
        detector.trackPacket(pkt);
    }
    
    auto anomalies = detector.detectAnomalies();
    ASSERT_FALSE(anomalies.empty());
    // Verify that the anomaly is for IP "192.168.1.2" and count is at least 6.
    EXPECT_EQ(anomalies[0].ip, "192.168.1.2");
    EXPECT_GE(anomalies[0].packetCount, 6);
}