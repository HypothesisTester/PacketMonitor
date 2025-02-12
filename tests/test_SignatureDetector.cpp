// tests/test_SignatureDetector.cpp
#include <gtest/gtest.h>
#include "../src/SignatureDetector.h"
#include "../src/PacketCapture.h"  // For Packet

TEST(SignatureDetectorTest, LoadSignatures) {
    SignatureDetector detector;
    // Load the test signatures file from the tests folder.
    bool loadResult = detector.loadSignatures("../test_signatures.txt");
    EXPECT_TRUE(loadResult);
}

TEST(SignatureDetectorTest, DetectSignature) {
    SignatureDetector detector;
    bool loadResult = detector.loadSignatures("../test_signatures.txt");
    EXPECT_TRUE(loadResult);

    Packet pkt;
    pkt.payload = "This packet contains a malicious payload";
    FlaggedPacket flaggedPkt;
    bool detected = detector.detect(pkt, flaggedPkt);
    EXPECT_TRUE(detected);
    EXPECT_EQ(flaggedPkt.matchedSignature, "malicious");
}