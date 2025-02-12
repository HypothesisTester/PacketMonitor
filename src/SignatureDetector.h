// src/SignatureDetector.h
#ifndef SIGNATUREDETECTOR_H
#define SIGNATUREDETECTOR_H

#include <vector>
#include <string>
#include "PacketCapture.h"

// Struct to hold a flagged packet along with the matched signature.
struct FlaggedPacket {
    Packet packet;
    std::string matchedSignature;
};

class SignatureDetector {
public:
    SignatureDetector();
    bool loadSignatures(const std::string &filePath);
    // Returns true if a signature is detected
    bool detect(const Packet &packet, FlaggedPacket &flaggedPkt);
    const std::vector<FlaggedPacket>& getFlaggedPackets() const;
    void clearFlaggedPackets();

private:
    std::vector<std::string> signatures_;
    std::vector<FlaggedPacket> flaggedPackets_;
};

#endif // SIGNATUREDETECTOR_H