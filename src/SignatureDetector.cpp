// src/SignatureDetector.cpp
#include "SignatureDetector.h"
#include <fstream>
#include <algorithm>

SignatureDetector::SignatureDetector() {}

bool SignatureDetector::loadSignatures(const std::string &filePath) {
    std::ifstream infile(filePath);
    if (!infile.is_open()) {
        return false;
    }
    std::string line;
    while (std::getline(infile, line)) {
        if (!line.empty()) {
            signatures_.push_back(line);
        }
    }
    infile.close();
    return true;
}

bool SignatureDetector::detect(const Packet &packet, FlaggedPacket &flaggedPkt) {
    for (const auto &sig : signatures_) {
        if (packet.payload.find(sig) != std::string::npos) {
            flaggedPkt.packet = packet;
            flaggedPkt.matchedSignature = sig;
            flaggedPackets_.push_back(flaggedPkt);
            return true;
        }
    }
    return false;
}

const std::vector<FlaggedPacket>& SignatureDetector::getFlaggedPackets() const {
    return flaggedPackets_;
}

void SignatureDetector::clearFlaggedPackets() {
    flaggedPackets_.clear();
}