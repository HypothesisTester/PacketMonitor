// src/main.cpp
#include "PacketCapture.h"
#include "SignatureDetector.h"
#include "AnomalyDetector.h"
#include "Utils.h"
#include "UI.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <vector>
#include <atomic>
#include <getopt.h>
#include <signal.h>

// Global flag for graceful shutdown.
std::atomic<bool> keepRunning(true);

void handleSigint(int signum) {
    keepRunning = false;
}

void printUsage(const char* programName) {
    std::cout << "Usage: " << programName << " [OPTIONS]\n"
              << "  -i, --interface   Network interface (default: eth0)\n"
              << "  -f, --filter      BPF filter expression (default: \"tcp or udp\")\n"
              << "  -s, --signatures  Path to signatures file (default: data/signatures.txt)\n"
              << "  -t, --threshold   Anomaly threshold (default: 1000)\n"
              << "  -w, --window      Time window in seconds (default: 60)\n"
              << "  -h, --help        Display this help message\n";
}

int main(int argc, char* argv[]) {
    // Default parameters.
    std::string interface = "eth0";
    std::string filter = "tcp or udp";
    std::string signaturesFile = "data/signatures.txt";
    int anomalyThreshold = 1000;
    int anomalyTimeWindow = 60;

    // Parse command-line arguments.
    static struct option long_options[] = {
        {"interface",  required_argument, 0, 'i'},
        {"filter",     required_argument, 0, 'f'},
        {"signatures", required_argument, 0, 's'},
        {"threshold",  required_argument, 0, 't'},
        {"window",     required_argument, 0, 'w'},
        {"help",       no_argument,       0, 'h'},
        {0,            0,                 0,  0 }
    };

    int opt, option_index = 0;
    while ((opt = getopt_long(argc, argv, "i:f:s:t:w:h", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'i': interface = optarg; break;
            case 'f': filter = optarg; break;
            case 's': signaturesFile = optarg; break;
            case 't': anomalyThreshold = std::stoi(optarg); break;
            case 'w': anomalyTimeWindow = std::stoi(optarg); break;
            case 'h':
            default:
                printUsage(argv[0]);
                return 0;
        }
    }

    // Initialise modules.
    PacketCapture packetCapture(interface, filter);
    if (!packetCapture.initialize()) {
        std::cerr << "Failed to initialize packet capture." << std::endl;
        return -1;
    }

    SignatureDetector sigDetector;
    if (!sigDetector.loadSignatures(signaturesFile)) {
        std::cerr << "Failed to load signatures from " << signaturesFile << std::endl;
        return -1;
    }

    AnomalyDetector anomalyDetector(anomalyThreshold, anomalyTimeWindow);
    UI ui;
    ui.start();

    // Register callbacks.
    packetCapture.setSignatureCallback([&sigDetector, &ui](const Packet &pkt) {
        FlaggedPacket flaggedPkt;
        if (sigDetector.detect(pkt, flaggedPkt)) {
            std::string logMsg = "Signature detected: " + flaggedPkt.matchedSignature +
                                 " from " + flaggedPkt.packet.srcIP + ":" + std::to_string(flaggedPkt.packet.srcPort);
            Utils::logEvent(logMsg, LogLevel::INFO);
            ui.addFlaggedPacket(flaggedPkt);
        }
    });
    packetCapture.setAnomalyCallback([&anomalyDetector, &ui](const Packet &pkt) {
        anomalyDetector.trackPacket(pkt);
    });

    // Set up SIGINT handler.
    signal(SIGINT, handleSigint);

    // Start packet capture in a separate thread.
    std::thread captureThread([&packetCapture]() {
        packetCapture.startCapture();
    });

    // Main thread: periodically check for anomalies.
    while (keepRunning) {
        std::this_thread::sleep_for(std::chrono::seconds(anomalyTimeWindow));
        auto anomalies = anomalyDetector.detectAnomalies();
        for (const auto &anomaly : anomalies) {
            std::string anomalyMsg = "Anomaly detected: IP " + anomaly.ip +
                                     " sent " + std::to_string(anomaly.packetCount) + " packets.";
            Utils::logEvent(anomalyMsg, LogLevel::WARNING);
            ui.addAnomaly(anomaly);
        }
    }

    // Clean up.
    packetCapture.stopCapture();
    captureThread.join();
    ui.stop();

    std::cout << "Packet monitoring stopped." << std::endl;
    return 0;
}