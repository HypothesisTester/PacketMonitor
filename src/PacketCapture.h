// src/PacketCapture.h
#ifndef PACKETCAPTURE_H
#define PACKETCAPTURE_H

#include <pcap.h>
#include <string>
#include <functional>

// Forward declaration for Packet structure (defined here for simplicity)
struct Packet {
    std::string srcIP;
    std::string destIP;
    int srcPort;
    int destPort;
    std::string payload;
};

// Callback type: function that takes a const Packet&.§
using PacketCallback = std::function<void(const Packet&)>;

class PacketCapture {
public:
    PacketCapture(const std::string &interface, const std::string &filter);
    ~PacketCapture();
    
    bool initialize();
    void startCapture();
    void stopCapture();
    
    // Register callback functions to process packets (for signature & anomaly detection)
    void setSignatureCallback(PacketCallback cb);
    void setAnomalyCallback(PacketCallback cb);

private:
    std::string interface_;
    std::string filter_;
    pcap_t *handle_;
    bool isRunning_;

    // Callback functions to be invoked for each packet
    PacketCallback signatureCallback_;
    PacketCallback anomalyCallback_;

    // Static callback function used by libpcap
    static void packetHandler(u_char *userData, const struct pcap_pkthdr* header, const u_char* packet);
    
    // Helper function to process raw packet data
    void processPacket(const struct pcap_pkthdr* header, const u_char* packet);
};

#endif // PACKETCAPTURE_H