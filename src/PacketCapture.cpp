// src/PacketCapture.cpp
#include "PacketCapture.h"
#include "Utils.h"    // For potential helper functions (if needed)
#include <iostream>
#include <cstring>
#include <arpa/inet.h>

// Define Ethernet header size
#define SIZE_ETHERNET 14

// Structure for IP header 
struct sniff_ip {
    u_char  ip_vhl;                 // version << 4 | header length >> 2
    u_char  ip_tos;                 // type of service
    u_short ip_len;                 // total length
    u_short ip_id;                  // identification
    u_short ip_off;                 // fragment offset field
    u_char  ip_ttl;                 // time to live
    u_char  ip_p;                   // protocol
    u_short ip_sum;                 // checksum
    struct  in_addr ip_src, ip_dst; // source and dest address
};

// Structure for TCP header
struct sniff_tcp {
    u_short th_sport; // source port
    u_short th_dport; // destination port
};

PacketCapture::PacketCapture(const std::string &interface, const std::string &filter)
    : interface_(interface), filter_(filter), handle_(nullptr), isRunning_(false) {}

PacketCapture::~PacketCapture() {
    if (handle_) {
        if (isRunning_) {
            pcap_breakloop(handle_);
        }
        pcap_close(handle_);
    }
}

bool PacketCapture::initialize() {
    char errbuf[PCAP_ERRBUF_SIZE];
    handle_ = pcap_open_live(interface_.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle_ == nullptr) {
        std::cerr << "Couldn't open device " << interface_ << ": " << errbuf << std::endl;
        return false;
    }

    // Compile and set the filter
    struct bpf_program fp;
    if (pcap_compile(handle_, &fp, filter_.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Couldn't parse filter " << filter_ << ": " << pcap_geterr(handle_) << std::endl;
        return false;
    }
    if (pcap_setfilter(handle_, &fp) == -1) {
        std::cerr << "Couldn't install filter " << filter_ << ": " << pcap_geterr(handle_) << std::endl;
        return false;
    }
    pcap_freecode(&fp);
    return true;
}

void PacketCapture::startCapture() {
    if (!handle_) {
        std::cerr << "Packet capture not initialized." << std::endl;
        return;
    }
    isRunning_ = true;
    pcap_loop(handle_, 0, PacketCapture::packetHandler, reinterpret_cast<u_char*>(this));
}

void PacketCapture::stopCapture() {
    if (handle_ && isRunning_) {
        pcap_breakloop(handle_);
        isRunning_ = false;
    }
}

void PacketCapture::setSignatureCallback(PacketCallback cb) {
    signatureCallback_ = cb;
}

void PacketCapture::setAnomalyCallback(PacketCallback cb) {
    anomalyCallback_ = cb;
}

void PacketCapture::packetHandler(u_char *userData, const struct pcap_pkthdr* header, const u_char* packet) {
    PacketCapture* self = reinterpret_cast<PacketCapture*>(userData);
    self->processPacket(header, packet);
}

void PacketCapture::processPacket(const struct pcap_pkthdr* header, const u_char* packet) {
    // Ensure the packet is large enough for the Ethernet header
    if (header->len < SIZE_ETHERNET) {
        return;
    }

    // Point to the IP header (skip Ethernet header)
    const struct sniff_ip* ip = reinterpret_cast<const struct sniff_ip*>(packet + SIZE_ETHERNET);
    int ip_header_length = (ip->ip_vhl & 0x0f) * 4;
    if (ip_header_length < 20) {
        std::cerr << "Invalid IP header length: " << ip_header_length << std::endl;
        return;
    }

    // Process only TCP packets for this example
    if (ip->ip_p != IPPROTO_TCP) {
        return;
    }

    // Point to the TCP header
    const struct sniff_tcp* tcp = reinterpret_cast<const struct sniff_tcp*>(packet + SIZE_ETHERNET + ip_header_length);
    int tcp_header_length = 20; // Assuming no TCP options

    // Calculate payload offset and size
    int payload_offset = SIZE_ETHERNET + ip_header_length + tcp_header_length;
    if (payload_offset > header->len) return;
    int payload_size = header->len - payload_offset;
    std::string payload;
    if (payload_size > 0) {
        payload = std::string(reinterpret_cast<const char*>(packet + payload_offset), payload_size);
    }

    // Convert source and destination IP addresses to strings
    char src_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->ip_dst), dest_ip, INET_ADDRSTRLEN);

    // Extract TCP ports
    int src_port = ntohs(tcp->th_sport);
    int dest_port = ntohs(tcp->th_dport);

    // Populate the Packet struct
    Packet pkt;
    pkt.srcIP = std::string(src_ip);
    pkt.destIP = std::string(dest_ip);
    pkt.srcPort = src_port;
    pkt.destPort = dest_port;
    pkt.payload = payload;

    // Call the registered callbacks (if set)
    if (signatureCallback_) {
        signatureCallback_(pkt);
    }
    if (anomalyCallback_) {
        anomalyCallback_(pkt);
    }
}