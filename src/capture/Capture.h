// libpcap, wrapped: live capture from an interface or reading a saved file,
// optionally paced to replay at the speed it was recorded.
#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "core/Packet.h"

struct pcap;
struct pcap_dumper;

namespace pm {

struct InterfaceInfo {
    std::string name, description;
    std::vector<IpAddr> addresses;
    bool up = false, running = false, loopback = false, wireless = false;
};

struct CaptureStats {
    uint64_t received = 0;  // packets the kernel handed over
    uint64_t dropped = 0;   // packets the kernel dropped because we were too slow
};

class Capture {
public:
    ~Capture();

    static std::vector<InterfaceInfo> interfaces(std::string& error);
    /** An up, non-loopback interface with an address, preferring wired and Wi-Fi ones. */
    static std::string defaultInterface(std::string& error);
    /** Every address of every interface: what counts as "this machine". */
    static std::vector<IpAddr> localAddresses();

    bool openLive(const std::string& interface, int snapLen, int bufferMb, bool promiscuous, std::string& error);
    bool openFile(const std::string& path, std::string& error);
    bool setFilter(const std::string& bpf, std::string& error);
    /** Also writes every captured packet to a pcap file. */
    bool writeTo(const std::string& path, std::string& error);

    int linkType() const;
    bool live() const { return live_; }
    const std::string& source() const { return source_; }

    /** For files: play back in real time times speed; 0 means as fast as possible. */
    void setReplaySpeed(double speed) { speed_ = speed; }

    using Sink = std::function<void(int64_t tsUsec, const uint8_t* data, uint32_t capLen, uint32_t wireLen)>;
    /** Delivers packets until stop() or the end of the file. Returns false on a read error. */
    bool run(const Sink& sink, std::string& error);
    void stop();

    /**
     * Capture time "now": the wall clock when live; for a paced replay, the
     * point in the recording being played; 0 when unknown.
     */
    int64_t clockUsec() const;

    /** Packet counters for live capture, as of the last quarter second or so. */
    CaptureStats stats() const;

private:
    pcap* handle_ = nullptr;
    pcap_dumper* dumper_ = nullptr;
    bool live_ = false;
    std::string source_;
    double speed_ = 1.0;
    std::atomic<bool> stop_{false};
    // Replay pacing: capture time firstTs_ was played at wall time wallStart_.
    std::atomic<int64_t> firstTs_{0}, wallStart_{0};
    // pcap handles aren't thread-safe, so the capture thread reads the
    // kernel's counters between batches and other threads read these.
    std::atomic<uint64_t> received_{0}, dropped_{0};
    void readStats();
};

int64_t wallClockUsec();

}  // namespace pm
