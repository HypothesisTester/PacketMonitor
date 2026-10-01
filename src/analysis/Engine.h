// The analysis engine: runs on one thread, takes packets in capture order and
// keeps everything the dashboard and the alerts need.
//
// Time comes from packet timestamps, not the wall clock, so replaying a
// capture reproduces exactly what was seen live. The engine ticks once per
// second of capture time: it closes that second's totals, updates rates, runs
// the detectors and publishes a Snapshot.
#pragma once

#include <array>
#include <atomic>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <ostream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "analysis/Detectors.h"
#include "analysis/Services.h"
#include "analysis/Signatures.h"
#include "analysis/Snapshot.h"
#include "core/Decoder.h"
#include "core/Packet.h"
#include "core/PacketRing.h"
#include "procs/Owners.h"

namespace pm {

struct EngineConfig {
    int linkType = kLinkEthernet;
    /** This machine's addresses. If empty, private addresses count as local. */
    std::vector<IpAddr> localAddresses;
    DetectorConfig detectors;
    size_t maxFlows = 250000;
    /** Build a Snapshot every second (off for benchmarks and headless runs). */
    bool publish = true;
    std::string source, linkName;
    bool live = false;
};

class Engine {
public:
    Engine(EngineConfig config, const SignatureSet* signatures, OwnerLookup* owners);
    ~Engine();

    /** Handles one captured packet. Packets must arrive in capture order. */
    void process(const PacketRecordHeader& header, const uint8_t* data);
    /** Runs any ticks due by this time, e.g. when no packets are arriving. */
    void advanceTo(int64_t nowUsec);
    /** Closes the current second and marks the run as finished. */
    void finish();

    /** The latest published snapshot; safe to call from any thread. */
    std::shared_ptr<const Snapshot> snapshot() const;

    void onAlert(std::function<void(const Alert&)> cb) { alertCallback_ = std::move(cb); }
    void setOwnerLog(std::ostream* log) { ownerLog_ = log; }
    void setAppsProblem(std::string problem) { appsProblem_ = std::move(problem); }
    void setCaptureDrops(uint64_t kernel, uint64_t ring) {
        kernelDrops_.store(kernel, std::memory_order_relaxed);
        ringDrops_.store(ring, std::memory_order_relaxed);
    }

    uint64_t packets() const { return packets_; }
    uint64_t bytes() const { return bytes_; }
    uint64_t alertCount() const { return alertCount_; }
    size_t flowCount() const { return flows_.size(); }
    /** Every alert raised so far (kept for tests and summaries, capped). */
    const std::deque<Alert>& alerts() const { return alerts_; }
    /** The hostname learned for an address, or empty. */
    std::string hostFor(const IpAddr& addr) const;

private:
    struct Flow;
    Flow* flowFor(const PacketView& p, const FlowKey& key, bool srcIsA);
    void initFlow(Flow& f, const PacketView& p, bool srcIsA);
    void handleTcp(Flow& f, const PacketView& p, int dir);
    void handlePayload(Flow& f, const PacketView& p, int dir);
    void inspectClientStart(Flow& f, const uint8_t* data, size_t len, bool gap);
    void handleDns(const PacketView& p);
    void setHost(Flow& f, std::string host, uint8_t source);
    void tryOwner(Flow& f);
    void raise(Alert a);
    void signatureAlert(Flow& f, const PacketView& p, uint32_t sig);
    void tick(int64_t tickUsec);
    void publish(int64_t nowUsec);
    bool isLocal(const IpAddr& a) const;
    void account(uint64_t bytes, bool out);

    EngineConfig cfg_;
    const SignatureSet* sigs_;
    OwnerLookup* owners_;
    std::ostream* ownerLog_ = nullptr;
    std::string appsProblem_;
    std::function<void(const Alert&)> alertCallback_;

    std::unordered_set<IpAddr, IpAddrHash> local_;
    std::unordered_map<FlowKey, std::unique_ptr<Flow>, FlowKeyHash> flows_;
    std::unordered_map<IpAddr, std::string, IpAddrHash> dnsNames_;

    PortScanDetector portScan_;
    SynFloodDetector synFlood_;
    SpikeDetector spikeIn_, spikeOut_;
    AlertList pending_;
    std::unordered_map<std::string, int64_t> sigCooldown_;

    // The second in progress.
    uint64_t secIn_ = 0, secOut_ = 0, secPackets_ = 0;
    uint64_t secService_[kServiceCount] = {};

    std::deque<SecondSample> history_;
    std::deque<std::array<uint64_t, kServiceCount>> serviceWindow_;
    std::deque<Lookup> lookups_;
    std::deque<Alert> alerts_;

    struct Group {
        uint64_t totalIn = 0, totalOut = 0;
        int64_t lastActive = 0;
        // Recomputed every tick:
        uint32_t flows = 0;
        double rateIn = 0, rateOut = 0;
        std::string detail;
        double detailRate = -1;
        Service service = Service::Other;
    };
    std::unordered_map<std::string, Group> apps_, hosts_;

    int64_t startUsec_ = 0, nowUsec_ = 0, nextTick_ = 0;
    uint64_t packets_ = 0, bytes_ = 0, notIp_ = 0, malformed_ = 0, alertCount_ = 0;
    std::atomic<uint64_t> kernelDrops_{0}, ringDrops_{0};
    bool finished_ = false;

    mutable std::mutex snapMu_;
    std::shared_ptr<const Snapshot> snapshot_;
};

}  // namespace pm
