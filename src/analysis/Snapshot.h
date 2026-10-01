// What the engine publishes once a second for the dashboard: an immutable
// copy, so the display thread never touches live engine state.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "analysis/Alert.h"

namespace pm {

struct SecondSample {
    int64_t sec = 0;  // capture time, whole seconds
    uint64_t bytesIn = 0, bytesOut = 0, packets = 0;
};

struct FlowRow {
    std::string app;     // empty if unknown
    std::string host;    // hostname, or the remote address
    std::string remote;  // address:port
    const char* service = "";
    double rateIn = 0, rateOut = 0;  // bytes per second
    uint64_t totalIn = 0, totalOut = 0;
    int64_t firstUsec = 0, lastUsec = 0;
    bool active = false;  // traffic in the last few seconds
};

struct GroupRow {
    std::string name;
    std::string detail;  // the busiest host (for apps) or app (for hosts)
    const char* service = "";
    uint32_t flows = 0;
    double rateIn = 0, rateOut = 0;
    uint64_t totalIn = 0, totalOut = 0;
};

struct ServiceShare {
    const char* name;
    uint64_t bytes;
};

struct Lookup {
    int64_t tsUsec = 0;
    std::string name;
    uint16_t type = 0;
    bool failed = false;  // no such name
};

struct Snapshot {
    int64_t nowUsec = 0;
    int64_t startUsec = 0;
    std::string source;       // interface or file
    std::string linkName;
    bool live = false;
    bool finished = false;    // a replay that has reached its end
    std::string appsProblem;  // why app names are missing, if they are

    double rateIn = 0, rateOut = 0, packetsPerSec = 0;
    uint64_t totalBytes = 0, totalPackets = 0;
    uint64_t kernelDrops = 0, ringDrops = 0, notIp = 0, malformed = 0;
    size_t activeFlows = 0, trackedFlows = 0;

    std::vector<SecondSample> history;  // oldest first
    std::vector<FlowRow> flows;         // busiest first
    std::vector<GroupRow> apps, hosts;
    std::vector<ServiceShare> services; // bytes over the last minute, largest first
    std::vector<Lookup> lookups;        // newest first
    std::vector<Alert> alerts;          // newest first
    uint64_t alertCount = 0;
};

}  // namespace pm
