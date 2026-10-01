#pragma once

#include <cstdint>
#include <string>

#include "analysis/Signatures.h"

namespace pm {

enum class AlertKind : uint8_t { Signature, PortScan, SynFlood, TrafficSpike };

struct Alert {
    int64_t tsUsec = 0;
    AlertKind kind = AlertKind::Signature;
    Severity severity = Severity::Medium;
    std::string title;    // short, e.g. "Port scan"
    std::string message;  // one line of detail
    std::string src, dst; // addresses involved, if any
};

/** snake_case name used in logs, e.g. "port_scan". */
const char* alertKindId(AlertKind k);

/** One JSON object, no trailing newline. */
std::string alertToJson(const Alert& a);

}  // namespace pm
