// Turns captured bytes into a PacketView. Every read is checked against the
// number of bytes actually captured, so truncated or malformed packets are
// rejected rather than read past.
#pragma once

#include "core/Packet.h"

namespace pm {

/** Link-layer types, numbered as libpcap's DLT_ values. */
enum LinkType : int {
    kLinkNull = 0,        // BSD loopback, host byte order family (macOS lo0, utun)
    kLinkEthernet = 1,
    kLinkRaw = 12,        // raw IP (DLT_RAW on Linux and macOS)
    kLinkRawOpenBsd = 14,
    kLinkRawFile = 101,   // LINKTYPE_RAW as written in files
    kLinkLoop = 108,      // OpenBSD loopback, network byte order family
    kLinkLinuxSll = 113,  // Linux "any" device
    kLinkIpv4 = 228,
    kLinkIpv6 = 229,
    kLinkLinuxSll2 = 276,
};

bool linkTypeSupported(int linkType);
const char* linkTypeName(int linkType);

enum class DecodeResult {
    Ok,         // an IP packet, decoded
    NotIp,      // well formed but not IPv4/IPv6 (ARP, LLDP, ...)
    Malformed,  // too short or inconsistent
};

DecodeResult decode(int linkType, const uint8_t* data, uint32_t capLen, uint32_t wireLen, int64_t tsUsec,
                    PacketView& out);

}  // namespace pm
