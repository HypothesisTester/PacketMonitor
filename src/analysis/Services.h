// Labels for what a flow is: TLS, QUIC, DNS and so on, from its server port
// and, where possible, from what its payload looks like.
#pragma once

#include <cstdint>

namespace pm {

enum class Service : uint8_t {
    Tls,
    Quic,
    Http,
    Dns,
    Ssh,
    Push,   // Apple and Google push notifications
    Mail,
    Ntp,
    Mdns,
    Dhcp,
    Ssdp,
    Stun,   // WebRTC calls
    Vpn,
    Smb,
    Tcp,    // other TCP
    Udp,    // other UDP
    Icmp,
    Other,
    Count,
};

constexpr int kServiceCount = static_cast<int>(Service::Count);

const char* serviceName(Service s);

/** A guess from the transport protocol and the server's port. */
Service classifyPort(uint8_t proto, uint16_t serverPort);

/** True for ports that identify a service, so the other end is the client. */
bool isServicePort(uint8_t proto, uint16_t port);

}  // namespace pm
