#include "analysis/Services.h"

#include "core/Packet.h"

namespace pm {

const char* serviceName(Service s) {
    switch (s) {
    case Service::Tls: return "TLS";
    case Service::Quic: return "QUIC";
    case Service::Http: return "HTTP";
    case Service::Dns: return "DNS";
    case Service::Ssh: return "SSH";
    case Service::Push: return "Push";
    case Service::Mail: return "Mail";
    case Service::Ntp: return "NTP";
    case Service::Mdns: return "mDNS";
    case Service::Dhcp: return "DHCP";
    case Service::Ssdp: return "SSDP";
    case Service::Stun: return "STUN";
    case Service::Vpn: return "VPN";
    case Service::Smb: return "SMB";
    case Service::Tcp: return "TCP";
    case Service::Udp: return "UDP";
    case Service::Icmp: return "ICMP";
    case Service::Other: return "Other";
    case Service::Count: break;
    }
    return "?";
}

Service classifyPort(uint8_t proto, uint16_t port) {
    if (proto == kProtoIcmp || proto == kProtoIcmp6) return Service::Icmp;
    if (proto == kProtoTcp) {
        switch (port) {
        case 443: case 8443: return Service::Tls;
        case 80: case 8080: case 8000: return Service::Http;
        case 53: return Service::Dns;
        case 853: return Service::Tls;  // DNS over TLS
        case 22: return Service::Ssh;
        case 5223: case 5228: return Service::Push;
        case 25: case 465: case 587: case 143: case 993: case 110: case 995: return Service::Mail;
        case 445: case 139: return Service::Smb;
        case 1194: return Service::Vpn;
        default: return Service::Tcp;
        }
    }
    if (proto == kProtoUdp) {
        switch (port) {
        case 443: return Service::Quic;
        case 53: return Service::Dns;
        case 5353: return Service::Mdns;
        case 123: return Service::Ntp;
        case 67: case 68: case 546: case 547: return Service::Dhcp;
        case 1900: return Service::Ssdp;
        case 3478: case 3479: case 19302: case 19305: return Service::Stun;
        case 51820: case 500: case 4500: case 1194: return Service::Vpn;
        default: return Service::Udp;
        }
    }
    return Service::Other;
}

bool isServicePort(uint8_t proto, uint16_t port) {
    if (port == 0) return false;
    if (port < 1024) return true;
    Service s = classifyPort(proto, port);
    return s != Service::Tcp && s != Service::Udp;
}

}  // namespace pm
