// Writes a synthetic three-minute capture of a laptop's traffic, used by the
// tests, the README demo and the benchmark. Everything in it is made up but
// built like the real thing: TCP handshakes and teardowns, DNS answers with
// name compression, TLS ClientHellos (one split across two segments), QUIC
// over IPv6, and a few incidents for the detectors to find:
//
//   0:45  a password sent to a NAS over plain HTTP
//   1:10  a port scan from another machine on the network
//   1:35  the EICAR test file downloaded over HTTP, split across two segments
//   2:00  a 30 MB/s software update (a traffic spike)
//   2:40  a SYN flood against a local development server
//
// Bulk data packets are cut to their headers, as tcpdump -s 96 would, so the
// file stays small. It also writes sample.pcap.apps naming the app behind
// each connection, as packetmonitor -w does during live capture.
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <random>
#include <string>
#include <vector>

#include "core/Packet.h"
#include "procs/Owners.h"

using namespace pm;

namespace {

using Bytes = std::vector<uint8_t>;

std::mt19937 rng(20260930);

double uniform(double a, double b) { return std::uniform_real_distribution<double>(a, b)(rng); }
uint32_t rand32() { return rng(); }
Bytes randomBytes(size_t n) {
    Bytes b(n);
    for (auto& x : b) x = uint8_t(rng());
    return b;
}
Bytes text(const std::string& s) { return Bytes(s.begin(), s.end()); }

void put16(Bytes& b, uint16_t v) {
    b.push_back(uint8_t(v >> 8));
    b.push_back(uint8_t(v));
}
void put32(Bytes& b, uint32_t v) {
    put16(b, uint16_t(v >> 16));
    put16(b, uint16_t(v));
}
void append(Bytes& b, const Bytes& more) { b.insert(b.end(), more.begin(), more.end()); }

IpAddr ip(const char* s) { return *IpAddr::parse(s); }

// ---- pcap file ------------------------------------------------------------

const int64_t kStart = 1790168400LL * 1000000;  // 2026-09-23 13:00 UTC

struct Record {
    int64_t ts;
    uint32_t wireLen;
    Bytes data;  // what was captured
};
std::vector<Record> records;

void emit(double t, Bytes frame, uint32_t wireLen) {
    records.push_back(Record{kStart + int64_t(t * 1e6), wireLen, std::move(frame)});
}

bool writePcap(const std::string& path) {
    std::stable_sort(records.begin(), records.end(), [](const Record& a, const Record& b) { return a.ts < b.ts; });
    std::FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) return false;
    struct {
        uint32_t magic = 0xa1b2c3d4;
        uint16_t major = 2, minor = 4;
        int32_t zone = 0;
        uint32_t sigfigs = 0, snaplen = 65535, linktype = 1;
    } header;
    std::fwrite(&header, sizeof header, 1, f);
    for (const auto& r : records) {
        uint32_t h[4] = {uint32_t(r.ts / 1000000), uint32_t(r.ts % 1000000), uint32_t(r.data.size()), r.wireLen};
        std::fwrite(h, sizeof h, 1, f);
        std::fwrite(r.data.data(), 1, r.data.size(), f);
    }
    return std::fclose(f) == 0;
}

// ---- Frames ---------------------------------------------------------------

const uint8_t kLaptopMac[6] = {0x3c, 0x22, 0xfb, 0x1a, 0x2b, 0x23};
const uint8_t kRouterMac[6] = {0x44, 0xd4, 0x54, 0x0a, 0x00, 0x01};
const uint8_t kPeerMac[6] = {0x98, 0x5a, 0xeb, 0x7c, 0x1d, 0x44};

const IpAddr kLaptop = ip("192.168.1.23");
const IpAddr kLaptop6 = ip("2a02:8084:4b82:5e00:1c2b:3dff:fe4a:9b10");
const IpAddr kRouter = ip("192.168.1.1");
const IpAddr kScanner = ip("192.168.1.44");

uint32_t sumWords(const uint8_t* p, size_t n, uint32_t sum = 0) {
    for (size_t i = 0; i + 1 < n; i += 2) sum += uint32_t(p[i] << 8 | p[i + 1]);
    if (n & 1) sum += uint32_t(p[n - 1] << 8);
    return sum;
}
uint16_t fold(uint32_t sum) {
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return uint16_t(~sum);
}

/**
 * An Ethernet frame carrying l4 (a TCP or UDP header plus payload). keep is
 * how many bytes of the payload to capture; the rest counts only on the wire.
 */
void frame(double t, const IpAddr& src, const IpAddr& dst, uint8_t proto, Bytes l4, size_t headerLen, size_t keep) {
    const bool v6 = src.family == 6;
    const bool outbound = src == kLaptop || src == kLaptop6;
    const bool lanPeer = src == kScanner || dst == kScanner || src.bytes[3] == 30;
    Bytes f;
    const uint8_t* dmac = outbound ? (lanPeer ? kPeerMac : kRouterMac) : kLaptopMac;
    const uint8_t* smac = outbound ? kLaptopMac : (lanPeer ? kPeerMac : kRouterMac);
    f.insert(f.end(), dmac, dmac + 6);
    f.insert(f.end(), smac, smac + 6);
    put16(f, v6 ? 0x86dd : 0x0800);

    // Transport checksum over the pseudo-header and the full segment.
    uint32_t sum = 0;
    const size_t addrLen = v6 ? 16 : 4;
    sum = sumWords(src.bytes.data(), addrLen, sum);
    sum = sumWords(dst.bytes.data(), addrLen, sum);
    sum += proto + uint32_t(l4.size());
    const size_t csumAt = proto == kProtoTcp ? 16 : 6;
    l4[csumAt] = l4[csumAt + 1] = 0;
    uint16_t c = fold(sumWords(l4.data(), l4.size(), sum));
    if (proto == kProtoUdp && c == 0) c = 0xffff;
    l4[csumAt] = uint8_t(c >> 8);
    l4[csumAt + 1] = uint8_t(c);

    if (v6) {
        put32(f, 0x60000000u | (rand32() & 0xfffff));
        put16(f, uint16_t(l4.size()));
        f.push_back(proto);
        f.push_back(64);
        f.insert(f.end(), src.bytes.begin(), src.bytes.end());
        f.insert(f.end(), dst.bytes.begin(), dst.bytes.end());
    } else {
        size_t start = f.size();
        f.push_back(0x45);
        f.push_back(0);
        put16(f, uint16_t(20 + l4.size()));
        put16(f, uint16_t(rand32()));
        put16(f, 0x4000);  // don't fragment
        f.push_back(outbound ? 64 : 56);
        f.push_back(proto);
        put16(f, 0);
        f.insert(f.end(), src.bytes.begin(), src.bytes.begin() + 4);
        f.insert(f.end(), dst.bytes.begin(), dst.bytes.begin() + 4);
        uint16_t ipsum = fold(sumWords(f.data() + start, 20));
        f[start + 10] = uint8_t(ipsum >> 8);
        f[start + 11] = uint8_t(ipsum);
    }
    const uint32_t wire = uint32_t(f.size() + l4.size());
    f.insert(f.end(), l4.begin(), l4.begin() + long(std::min(l4.size(), headerLen + keep)));
    emit(t, std::move(f), wire);
}

// ---- Apps -----------------------------------------------------------------

std::vector<std::string> appLines;

void owns(const std::string& app, uint8_t proto, const IpAddr& lip, uint16_t lport, const IpAddr& rip,
          uint16_t rport) {
    appLines.push_back(RecordedOwners::line(proto, lip, lport, rip, rport, app));
}

uint16_t ephemeralPort() { return uint16_t(49152 + rand32() % 16000); }

// ---- UDP and DNS ----------------------------------------------------------

void udp(double t, const IpAddr& src, uint16_t sport, const IpAddr& dst, uint16_t dport, const Bytes& payload,
         size_t keep = SIZE_MAX) {
    Bytes l4;
    put16(l4, sport);
    put16(l4, dport);
    put16(l4, uint16_t(8 + payload.size()));
    put16(l4, 0);
    append(l4, payload);
    frame(t, src, dst, kProtoUdp, std::move(l4), 8, std::min(keep, payload.size()));
}

void dnsName(Bytes& b, const std::string& name) {
    size_t start = 0;
    while (start < name.size()) {
        size_t dot = name.find('.', start);
        if (dot == std::string::npos) dot = name.size();
        b.push_back(uint8_t(dot - start));
        b.insert(b.end(), name.begin() + long(start), name.begin() + long(dot));
        start = dot + 1;
    }
    b.push_back(0);
}

/**
 * A lookup by mDNSResponder: the query, then the answer 15–40 ms later. With a
 * cname, the answer goes through it, as CDN-hosted names do.
 */
void lookup(double t, const std::string& name, const std::vector<IpAddr>& addrs, const std::string& cname = "") {
    const uint16_t id = uint16_t(rand32());
    const uint16_t port = ephemeralPort();
    const uint16_t qtype = addrs.empty() || addrs[0].family == 4 ? 1 : 28;
    Bytes q;
    put16(q, id);
    put16(q, 0x0100);
    put16(q, 1);
    put16(q, 0);
    put16(q, 0);
    put16(q, 0);
    dnsName(q, name);
    put16(q, qtype);
    put16(q, 1);
    udp(t, kLaptop, port, kRouter, 53, q);
    owns("mDNSResponder", kProtoUdp, kLaptop, port, kRouter, 53);

    Bytes r;
    put16(r, id);
    put16(r, addrs.empty() ? 0x8183 : 0x8180);  // NXDOMAIN when there are no answers
    put16(r, 1);
    put16(r, uint16_t(addrs.size() + (cname.empty() || addrs.empty() ? 0 : 1)));
    put16(r, 0);
    put16(r, 0);
    dnsName(r, name);
    put16(r, qtype);
    put16(r, 1);
    uint16_t ownerPtr = 0xc00c;  // the question's name
    if (!cname.empty() && !addrs.empty()) {
        put16(r, 0xc00c);
        put16(r, 5);
        put16(r, 1);
        put32(r, 300);
        Bytes target;
        dnsName(target, cname);
        put16(r, uint16_t(target.size()));
        ownerPtr = uint16_t(0xc000 | r.size());
        append(r, target);
    }
    for (const auto& a : addrs) {
        put16(r, ownerPtr);
        put16(r, a.family == 4 ? 1 : 28);
        put16(r, 1);
        put32(r, 60);
        put16(r, a.family == 4 ? 4 : 16);
        r.insert(r.end(), a.bytes.begin(), a.bytes.begin() + (a.family == 4 ? 4 : 16));
    }
    udp(t + uniform(0.015, 0.04), kRouter, 53, kLaptop, port, r);
}

// ---- TCP ------------------------------------------------------------------

struct Tcp {
    IpAddr client, server;
    uint16_t cport, sport;
    uint32_t cseq, sseq;
    double rtt = 0.02;

    Tcp(const std::string& app, const IpAddr& c, const IpAddr& s, uint16_t port, double rttSec = 0.02)
        : client(c), server(s), cport(ephemeralPort()), sport(port), cseq(rand32()), sseq(rand32()), rtt(rttSec) {
        if (!app.empty()) owns(app, kProtoTcp, c, cport, s, port);
    }

    void segment(double t, bool fromClient, uint8_t flags, const Bytes& payload, size_t keep = SIZE_MAX) {
        Bytes l4;
        put16(l4, fromClient ? cport : sport);
        put16(l4, fromClient ? sport : cport);
        put32(l4, fromClient ? cseq : sseq);
        put32(l4, (flags & 0x10) ? (fromClient ? sseq : cseq) : 0);
        l4.push_back(0x80);  // 32-byte header: timestamps option
        l4.push_back(flags);
        put16(l4, 2048);
        put16(l4, 0);
        put16(l4, 0);
        const Bytes opts = {1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 1};
        append(l4, opts);
        append(l4, payload);
        frame(t, fromClient ? client : server, fromClient ? server : client, kProtoTcp, std::move(l4), 32,
              std::min(keep, payload.size()));
        uint32_t used = uint32_t(payload.size()) + ((flags & 0x03) ? 1 : 0);
        (fromClient ? cseq : sseq) += used;
    }

    double open(double t) {
        segment(t, true, 0x02, {});
        segment(t + rtt / 2, false, 0x12, {});
        segment(t + rtt, true, 0x10, {});
        return t + rtt;
    }

    /** Sends data in 1448-byte segments, acknowledged every other segment. */
    double send(double t, bool fromClient, const Bytes& data, size_t keepPerSegment = SIZE_MAX,
                double gap = 0.0002) {
        size_t off = 0;
        int n = 0;
        while (off < data.size()) {
            size_t len = std::min<size_t>(1448, data.size() - off);
            Bytes seg(data.begin() + long(off), data.begin() + long(off + len));
            segment(t, fromClient, 0x18, seg, keepPerSegment);
            if (++n % 2 == 0) segment(t + rtt / 2, !fromClient, 0x10, {});
            off += len;
            t += gap;
        }
        segment(t + rtt / 2, !fromClient, 0x10, {});
        return t + rtt;
    }

    /** Bulk data from the server at about rate bytes a second; headers only. */
    double download(double t0, double t1, double rate) {
        double t = t0;
        while (t < t1) {
            size_t chunk = size_t(rate * 0.1 * uniform(0.85, 1.15));
            Bytes zeros(chunk);
            send(t, false, zeros, 0, 0.1 / double((chunk + 1447) / 1448));
            t += 0.1;
        }
        return t;
    }

    void close(double t) {
        segment(t, true, 0x11, {});
        segment(t + rtt / 2, false, 0x11, {});
        segment(t + rtt, true, 0x10, {});
    }
};

// ---- TLS ------------------------------------------------------------------

/**
 * A TLS 1.3 ClientHello like a browser's. With a post-quantum key share it is
 * about 1.8 kB, too big for one segment, and the server name comes after the
 * key share, so it lands in the second segment.
 */
Bytes clientHello(const std::string& host, bool postQuantum) {
    Bytes ext;
    auto extension = [&](uint16_t type, const Bytes& body) {
        put16(ext, type);
        put16(ext, uint16_t(body.size()));
        append(ext, body);
    };
    Bytes groups;
    put16(groups, postQuantum ? 6 : 4);
    if (postQuantum) put16(groups, 0x11ec);
    put16(groups, 0x001d);
    put16(groups, 0x0017);
    Bytes keyShare;
    Bytes shares;
    if (postQuantum) {
        put16(shares, 0x11ec);
        put16(shares, 1216);
        append(shares, randomBytes(1216));
    }
    put16(shares, 0x001d);
    put16(shares, 32);
    append(shares, randomBytes(32));
    put16(keyShare, uint16_t(shares.size()));
    append(keyShare, shares);
    Bytes sni;
    put16(sni, uint16_t(host.size() + 3));
    sni.push_back(0);
    put16(sni, uint16_t(host.size()));
    append(sni, text(host));
    const Bytes alpn = {0, 12, 2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    const Bytes versions = {4, 0x03, 0x04, 0x03, 0x03};
    const Bytes sigalgs = {0, 8, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03};

    extension(0x000a, groups);
    extension(0x0033, keyShare);
    extension(0x0010, alpn);
    extension(0x0000, sni);
    extension(0x002b, versions);
    extension(0x000d, sigalgs);

    Bytes body;
    put16(body, 0x0303);
    append(body, randomBytes(32));
    body.push_back(32);
    append(body, randomBytes(32));
    const uint16_t suites[] = {0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8};
    put16(body, uint16_t(sizeof suites));
    for (uint16_t s : suites) put16(body, s);
    body.push_back(1);
    body.push_back(0);
    put16(body, uint16_t(ext.size()));
    append(body, ext);

    Bytes hs = {1};
    hs.push_back(uint8_t(body.size() >> 16));
    put16(hs, uint16_t(body.size()));
    append(hs, body);
    Bytes rec = {0x16, 0x03, 0x01};
    put16(rec, uint16_t(hs.size()));
    append(rec, hs);
    return rec;
}

Bytes tlsRecords(size_t n) {
    Bytes out;
    while (out.size() < n) {
        size_t len = std::min<size_t>(n - out.size(), 16384);
        out.push_back(0x17);
        out.push_back(0x03);
        out.push_back(0x03);
        put16(out, uint16_t(len));
        append(out, randomBytes(len));
    }
    return out;
}

/** A TLS connection: handshake, a request, a response of respBytes. Returns the end time. */
double tlsSession(Tcp& c, double t, const std::string& host, size_t reqBytes, size_t respBytes, bool pq = false) {
    t = c.open(t);
    t = c.send(t, true, clientHello(host, pq));
    t = c.send(t, false, tlsRecords(4200));  // ServerHello, certificate, ...
    t = c.send(t, true, tlsRecords(reqBytes));
    t = c.send(t, false, tlsRecords(respBytes));
    return t;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s OUTPUT.pcap\n", argv[0]);
        return 2;
    }
    const std::string out = argv[1];

    // Addresses of the made-up services.
    const IpAddr youtube = ip("142.250.187.238");
    const IpAddr video6 = ip("2a00:1450:4009:81e::200e");
    const IpAddr github = ip("140.82.121.4");
    const IpAddr spotifyCdn = ip("151.101.2.248");
    const IpAddr spotifyApi = ip("35.186.224.24");
    const IpAddr slack = ip("54.230.10.71");
    const IpAddr gmail = ip("64.233.184.109");
    const IpAddr apns = ip("17.57.146.20");
    const IpAddr apple = ip("17.253.53.207");
    const IpAddr timeApple = ip("17.253.52.125");
    const IpAddr nas = ip("192.168.1.50");
    const IpAddr eicarHost = ip("203.0.113.80");
    const IpAddr figma = ip("13.227.2.94");

    const double end = 180;

    // Chrome: YouTube, a video over QUIC for the whole capture, GitHub.
    lookup(2.0, "www.youtube.com", {youtube}, "youtube-ui.l.google.com");
    {
        Tcp c("Google Chrome", kLaptop, youtube, 443);
        double t = tlsSession(c, 2.1, "www.youtube.com", 1800, 380000);
        c.close(t + 30);
    }
    lookup(3.0, "rr4---sn-q0cedn7s.googlevideo.com", {video6});
    {
        const uint16_t port = ephemeralPort();
        owns("Google Chrome", kProtoUdp, kLaptop6, port, video6, 443);
        // QUIC Initial from the client, then about 5 Mb/s of video with
        // occasional stalls and refills.
        Bytes initial = {0xc3, 0, 0, 0, 1, 8};
        append(initial, randomBytes(1194));
        udp(3.1, kLaptop6, port, video6, 443, initial);
        for (double t = 3.2; t < end; t += 0.01) {
            double level = 1.0 + 0.25 * std::sin(t / 7.0) + uniform(-0.15, 0.15);
            if (std::fmod(t, 40) < 0.8) level = 2.4;  // buffer refill after a seek
            int packets = int(level * 6.2 + uniform(0, 1));
            for (int i = 0; i < packets; i++) {
                Bytes p = {0x41};
                append(p, randomBytes(1291));
                udp(t + i * 0.0012, video6, 443, kLaptop6, port, p, 24);
            }
            if (rand32() % 6 == 0) {
                Bytes ack = {0x43};
                append(ack, randomBytes(46));
                udp(t + 0.005, kLaptop6, port, video6, 443, ack, 24);
            }
        }
    }
    lookup(31.0, "github.com", {github});
    {
        Tcp c("Google Chrome", kLaptop, github, 443);
        double t = tlsSession(c, 31.1, "github.com", 2400, 210000, true);  // split ClientHello
        c.close(t + 5);
    }
    lookup(52.0, "www.figma.com", {figma}, "d1xz5s4wbe9f8z.cloudfront.net");
    {
        Tcp c("Figma", kLaptop, figma, 443);
        double t = tlsSession(c, 52.1, "www.figma.com", 3000, 1400000);
        for (double s = t + 2; s < end; s += 9) c.send(s, false, tlsRecords(2000 + rand32() % 6000));
    }

    // Spotify: a stream fetched in chunks, and its API now and then.
    lookup(4.0, "audio-ak-spotify-com.akamaized.net", {spotifyCdn}, "a1234.dscb.akamai.net");
    {
        Tcp c("Spotify", kLaptop, spotifyCdn, 443, 0.012);
        double t = tlsSession(c, 4.1, "audio-ak-spotify-com.akamaized.net", 900, 420000);
        for (double s = t + 8; s < end; s += 10) {
            c.send(s, true, tlsRecords(700));
            c.send(s + 0.02, false, tlsRecords(390000 + rand32() % 60000), 0);
        }
    }
    lookup(6.0, "spclient.wg.spotify.com", {spotifyApi}, "edge-web.dual-gslb.spotify.com");
    {
        Tcp c("Spotify", kLaptop, spotifyApi, 443);
        double t = tlsSession(c, 6.1, "spclient.wg.spotify.com", 1500, 9000);
        for (double s = t + 15; s < end; s += 30) {
            c.send(s, true, tlsRecords(1200));
            c.send(s + 0.04, false, tlsRecords(5000));
        }
    }

    // Slack's websocket, Mail over IMAP, Apple push: small and steady.
    lookup(1.0, "wss-primary.slack.com", {slack});
    {
        Tcp c("Slack", kLaptop, slack, 443, 0.03);
        double t = tlsSession(c, 1.1, "wss-primary.slack.com", 1100, 6000);
        for (double s = t + 3; s < end; s += uniform(2, 7)) {
            c.send(s, false, tlsRecords(200 + rand32() % 2500));
            if (rand32() % 3 == 0) c.send(s + 0.5, true, tlsRecords(300 + rand32() % 900));
        }
    }
    lookup(8.0, "imap.gmail.com", {gmail}, "imap.l.google.com");
    {
        Tcp c("Mail", kLaptop, gmail, 993);
        double t = tlsSession(c, 8.1, "imap.gmail.com", 400, 30000);
        for (double s = t + 29; s < end; s += 29) {
            c.send(s, true, tlsRecords(120));
            c.send(s + 0.03, false, tlsRecords(900));
        }
    }
    {
        Tcp c("apsd", kLaptop, apns, 5223, 0.04);
        double t = tlsSession(c, 0.5, "courier.push.apple.com", 300, 5000);
        for (double s = t + 20; s < end; s += 20) {
            c.send(s, true, tlsRecords(60));
            c.send(s + 0.04, false, tlsRecords(60));
        }
    }
    {
        uint16_t port = ephemeralPort();
        owns("timed", kProtoUdp, kLaptop, port, timeApple, 123);
        lookup(59.9, "time.apple.com", {timeApple});
        Bytes ntp(48);
        ntp[0] = 0x23;
        udp(60.0, kLaptop, port, timeApple, 123, ntp);
        ntp[0] = 0x24;
        udp(60.02, timeApple, 123, kLaptop, port, ntp);
    }
    // Other devices announcing themselves over mDNS.
    for (double t = 5; t < end; t += 17) {
        Bytes m(90);
        m[5] = 1;
        udp(t, ip("192.168.1.30"), 5353, ip("224.0.0.251"), 5353, randomBytes(120));
    }
    lookup(88.0, "telemetry.nonexistent-vendor.io", {});

    // 0:45: curl sends a password to the NAS over plain HTTP.
    {
        Tcp c("curl", kLaptop, nas, 80, 0.002);
        double t = c.open(45.0);
        t = c.send(t, true,
                   text("GET /api/v1/shares HTTP/1.1\r\nHost: nas.home\r\nUser-Agent: curl/8.7.1\r\n"
                        "Authorization: Basic YWRtaW46aHVudGVyMg==\r\nAccept: */*\r\n\r\n"));
        t = c.send(t, false,
                   text("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 58\r\n\r\n"
                        "{\"shares\":[\"backups\",\"photos\",\"media\"],\"status\":\"ok\"}\r\n"));
        c.close(t + 0.01);
    }

    // 1:10: another machine scans this one's ports. Closed ports answer with a
    // reset; SSH answers and the scanner resets it.
    {
        std::vector<uint16_t> ports;
        for (uint16_t p = 1; p <= 1024; p++) ports.push_back(p);
        std::shuffle(ports.begin(), ports.end(), rng);
        ports.resize(300);
        double t = 70.0;
        for (uint16_t port : ports) {
            Tcp probe("", kScanner, kLaptop, port, 0.001);
            probe.segment(t, true, 0x02, {});
            if (port == 22) {
                probe.segment(t + 0.0005, false, 0x12, {});
                probe.segment(t + 0.001, true, 0x04, {});
            } else {
                probe.segment(t + 0.0005, false, 0x14, {});
            }
            t += uniform(0.002, 0.008);
        }
    }

    // 1:35: the EICAR test file over plain HTTP, split across two segments.
    lookup(94.9, "downloads.example.com", {eicarHost});
    {
        Tcp c("curl", kLaptop, eicarHost, 80, 0.03);
        double t = c.open(95.0);
        t = c.send(t, true,
                   text("GET /eicar.com HTTP/1.1\r\nHost: downloads.example.com\r\nUser-Agent: curl/8.7.1\r\n"
                        "Accept: */*\r\n\r\n"));
        const std::string eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        std::string head = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 68\r\n\r\n";
        c.segment(t, false, 0x18, text(head + eicar.substr(0, 30)));
        c.segment(t + 0.0003, false, 0x18, text(eicar.substr(30)));
        c.segment(t + 0.015, true, 0x10, {});
        c.close(t + 0.05);
    }

    // 2:00: a software update downloads at about 30 MB/s for ten seconds.
    lookup(119.8, "swcdn.apple.com", {apple}, "swcdn.apple.com.akadns.net");
    {
        Tcp c("softwareupdated", kLaptop, apple, 443, 0.008);
        double t = tlsSession(c, 119.9, "swcdn.apple.com", 900, 60000);
        t = c.download(t, t + 1.0, 8e6);
        t = c.download(t, t + 10.0, 30e6);
        t = c.download(t, t + 1.0, 6e6);
        c.close(t + 0.2);
    }

    // 2:40: a SYN flood against a development server on port 3000.
    {
        const uint16_t listen = 3000;
        owns("node", kProtoTcp, kLaptop, listen, ip("0.0.0.0"), 0);
        double t = 160.0;
        while (t < 166.0) {
            Tcp probe("", kScanner, kLaptop, listen, 0.001);
            probe.segment(t, true, 0x02, {});
            probe.segment(t + 0.0004, false, 0x12, {});
            t += uniform(0.0006, 0.0016);
        }
    }

    if (!writePcap(out)) {
        std::fprintf(stderr, "can't write %s\n", out.c_str());
        return 1;
    }
    std::ofstream apps(out + ".apps");
    apps << "# App names for the sample capture (made up, like the traffic)\n";
    apps << "# local " << kLaptop.str() << "\n# local " << kLaptop6.str() << "\n";
    for (const auto& l : appLines) apps << l << '\n';
    std::printf("wrote %s: %zu packets\n", out.c_str(), records.size());
    return 0;
}
