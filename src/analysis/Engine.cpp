#include "analysis/Engine.h"

#include <algorithm>
#include <cctype>
#include <cstring>

#include "analysis/Dns.h"
#include "analysis/Tls.h"
#include "core/Format.h"

namespace pm {
namespace {

constexpr int64_t kSec = 1000000;
constexpr size_t kHistorySeconds = 3600;
constexpr size_t kSnapshotHistory = 900;
constexpr size_t kServiceWindow = 60;
constexpr size_t kMaxDnsNames = 65536;
constexpr size_t kMaxHelloBytes = 16384;
constexpr size_t kMaxAlertsKept = 1000;
constexpr int kOwnerTries = 6;
constexpr size_t kMaxHosts = 5000;

enum : uint8_t {
    kSynSeen = 1,
    kSynAckSeen = 2,
    kEstablished = 4,
    kFinA = 8,
    kFinB = 16,
    kReset = 32,
};

enum : uint8_t { kHostNone = 0, kHostDns = 2, kHostHttp = 3, kHostSni = 4 };
enum : uint8_t { kHelloWaiting = 0, kHelloBuffering = 1, kHelloDone = 2 };

bool startsWith(const uint8_t* d, size_t len, const char* prefix) {
    size_t n = std::strlen(prefix);
    return len >= n && std::memcmp(d, prefix, n) == 0;
}

bool isHttpRequest(const uint8_t* d, size_t len) {
    static const char* const methods[] = {"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ",
                                          "CONNECT "};
    for (const char* m : methods) {
        if (startsWith(d, len, m)) return true;
    }
    return false;
}

/** The Host header of an HTTP request, without a port. */
std::string httpHost(const uint8_t* d, size_t len) {
    len = std::min<size_t>(len, 4096);
    for (size_t i = 0; i + 7 < len; i++) {
        if (d[i] != '\n') continue;
        const char* h = "host:";
        size_t k = 0;
        while (k < 5 && i + 1 + k < len && std::tolower(d[i + 1 + k]) == h[k]) k++;
        if (k != 5) continue;
        size_t p = i + 6;
        while (p < len && d[p] == ' ') p++;
        std::string host;
        while (p < len && d[p] != '\r' && d[p] != '\n' && d[p] != ':' && host.size() < 253) {
            char c = char(std::tolower(d[p++]));
            if (!std::isalnum(static_cast<unsigned char>(c)) && c != '.' && c != '-' && c != '_') return "";
            host += c;
        }
        return host;
    }
    return "";
}

}  // namespace

struct Engine::Flow {
    FlowKey key;
    bool aLocal = true;   // side a is this machine
    bool aClient = true;  // side a opened the conversation
    Service service = Service::Other;
    uint8_t hostSource = kHostNone;
    std::string host;
    std::string remoteStr;
    std::string app;
    uint8_t ownerTries = 0;
    bool ownerDone = false;
    bool transit = false;  // between two other hosts

    int64_t first = 0, last = 0;
    uint64_t bytes[2] = {0, 0};  // [0] a to b, [1] b to a
    uint64_t tickBytes[2] = {0, 0};
    double rate[2] = {0, 0};

    uint8_t tcp = 0;
    uint8_t hello = kHelloWaiting;
    bool seqKnown[2] = {false, false};
    uint32_t nextSeq[2] = {0, 0};
    SignatureSet::Stream sig[2];
    std::string helloBuf;

    int clientDir() const { return aClient ? 0 : 1; }
    int localOutDir() const { return aLocal ? 0 : 1; }  // direction of traffic leaving this machine
    const IpAddr& remoteAddr() const { return aLocal ? key.b : key.a; }
    uint16_t remotePort() const { return aLocal ? key.pb : key.pa; }
    const IpAddr& localAddr() const { return aLocal ? key.a : key.b; }
    uint16_t localPort() const { return aLocal ? key.pa : key.pb; }
    uint16_t serverPort() const { return aClient ? key.pb : key.pa; }
    const IpAddr& serverAddr() const { return aClient ? key.b : key.a; }
    std::string displayHost() const { return host.empty() ? remoteStr : host; }
};

Engine::Engine(EngineConfig config, const SignatureSet* signatures, OwnerLookup* owners)
    : cfg_(std::move(config)),
      sigs_(signatures),
      owners_(owners),
      portScan_(cfg_.detectors),
      synFlood_(cfg_.detectors),
      spikeIn_(cfg_.detectors, "Inbound"),
      spikeOut_(cfg_.detectors, "Outbound") {
    for (const auto& a : cfg_.localAddresses) local_.insert(a.unmapped());
    auto empty = std::make_shared<Snapshot>();
    empty->source = cfg_.source;
    empty->linkName = cfg_.linkName;
    empty->live = cfg_.live;
    snapshot_ = empty;
}

Engine::~Engine() = default;

bool Engine::isLocal(const IpAddr& a) const {
    if (local_.empty()) return a.isPrivate();
    return a.isLoopback() || local_.count(a.unmapped()) > 0;
}

std::string Engine::hostFor(const IpAddr& addr) const {
    auto it = dnsNames_.find(addr.unmapped());
    return it == dnsNames_.end() ? std::string() : it->second;
}

void Engine::account(uint64_t bytes, bool out) {
    (out ? secOut_ : secIn_) += bytes;
}

// ---- Packets --------------------------------------------------------------

void Engine::process(const PacketRecordHeader& h, const uint8_t* data) {
    advanceTo(h.tsUsec);
    nowUsec_ = std::max(nowUsec_, h.tsUsec);
    packets_++;
    bytes_ += h.wireLen;
    secPackets_++;

    PacketView p;
    DecodeResult r = decode(cfg_.linkType, data, h.capLen, h.wireLen, h.tsUsec, p);
    if (r != DecodeResult::Ok) {
        (r == DecodeResult::NotIp ? notIp_ : malformed_)++;
        account(h.wireLen, false);
        secService_[int(Service::Other)] += h.wireLen;
        return;
    }

    // Connection attempts count even if the flow table is full: that is
    // exactly what a flood looks like.
    const bool attempt = p.proto == kProtoTcp && p.hasL4 && (p.tcpFlags & kTcpSyn) && !(p.tcpFlags & kTcpAck);
    if (attempt) {
        portScan_.onAttempt(p.tsUsec, p.src, p.dst, p.dport);
        synFlood_.onAttempt(p.tsUsec, p.dst, p.dport);
    }

    if (p.hasL4 && p.payloadLen > 0 && p.sport == 53 && (p.proto == kProtoUdp || p.proto == kProtoTcp)) handleDns(p);

    bool srcIsA = false;
    FlowKey key = FlowKey::of(p, srcIsA);
    Flow* f = p.fragment ? nullptr : flowFor(p, key, srcIsA);
    if (!f) {
        bool out = isLocal(p.src) && !isLocal(p.dst);
        account(p.wireLen, out);
        secService_[int(Service::Other)] += p.wireLen;
        return;
    }

    const int dir = srcIsA ? 0 : 1;
    f->last = p.tsUsec;
    f->bytes[dir] += p.wireLen;
    f->tickBytes[dir] += p.wireLen;
    account(p.wireLen, dir == f->localOutDir());

    if (p.proto == kProtoTcp && p.hasL4) handleTcp(*f, p, dir);
    if (p.payloadLen > 0 || (p.proto == kProtoTcp && p.payloadTotal > 0)) handlePayload(*f, p, dir);
    secService_[int(f->service)] += p.wireLen;
}

Engine::Flow* Engine::flowFor(const PacketView& p, const FlowKey& key, bool srcIsA) {
    auto it = flows_.find(key);
    if (it != flows_.end()) {
        Flow& f = *it->second;
        // A new SYN on a closed connection, or with a different initial
        // sequence number, is a new connection reusing the same ports.
        const int dir = srcIsA ? 0 : 1;
        const bool syn = p.proto == kProtoTcp && p.hasL4 && (p.tcpFlags & kTcpSyn) && !(p.tcpFlags & kTcpAck);
        if (syn && ((f.tcp & (kReset | kFinA | kFinB)) || (f.seqKnown[dir] && f.nextSeq[dir] != p.seq + 1))) {
            Flow fresh;
            fresh.key = key;
            for (int d = 0; d < 2; d++) {  // keep the counters, which belong to the address pair
                fresh.bytes[d] = f.bytes[d];
                fresh.tickBytes[d] = f.tickBytes[d];
                fresh.rate[d] = f.rate[d];
            }
            const int64_t first = f.first;
            f = std::move(fresh);
            initFlow(f, p, srcIsA);
            f.first = first;
        }
        return &f;
    }
    if (flows_.size() >= cfg_.maxFlows) makeRoom();
    auto f = std::make_unique<Flow>();
    f->key = key;
    Flow* raw = f.get();
    flows_.emplace(key, std::move(f));
    initFlow(*raw, p, srcIsA);
    return raw;
}

void Engine::makeRoom() {
    // Rather than stop tracking new connections when the table is full (which
    // a flood of spoofed SYNs could force), drop a tenth of it: half-open
    // connections first, then the longest idle.
    std::vector<std::pair<int64_t, const FlowKey*>> order;
    order.reserve(flows_.size());
    for (const auto& [k, f] : flows_) {
        const bool halfOpen = k.proto == kProtoTcp && !(f->tcp & kEstablished);
        order.emplace_back(halfOpen ? f->last - (int64_t(1) << 50) : f->last, &k);
    }
    const size_t drop = std::max<size_t>(1, flows_.size() / 10);
    std::nth_element(order.begin(), order.begin() + long(drop - 1), order.end());
    std::vector<FlowKey> victims;
    victims.reserve(drop);
    for (size_t i = 0; i < drop; i++) victims.push_back(*order[i].second);
    for (const auto& k : victims) flows_.erase(k);
    evicted_ += drop;
}

void Engine::initFlow(Flow& f, const PacketView& p, bool srcIsA) {
    f.first = f.last = p.tsUsec;

    // Who started it: a SYN says for certain; otherwise the side on a
    // well-known port is the server.
    bool clientIsSrc;
    const bool srcLocal = isLocal(p.src), dstLocal = isLocal(p.dst);
    if (p.proto == kProtoTcp && p.hasL4 && (p.tcpFlags & kTcpSyn)) {
        clientIsSrc = !(p.tcpFlags & kTcpAck);
    } else {
        bool srcSvc = p.hasL4 && isServicePort(p.proto, p.sport);
        bool dstSvc = p.hasL4 && isServicePort(p.proto, p.dport);
        if (dstSvc != srcSvc) clientIsSrc = dstSvc;
        else if (srcSvc && p.sport != p.dport) clientIsSrc = p.sport > p.dport;
        else clientIsSrc = srcLocal || !dstLocal;
    }
    f.aClient = clientIsSrc == srcIsA;

    // Which end is this machine: the local address. With both local
    // (loopback), the client. With neither, this machine is at most a
    // receiver: of multicast or broadcast, or of other hosts' traffic seen in
    // promiscuous mode, which isn't ours to look up.
    bool localIsSrc;
    if (srcLocal != dstLocal) {
        localIsSrc = srcLocal;
    } else if (srcLocal) {
        localIsSrc = clientIsSrc;
    } else {
        localIsSrc = false;
        f.transit = !p.dst.isMulticastOrBroadcast();
    }
    f.aLocal = localIsSrc == srcIsA;

    f.service = classifyPort(p.proto, p.hasL4 ? f.serverPort() : 0);
    f.remoteStr = f.remoteAddr().str();
    auto it = dnsNames_.find(f.remoteAddr().unmapped());
    if (it != dnsNames_.end()) {
        f.host = it->second;
        f.hostSource = kHostDns;
    }
    tryOwner(f);
}

void Engine::handleTcp(Flow& f, const PacketView& p, int dir) {
    const uint8_t fl = p.tcpFlags;
    const bool fromClient = dir == f.clientDir();
    if (fl & kTcpSyn) {
        f.seqKnown[dir] = true;
        f.nextSeq[dir] = p.seq + 1;
        f.tcp |= (fl & kTcpAck) ? kSynAckSeen : kSynSeen;
    } else if ((fl & kTcpAck) && fromClient && (f.tcp & kSynAckSeen) && !(f.tcp & kEstablished)) {
        f.tcp |= kEstablished;
        synFlood_.onCompleted(p.tsUsec, f.serverAddr(), f.serverPort());
    }
    if (fl & kTcpFin) f.tcp |= dir == 0 ? kFinA : kFinB;
    if (fl & kTcpRst) f.tcp |= kReset;
}

void Engine::handlePayload(Flow& f, const PacketView& p, int dir) {
    const uint8_t* data = p.payload;
    size_t len = p.payloadLen;
    bool gap = false;

    if (p.proto == kProtoTcp) {
        // Follow the byte stream: skip retransmitted bytes and notice gaps, so
        // a signature split across segments is still found exactly once.
        uint32_t seq = p.seq + ((p.tcpFlags & kTcpSyn) ? 1 : 0);
        if (!f.seqKnown[dir]) {
            f.seqKnown[dir] = true;
            f.nextSeq[dir] = seq;
            gap = true;  // joined mid-stream
        }
        uint32_t end = seq + p.payloadTotal;
        int32_t ahead = int32_t(seq - f.nextSeq[dir]);
        if (ahead < 0) {
            if (int32_t(end - f.nextSeq[dir]) <= 0) return;  // all seen before
            size_t skip = f.nextSeq[dir] - seq;
            if (skip >= len) {
                f.nextSeq[dir] = end;
                f.sig[dir] = {};
                return;
            }
            data += skip;
            len -= skip;
        } else if (ahead > 0) {
            gap = true;
            f.sig[dir] = {};
        }
        f.nextSeq[dir] = end;
        if (dir == f.clientDir() && f.hello != kHelloDone) {
            // A hole in a ClientHello we were collecting, or bytes we didn't
            // capture, means the rest of it can't be read.
            inspectClientStart(f, data, len, gap && f.hello == kHelloBuffering);
            if (p.payloadTruncated() && f.hello == kHelloBuffering) inspectClientStart(f, nullptr, 0, true);
        }
    }

    if (sigs_ && sigs_->size() && len > 0) {
        SignatureSet::Stream fresh;
        SignatureSet::Stream& st = p.proto == kProtoTcp ? f.sig[dir] : fresh;
        sigs_->scan(st, data, len, [&](uint32_t id) { signatureAlert(f, p, id); });
    }
    // Bytes we didn't capture break the stream.
    if (p.proto == kProtoTcp && p.payloadTruncated()) f.sig[dir] = {};
}

void Engine::inspectClientStart(Flow& f, const uint8_t* data, size_t len, bool gap) {
    if (gap) {
        f.hello = kHelloDone;
        f.helloBuf.clear();
        return;
    }
    if (f.hello == kHelloWaiting) {
        if (len == 0) return;
        if (len < 6 && data[0] == 0x16) {  // a record header split off on its own
            f.service = Service::Tls;
            f.helloBuf.assign(reinterpret_cast<const char*>(data), len);
            f.hello = kHelloBuffering;
            return;
        }
        if (!looksLikeTlsHandshake(data, len)) {
            f.hello = kHelloDone;
            if (isHttpRequest(data, len)) {
                f.service = Service::Http;
                std::string host = httpHost(data, len);
                if (!host.empty()) setHost(f, host, kHostHttp);
            } else if (startsWith(data, len, "SSH-")) {
                f.service = Service::Ssh;
            }
            return;
        }
        f.service = Service::Tls;
        std::string host;
        SniResult r = extractSni(data, len, host);
        if (r == SniResult::Found) setHost(f, host, kHostSni);
        if (r == SniResult::NeedMore) {
            f.helloBuf.assign(reinterpret_cast<const char*>(data), len);
            f.hello = kHelloBuffering;
        } else {
            f.hello = kHelloDone;
        }
        return;
    }
    // Buffering a ClientHello that spans several segments.
    f.helloBuf.append(reinterpret_cast<const char*>(data), len);
    std::string host;
    SniResult r = extractSni(reinterpret_cast<const uint8_t*>(f.helloBuf.data()), f.helloBuf.size(), host);
    if (r == SniResult::Found) setHost(f, host, kHostSni);
    if (r == SniResult::NotTls) f.service = classifyPort(f.key.proto, f.serverPort());
    if (r != SniResult::NeedMore || f.helloBuf.size() > kMaxHelloBytes) {
        f.hello = kHelloDone;
        std::string().swap(f.helloBuf);
    }
}

void Engine::handleDns(const PacketView& p) {
    DnsMessage m;
    bool ok = p.proto == kProtoTcp ? parseDnsTcp(p.payload, p.payloadLen, m) : parseDns(p.payload, p.payloadLen, m);
    if (!ok || !m.response || m.question.empty()) return;

    for (const auto& a : m.answers) {
        if (!a.addr.valid()) continue;
        if (dnsNames_.size() >= kMaxDnsNames && !dnsNames_.count(a.addr.unmapped())) {
            // Forget a quarter of the names rather than track them all forever.
            size_t drop = dnsNames_.size() / 4;
            for (auto it = dnsNames_.begin(); it != dnsNames_.end() && drop; drop--) it = dnsNames_.erase(it);
        }
        // Remember the name that was asked for, not the CDN name it resolves through.
        dnsNames_[a.addr.unmapped()] = m.question;
    }

    if (!lookups_.empty() && lookups_.front().name == m.question && p.tsUsec - lookups_.front().tsUsec < 2 * kSec) {
        if (m.rcode == 0) lookups_.front().failed = false;
        return;  // the A and AAAA answers for one lookup
    }
    lookups_.push_front(Lookup{p.tsUsec, m.question, m.qtype, m.rcode == 3});
    if (lookups_.size() > 100) lookups_.pop_back();
}

void Engine::setHost(Flow& f, std::string host, uint8_t source) {
    if (host.empty() || source < f.hostSource) return;
    f.host = std::move(host);
    f.hostSource = source;
}

void Engine::tryOwner(Flow& f) {
    if (f.ownerDone) return;
    if (!owners_ || f.transit || (f.key.proto != kProtoTcp && f.key.proto != kProtoUdp)) {
        f.ownerDone = true;
        return;
    }
    Owner o;
    if (owners_->find(f.key.proto, f.localAddr(), f.localPort(), f.remoteAddr(), f.remotePort(), o)) {
        f.app = o.app;
        f.ownerDone = true;
        if (ownerLog_) {
            *ownerLog_ << RecordedOwners::line(f.key.proto, f.localAddr(), f.localPort(), f.remoteAddr(),
                                               f.remotePort(), f.app)
                       << '\n';
        }
        return;
    }
    if (f.ownerTries++ == 0) owners_->requestRefresh();
    if (f.ownerTries >= kOwnerTries) f.ownerDone = true;
}

// ---- Alerts ---------------------------------------------------------------

void Engine::raise(Alert a) {
    alertCount_++;
    if (alertCallback_) alertCallback_(a);
    alerts_.push_back(std::move(a));
    if (alerts_.size() > kMaxAlertsKept) alerts_.pop_front();
}

void Engine::signatureAlert(Flow& f, const PacketView& p, uint32_t sigIndex) {
    const Signature& s = sigs_->signatures()[sigIndex];
    std::string key = s.name + '|' + p.src.str() + '|' + p.dst.str();
    auto it = sigCooldown_.find(key);
    if (it != sigCooldown_.end() && p.tsUsec - it->second < int64_t(cfg_.detectors.cooldownSec) * kSec) return;
    if (sigCooldown_.size() > 10000) sigCooldown_.clear();
    sigCooldown_[key] = p.tsUsec;

    auto endpoint = [](const IpAddr& a, uint16_t port) {
        return a.family == 6 ? "[" + a.str() + "]:" + std::to_string(port) : a.str() + ":" + std::to_string(port);
    };
    Alert a;
    a.tsUsec = p.tsUsec;
    a.kind = AlertKind::Signature;
    a.severity = s.severity;
    a.title = s.message;
    a.src = endpoint(p.src, p.sport);
    a.dst = endpoint(p.dst, p.dport);
    a.message = a.src + " → " + a.dst;
    if (!f.host.empty() && f.host != f.remoteStr) a.message += " (" + f.host + ")";
    if (!f.app.empty()) a.message += ", " + f.app;
    a.message += ", signature " + s.name;
    raise(std::move(a));
}

// ---- Time -----------------------------------------------------------------

void Engine::advanceTo(int64_t now) {
    if (now <= 0) return;
    if (nextTick_ == 0) {
        startUsec_ = now;
        nextTick_ = (now / kSec + 1) * kSec;
        return;
    }
    if (now < nextTick_ - 10 * kSec) {
        // Time went backwards (the clock was corrected, or a bad timestamp
        // pushed us ahead): start again from now rather than wait.
        nextTick_ = (now / kSec + 1) * kSec;
        nowUsec_ = now;
        portScan_.reset();
        synFlood_.reset();
        return;
    }
    int caughtUp = 0;
    while (now >= nextTick_) {
        tick(nextTick_);
        nextTick_ += kSec;
        // After a long silence in a capture, skip ahead rather than tick through it.
        if (++caughtUp >= 900 && now >= nextTick_) nextTick_ = (now / kSec) * kSec;
    }
}

void Engine::finish() {
    if (nextTick_ != 0) {
        tick(nextTick_);
        nextTick_ += kSec;
    }
    finished_ = true;
    publish(nowUsec_);
}

void Engine::tick(int64_t t) {
    nowUsec_ = std::max(nowUsec_, t);
    // 1. Close the second that just ended.
    SecondSample s{t / kSec - 1, secIn_, secOut_, secPackets_};
    history_.push_back(s);
    if (history_.size() > kHistorySeconds) history_.pop_front();
    spikeIn_.onSecond(t, double(secIn_), pending_);
    spikeOut_.onSecond(t, double(secOut_), pending_);
    std::array<uint64_t, kServiceCount> svc;
    std::copy(std::begin(secService_), std::end(secService_), svc.begin());
    serviceWindow_.push_back(svc);
    if (serviceWindow_.size() > kServiceWindow) serviceWindow_.pop_front();
    secIn_ = secOut_ = secPackets_ = 0;
    std::fill(std::begin(secService_), std::end(secService_), 0);

    // 2. Rates, totals by app and host, and expiry.
    if (cfg_.publish) {
        for (auto& [name, g] : apps_) g.flows = 0, g.rateIn = g.rateOut = 0, g.detailRate = -1;
        for (auto& [name, g] : hosts_) g.flows = 0, g.rateIn = g.rateOut = 0, g.detailRate = -1;
    }
    for (auto it = flows_.begin(); it != flows_.end();) {
        Flow& f = *it->second;
        for (int d = 0; d < 2; d++) {
            f.rate[d] = 0.5 * f.rate[d] + 0.5 * double(f.tickBytes[d]);
            if (f.rate[d] < 1) f.rate[d] = 0;
        }
        const int outDir = f.localOutDir();
        if (cfg_.publish) {
            const uint64_t in = f.tickBytes[1 - outDir], out = f.tickBytes[outDir];
            const double rIn = f.rate[1 - outDir], rOut = f.rate[outDir];
            const bool active = t - f.last < 60 * kSec;
            auto add = [&](Group& g, const std::string& detail) {
                g.totalIn += in;
                g.totalOut += out;
                if (!active) return;
                g.lastActive = std::max(g.lastActive, f.last);
                g.flows++;
                g.rateIn += rIn;
                g.rateOut += rOut;
                if (rIn + rOut > g.detailRate) {
                    g.detailRate = rIn + rOut;
                    g.detail = detail;
                    g.service = f.service;
                }
            };
            add(apps_[f.app], f.displayHost());
            add(hosts_[f.displayHost()], f.app);
        }
        f.tickBytes[0] = f.tickBytes[1] = 0;

        if (f.hostSource < kHostDns) {
            auto h = dnsNames_.find(f.remoteAddr().unmapped());
            if (h != dnsNames_.end()) setHost(f, h->second, kHostDns);
        }
        if (!f.ownerDone) tryOwner(f);

        int64_t idle = t - f.last, limit;
        if (f.tcp & kReset || ((f.tcp & kFinA) && (f.tcp & kFinB))) limit = 10 * kSec;
        else if (f.key.proto == kProtoTcp && (f.tcp & kSynSeen) && !(f.tcp & kEstablished)) limit = 30 * kSec;
        else if (f.key.proto == kProtoTcp) limit = 300 * kSec;
        else limit = 120 * kSec;
        it = idle > limit ? flows_.erase(it) : std::next(it);
    }
    if (hosts_.size() > kMaxHosts) {
        // Many hosts (a spoofed flood, a scan of the internet): forget the
        // quiet ones, oldest first.
        std::vector<std::pair<int64_t, const std::string*>> quiet;
        for (const auto& [name, g] : hosts_) {
            if (g.flows == 0) quiet.emplace_back(g.lastActive, &name);
        }
        size_t drop = std::min(quiet.size(), hosts_.size() - kMaxHosts / 2);
        if (drop) {
            std::nth_element(quiet.begin(), quiet.begin() + long(drop - 1), quiet.end());
            std::vector<std::string> names;
            for (size_t i = 0; i < drop; i++) names.push_back(*quiet[i].second);
            for (const auto& n : names) hosts_.erase(n);
        }
    }

    // 3. Detectors.
    portScan_.tick(t, pending_);
    synFlood_.tick(t, pending_);
    for (auto& a : pending_) raise(std::move(a));
    pending_.clear();

    if (cfg_.publish) publish(t);
}

void Engine::publish(int64_t t) {
    auto s = std::make_shared<Snapshot>();
    s->nowUsec = t;
    s->startUsec = startUsec_;
    s->source = cfg_.source;
    s->linkName = cfg_.linkName;
    s->live = cfg_.live;
    s->finished = finished_;
    s->appsProblem = appsProblem_;
    if (!history_.empty()) {
        const auto& last = history_.back();
        s->rateIn = double(last.bytesIn);
        s->rateOut = double(last.bytesOut);
        s->packetsPerSec = double(last.packets);
    }
    s->totalBytes = bytes_;
    s->totalPackets = packets_;
    s->kernelDrops = kernelDrops_.load(std::memory_order_relaxed);
    s->ringDrops = ringDrops_.load(std::memory_order_relaxed);
    s->notIp = notIp_;
    s->malformed = malformed_;
    s->trackedFlows = flows_.size();
    s->alertCount = alertCount_;

    size_t from = history_.size() > kSnapshotHistory ? history_.size() - kSnapshotHistory : 0;
    s->history.assign(history_.begin() + long(from), history_.end());

    // Connections that were active in the last minute, busiest first.
    std::vector<const Flow*> recent;
    for (const auto& [k, f] : flows_) {
        if (t - f->last < 60 * kSec) recent.push_back(f.get());
        if (t - f->last < 5 * kSec) s->activeFlows++;
    }
    auto busier = [](const Flow* a, const Flow* b) {
        double ra = a->rate[0] + a->rate[1], rb = b->rate[0] + b->rate[1];
        if (ra != rb) return ra > rb;
        return a->last > b->last;
    };
    size_t keep = std::min<size_t>(recent.size(), 200);
    std::partial_sort(recent.begin(), recent.begin() + long(keep), recent.end(), busier);
    for (size_t i = 0; i < keep; i++) {
        const Flow& f = *recent[i];
        const int out = f.localOutDir();
        FlowRow r;
        r.app = f.app;
        r.host = f.displayHost();
        r.remote = f.remoteAddr().family == 6 ? "[" + f.remoteStr + "]:" + std::to_string(f.remotePort())
                                              : f.remoteStr + ":" + std::to_string(f.remotePort());
        r.service = serviceName(f.service);
        r.rateIn = f.rate[1 - out];
        r.rateOut = f.rate[out];
        r.totalIn = f.bytes[1 - out];
        r.totalOut = f.bytes[out];
        r.firstUsec = f.first;
        r.lastUsec = f.last;
        r.active = t - f.last < 5 * kSec;
        s->flows.push_back(std::move(r));
    }

    auto groups = [&](const std::unordered_map<std::string, Group>& src, std::vector<GroupRow>& dst, size_t max) {
        using Entry = std::pair<const std::string*, const Group*>;
        std::vector<Entry> order;
        for (const auto& [name, g] : src) {
            if (g.totalIn + g.totalOut) order.emplace_back(&name, &g);
        }
        auto first = [](const Entry& a, const Entry& b) {
            double ra = a.second->rateIn + a.second->rateOut, rb = b.second->rateIn + b.second->rateOut;
            if (ra != rb) return ra > rb;
            return a.second->totalIn + a.second->totalOut > b.second->totalIn + b.second->totalOut;
        };
        const size_t keep = std::min(order.size(), max);
        std::partial_sort(order.begin(), order.begin() + long(keep), order.end(), first);
        for (size_t i = 0; i < keep; i++) {
            const std::string& name = *order[i].first;
            const Group& g = *order[i].second;
            GroupRow r;
            r.name = name;
            r.detail = g.detail;
            r.service = g.flows ? serviceName(g.service) : "";
            r.flows = g.flows;
            r.rateIn = g.rateIn;
            r.rateOut = g.rateOut;
            r.totalIn = g.totalIn;
            r.totalOut = g.totalOut;
            dst.push_back(std::move(r));
        }
    };
    groups(apps_, s->apps, 100);
    groups(hosts_, s->hosts, 200);

    uint64_t svc[kServiceCount] = {};
    for (const auto& sec : serviceWindow_) {
        for (int i = 0; i < kServiceCount; i++) svc[i] += sec[i];
    }
    for (int i = 0; i < kServiceCount; i++) {
        if (svc[i]) s->services.push_back(ServiceShare{serviceName(Service(i)), svc[i]});
    }
    std::sort(s->services.begin(), s->services.end(),
              [](const ServiceShare& a, const ServiceShare& b) { return a.bytes > b.bytes; });

    s->lookups.assign(lookups_.begin(), lookups_.begin() + long(std::min<size_t>(lookups_.size(), 50)));
    for (auto it = alerts_.rbegin(); it != alerts_.rend() && s->alerts.size() < 100; ++it) s->alerts.push_back(*it);

    std::lock_guard<std::mutex> lk(snapMu_);
    snapshot_ = std::move(s);
}

std::shared_ptr<const Snapshot> Engine::snapshot() const {
    std::lock_guard<std::mutex> lk(snapMu_);
    return snapshot_;
}

}  // namespace pm
