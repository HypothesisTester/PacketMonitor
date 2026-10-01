#include "procs/Owners.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>

namespace pm {
namespace {

bool isAny(const IpAddr& a) {
    for (uint8_t b : a.bytes) {
        if (b) return false;
    }
    return true;
}

bool sameAddr(const IpAddr& a, const IpAddr& b) { return a.unmapped() == b.unmapped(); }

uint32_t portKey(uint8_t proto, uint16_t port) { return uint32_t(proto) << 16 | port; }

const char* protoName(uint8_t proto) { return proto == kProtoTcp ? "tcp" : proto == kProtoUdp ? "udp" : "ip"; }

}  // namespace

// ---- SocketTable ----------------------------------------------------------

uint32_t SocketTable::internApp(const std::string& name) {
    auto it = appIds_.find(name);
    if (it != appIds_.end()) return it->second;
    uint32_t id = uint32_t(apps_.size());
    apps_.push_back(name);
    appIds_.emplace(name, id);
    return id;
}

void SocketTable::index() {
    byPort_.clear();
    byPort_.reserve(entries_.size());
    for (uint32_t i = 0; i < entries_.size(); i++) {
        byPort_.emplace(portKey(entries_[i].proto, entries_[i].localPort), i);
    }
}

bool SocketTable::find(uint8_t proto, const IpAddr& localIp, uint16_t localPort, const IpAddr& remoteIp,
                       uint16_t remotePort, Owner& out) const {
    auto range = byPort_.equal_range(portKey(proto, localPort));
    const SocketEntry* best = nullptr;
    int bestScore = 0;
    for (auto it = range.first; it != range.second; ++it) {
        const SocketEntry& e = entries_[it->second];
        if (!isAny(e.local) && !sameAddr(e.local, localIp)) continue;
        int score;
        if (isAny(e.remote) && e.remotePort == 0) {
            score = isAny(e.local) ? 1 : 2;  // listening or unconnected
        } else if (e.remotePort == remotePort && sameAddr(e.remote, remoteIp)) {
            score = 3;  // this exact connection
        } else {
            continue;
        }
        if (score > bestScore) {
            bestScore = score;
            best = &e;
        }
    }
    if (!best) return false;
    out.pid = best->pid;
    out.app = best->app < apps_.size() ? apps_[best->app] : std::string();
    return true;
}

// ---- SystemOwners ---------------------------------------------------------

SystemOwners::SystemOwners() : thread_([this] { run(); }) {}

SystemOwners::~SystemOwners() {
    {
        std::lock_guard<std::mutex> lk(mu_);
        stop_ = true;
    }
    cv_.notify_all();
    thread_.join();
}

void SystemOwners::run() {
    using namespace std::chrono;
    for (;;) {
        auto table = std::make_shared<SocketTable>();
        std::string error;
        bool ok = readSystemSockets(*table, error);
        table->index();
        std::unique_lock<std::mutex> lk(mu_);
        if (ok) table_ = std::move(table);
        problem_ = ok ? std::string() : error;
        cv_.wait_for(lk, seconds(2), [this] { return stop_ || wanted_; });
        if (stop_) return;
        bool asked = wanted_;
        wanted_ = false;
        lk.unlock();
        // Let a burst of new connections share one refresh.
        if (asked) std::this_thread::sleep_for(milliseconds(150));
    }
}

bool SystemOwners::find(uint8_t proto, const IpAddr& localIp, uint16_t localPort, const IpAddr& remoteIp,
                        uint16_t remotePort, Owner& out) {
    std::shared_ptr<const SocketTable> t;
    {
        std::lock_guard<std::mutex> lk(mu_);
        t = table_;
    }
    return t && t->find(proto, localIp, localPort, remoteIp, remotePort, out);
}

void SystemOwners::requestRefresh() {
    {
        std::lock_guard<std::mutex> lk(mu_);
        wanted_ = true;
    }
    cv_.notify_one();
}

std::string SystemOwners::problem() const {
    std::lock_guard<std::mutex> lk(mu_);
    return problem_;
}

// ---- RecordedOwners -------------------------------------------------------

std::string RecordedOwners::key(uint8_t proto, const IpAddr& lip, uint16_t lport, const IpAddr& rip,
                                uint16_t rport) {
    return std::string(protoName(proto)) + ' ' + lip.unmapped().str() + ' ' + std::to_string(lport) + ' ' +
           rip.unmapped().str() + ' ' + std::to_string(rport);
}

std::string RecordedOwners::line(uint8_t proto, const IpAddr& lip, uint16_t lport, const IpAddr& rip,
                                 uint16_t rport, const std::string& app) {
    std::string clean;
    for (char c : app) clean += (c == '\n' || c == '\r') ? ' ' : c;
    return key(proto, lip, lport, rip, rport) + ' ' + clean;
}

bool RecordedOwners::load(const std::string& path, std::string& error) {
    std::ifstream f(path);
    if (!f) {
        error = "can't open " + path;
        return false;
    }
    auto addLocal = [this](const std::string& text) {
        auto a = IpAddr::parse(text);
        if (a && std::find(local_.begin(), local_.end(), *a) == local_.end()) local_.push_back(*a);
    };
    std::string l;
    while (std::getline(f, l)) {
        if (l.rfind("# local ", 0) == 0) {
            addLocal(l.substr(8));
            continue;
        }
        if (l.empty() || l[0] == '#') continue;
        // Five fields, then the app name, which may contain spaces.
        size_t pos = 0;
        for (int i = 0; i < 5 && pos != std::string::npos; i++) pos = l.find(' ', pos + (i ? 1 : 0));
        if (pos == std::string::npos) continue;
        map_[l.substr(0, pos)] = l.substr(pos + 1);
        size_t a = l.find(' '), b = a == std::string::npos ? a : l.find(' ', a + 1);
        if (b != std::string::npos) addLocal(l.substr(a + 1, b - a - 1));
    }
    return true;
}

bool RecordedOwners::find(uint8_t proto, const IpAddr& lip, uint16_t lport, const IpAddr& rip, uint16_t rport,
                          Owner& out) {
    auto it = map_.find(key(proto, lip, lport, rip, rport));
    // A listening socket is recorded with an unspecified remote end.
    if (it == map_.end()) {
        IpAddr any;
        any.family = 4;
        it = map_.find(key(proto, lip, lport, any, 0));
    }
    if (it == map_.end()) return false;
    out.pid = 0;
    out.app = it->second;
    return true;
}

// ---- Helpers --------------------------------------------------------------

std::string appNameFromPath(const std::string& path) {
    size_t slash = path.find_last_of('/');
    std::string base = slash == std::string::npos ? path : path.substr(slash + 1);
    // Only the main executable of a bundle belongs to its app; a command-line
    // tool that happens to live inside one (Xcode's git) is itself.
    const std::string macosDir = "/Contents/MacOS/";
    if (slash == std::string::npos || slash + 1 < macosDir.size() ||
        path.compare(slash + 1 - macosDir.size(), macosDir.size(), macosDir) != 0) {
        return base;
    }
    size_t app = path.find(".app/");
    if (app == std::string::npos) return base;
    size_t start = path.rfind('/', app);
    start = start == std::string::npos ? 0 : start + 1;
    std::string name = path.substr(start, app - start);
    return name.empty() ? base : name;
}

bool parseProcNetLine(const std::string& line, uint8_t proto, bool v6, SocketEntry& out, unsigned long& inode) {
    std::istringstream in(line);
    std::string slot, local, remote, state, queues, timer, retr, uid, timeout;
    if (!(in >> slot >> local >> remote >> state >> queues >> timer >> retr >> uid >> timeout >> inode)) return false;
    if (slot.empty() || slot.back() != ':') return false;

    auto parseEndpoint = [v6](const std::string& s, IpAddr& addr, uint16_t& port) {
        size_t colon = s.find(':');
        size_t hexLen = v6 ? 32 : 8;
        if (colon != hexLen || s.size() != hexLen + 5) return false;
        // The kernel prints each 32-bit word of the address as a native
        // integer, so reading it back as one and copying the bytes restores
        // network order on any host.
        addr = IpAddr{};
        addr.family = v6 ? 6 : 4;
        for (size_t w = 0; w < hexLen / 8; w++) {
            char* end = nullptr;
            std::string word = s.substr(w * 8, 8);
            uint32_t v = uint32_t(std::strtoul(word.c_str(), &end, 16));
            if (*end) return false;
            std::memcpy(addr.bytes.data() + w * 4, &v, 4);
        }
        char* end = nullptr;
        unsigned long p = std::strtoul(s.c_str() + colon + 1, &end, 16);
        if (*end || p > 65535) return false;
        port = uint16_t(p);
        return true;
    };

    out = SocketEntry{};
    out.proto = proto;
    return parseEndpoint(local, out.local, out.localPort) && parseEndpoint(remote, out.remote, out.remotePort);
}

}  // namespace pm
