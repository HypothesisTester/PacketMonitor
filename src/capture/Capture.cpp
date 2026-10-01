#include "capture/Capture.h"

#include <pcap/pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <thread>

namespace pm {

int64_t wallClockUsec() {
    using namespace std::chrono;
    return duration_cast<microseconds>(system_clock::now().time_since_epoch()).count();
}

Capture::~Capture() {
    if (dumper_) {
        pcap_dump_flush(dumper_);
        pcap_dump_close(dumper_);
    }
    if (handle_) pcap_close(handle_);
}

std::vector<InterfaceInfo> Capture::interfaces(std::string& error) {
    std::vector<InterfaceInfo> out;
    char errbuf[PCAP_ERRBUF_SIZE] = {};
    pcap_if_t* all = nullptr;
    if (pcap_findalldevs(&all, errbuf) != 0) {
        error = errbuf;
        return out;
    }
    for (pcap_if_t* d = all; d; d = d->next) {
        InterfaceInfo i;
        i.name = d->name;
        if (d->description) i.description = d->description;
        i.loopback = d->flags & PCAP_IF_LOOPBACK;
#ifdef PCAP_IF_UP
        i.up = d->flags & PCAP_IF_UP;
        i.running = d->flags & PCAP_IF_RUNNING;
#else
        i.up = i.running = true;
#endif
#ifdef PCAP_IF_WIRELESS
        i.wireless = d->flags & PCAP_IF_WIRELESS;
#endif
        for (pcap_addr_t* a = d->addresses; a; a = a->next) {
            if (!a->addr) continue;
            if (a->addr->sa_family == AF_INET) {
                auto* sin = reinterpret_cast<const sockaddr_in*>(a->addr);
                i.addresses.push_back(IpAddr::v4(reinterpret_cast<const uint8_t*>(&sin->sin_addr)));
            } else if (a->addr->sa_family == AF_INET6) {
                auto* sin6 = reinterpret_cast<const sockaddr_in6*>(a->addr);
                i.addresses.push_back(IpAddr::v6(reinterpret_cast<const uint8_t*>(&sin6->sin6_addr)).withoutScope());
            }
        }
        out.push_back(std::move(i));
    }
    pcap_freealldevs(all);
    return out;
}

std::string Capture::defaultInterface(std::string& error) {
    auto all = interfaces(error);
    static const char* const virtualPrefixes[] = {"utun", "awdl", "llw", "bridge", "anpi", "gif", "stf", "ap",
                                                  "docker", "veth", "br-", "virbr", "vmnet", "tailscale", "any",
                                                  "nflog", "nfqueue", "bluetooth", "dbus", "usbmon"};
    auto score = [&](const InterfaceInfo& i) {
        if (i.loopback || !i.up || i.addresses.empty()) return -1;
        for (const char* p : virtualPrefixes) {
            if (i.name.rfind(p, 0) == 0) return -1;
        }
        int s = 1;
        if (i.running) s += 2;
        bool hasV4 = std::any_of(i.addresses.begin(), i.addresses.end(), [](const IpAddr& a) { return a.family == 4; });
        if (hasV4) s += 4;
        return s;
    };
    const InterfaceInfo* best = nullptr;
    int bestScore = -1;
    for (const auto& i : all) {
        int s = score(i);
        if (s > bestScore) {
            bestScore = s;
            best = &i;
        }
    }
    if (!best) {
        if (error.empty()) error = "no active network interface found (see --list)";
        return "";
    }
    return best->name;
}

std::vector<IpAddr> Capture::localAddresses() {
    std::string error;
    std::vector<IpAddr> out;
    for (const auto& i : interfaces(error)) out.insert(out.end(), i.addresses.begin(), i.addresses.end());
    return out;
}

bool Capture::openLive(const std::string& interface, int snapLen, int bufferMb, bool promiscuous,
                       std::string& error) {
    char errbuf[PCAP_ERRBUF_SIZE] = {};
    handle_ = pcap_create(interface.c_str(), errbuf);
    if (!handle_) {
        error = errbuf;
        return false;
    }
    pcap_set_snaplen(handle_, snapLen);
    pcap_set_promisc(handle_, promiscuous ? 1 : 0);
    pcap_set_timeout(handle_, 100);
    pcap_set_immediate_mode(handle_, 1);
    pcap_set_buffer_size(handle_, bufferMb * 1024 * 1024);
    int r = pcap_activate(handle_);
    if (r < 0) {
        if (r == PCAP_ERROR_PERM_DENIED) {
            error = "permission denied capturing on " + interface + ": run with sudo";
        } else if (r == PCAP_ERROR_NO_SUCH_DEVICE) {
            error = "there is no interface called " + interface + " (see --list)";
        } else {
            std::string detail = pcap_geterr(handle_);
            error = interface + ": " + (detail.empty() ? pcap_statustostr(r) : detail);
        }
        pcap_close(handle_);
        handle_ = nullptr;
        return false;
    }
    live_ = true;
    source_ = interface;
    return true;
}

bool Capture::openFile(const std::string& path, std::string& error) {
    char errbuf[PCAP_ERRBUF_SIZE] = {};
    handle_ = pcap_open_offline_with_tstamp_precision(path.c_str(), PCAP_TSTAMP_PRECISION_MICRO, errbuf);
    if (!handle_) {
        error = errbuf;
        return false;
    }
    live_ = false;
    size_t slash = path.find_last_of('/');
    source_ = slash == std::string::npos ? path : path.substr(slash + 1);
    return true;
}

bool Capture::setFilter(const std::string& bpf, std::string& error) {
    if (bpf.empty()) return true;
    bpf_program prog{};
    if (pcap_compile(handle_, &prog, bpf.c_str(), 1, PCAP_NETMASK_UNKNOWN) != 0) {
        error = "bad filter \"" + bpf + "\": " + pcap_geterr(handle_);
        return false;
    }
    int r = pcap_setfilter(handle_, &prog);
    pcap_freecode(&prog);
    if (r != 0) {
        error = std::string("can't set the filter: ") + pcap_geterr(handle_);
        return false;
    }
    return true;
}

bool Capture::writeTo(const std::string& path, std::string& error) {
    dumper_ = pcap_dump_open(handle_, path.c_str());
    if (!dumper_) {
        error = std::string("can't write ") + path + ": " + pcap_geterr(handle_);
        return false;
    }
    return true;
}

int Capture::linkType() const { return handle_ ? pcap_datalink(handle_) : -1; }

namespace {

struct DispatchContext {
    const Capture::Sink* sink;
    pcap_dumper_t* dumper;
};

void onPacket(u_char* user, const pcap_pkthdr* h, const u_char* bytes) {
    auto* ctx = reinterpret_cast<DispatchContext*>(user);
    if (ctx->dumper) pcap_dump(reinterpret_cast<u_char*>(ctx->dumper), h, bytes);
    int64_t ts = int64_t(h->ts.tv_sec) * 1000000 + h->ts.tv_usec;
    (*ctx->sink)(ts, bytes, h->caplen, h->len);
}

}  // namespace

bool Capture::run(const Sink& sink, std::string& error) {
    if (live_) {
        DispatchContext ctx{&sink, dumper_};
        auto lastStats = std::chrono::steady_clock::now();
        while (!stop_.load(std::memory_order_relaxed)) {
            int n = pcap_dispatch(handle_, -1, onPacket, reinterpret_cast<u_char*>(&ctx));
            if (n == PCAP_ERROR_BREAK) break;
            if (n < 0) {
                error = pcap_geterr(handle_);
                return false;
            }
            auto now = std::chrono::steady_clock::now();
            if (now - lastStats > std::chrono::milliseconds(250)) {
                lastStats = now;
                readStats();
            }
        }
        if (dumper_) pcap_dump_flush(dumper_);
        return true;
    }

    pcap_pkthdr* h = nullptr;
    const u_char* bytes = nullptr;
    for (;;) {
        if (stop_.load(std::memory_order_relaxed)) return true;
        int r = pcap_next_ex(handle_, &h, &bytes);
        if (r == PCAP_ERROR_BREAK) return true;  // end of file
        if (r < 0) {
            error = pcap_geterr(handle_);
            return false;
        }
        if (r == 0) continue;
        int64_t ts = int64_t(h->ts.tv_sec) * 1000000 + h->ts.tv_usec;
        if (speed_ > 0) {
            if (firstTs_.load() == 0) {
                wallStart_.store(wallClockUsec());
                firstTs_.store(ts);
            }
            int64_t due = wallStart_.load() + int64_t(double(ts - firstTs_.load()) / speed_);
            for (;;) {
                int64_t wait = due - wallClockUsec();
                if (wait <= 0 || stop_.load(std::memory_order_relaxed)) break;
                std::this_thread::sleep_for(std::chrono::microseconds(std::min<int64_t>(wait, 50000)));
            }
        }
        if (dumper_) pcap_dump(reinterpret_cast<u_char*>(dumper_), h, bytes);
        sink(ts, bytes, h->caplen, h->len);
    }
}

void Capture::stop() {
    stop_.store(true);
    if (handle_ && live_) pcap_breakloop(handle_);
}

int64_t Capture::clockUsec() const {
    if (live_) return wallClockUsec();
    if (speed_ > 0 && firstTs_.load() != 0) {
        return firstTs_.load() + int64_t(double(wallClockUsec() - wallStart_.load()) * speed_);
    }
    return 0;
}

void Capture::readStats() {
    pcap_stat st{};
    if (pcap_stats(handle_, &st) == 0) {
        received_.store(st.ps_recv, std::memory_order_relaxed);
        dropped_.store(uint64_t(st.ps_drop) + st.ps_ifdrop, std::memory_order_relaxed);
    }
}

CaptureStats Capture::stats() const {
    return CaptureStats{received_.load(std::memory_order_relaxed), dropped_.load(std::memory_order_relaxed)};
}

}  // namespace pm
