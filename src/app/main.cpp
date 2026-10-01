// packetmonitor: watch a network interface or a saved capture, see which apps
// and hosts the traffic belongs to, and get alerted to scans, floods, spikes
// and suspicious payloads.
#include <getopt.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "analysis/Engine.h"
#include "capture/Capture.h"
#include "core/Format.h"
#include "core/PacketRing.h"
#include "ui/Dashboard.h"

namespace pm {
extern const char* const kDefaultSignatures;
}

using namespace pm;

namespace {

constexpr const char* kVersion = "2.0.0";
// Lock-free, so safe to set from a signal handler and read from threads.
std::atomic<int> gSignal{0};
static_assert(std::atomic<int>::is_always_lock_free, "signal flag must be lock-free");

void onSignal(int sig) { gSignal.store(sig); }

struct Options {
    std::string interface, file, filter, signatures, writeFile, logFile;
    double speed = -1;  // -1: default for the mode
    int snapLen = 65535;
    int bufferMb = 16;
    int repeat = 1;
    bool promisc = false, headless = false, json = false, bench = false, list = false;
    DetectorConfig detectors;
};

void usage(const char* argv0) {
    std::printf(
        "Usage: %s [options]\n"
        "\n"
        "Watches network traffic and shows which apps and hosts it belongs to, with\n"
        "alerts for port scans, SYN floods, traffic spikes and suspicious payloads.\n"
        "\n"
        "Source (live capture needs sudo):\n"
        "  -i, --interface NAME   capture from NAME (default: the active interface)\n"
        "  -r, --read FILE        read a pcap file instead\n"
        "      --speed X          replay speed for --read: 1 is real time, 0 is as fast\n"
        "                         as possible (default 1, or 0 with --headless)\n"
        "  -f, --filter EXPR      capture filter in tcpdump syntax, e.g. \"not port 22\"\n"
        "      --list             list interfaces and exit\n"
        "\n"
        "Output:\n"
        "      --headless         print alerts instead of showing the dashboard\n"
        "      --json             with --headless, print alerts as JSON lines\n"
        "      --log FILE         also append alerts to FILE as JSON lines\n"
        "  -w, --write FILE       save the packets to FILE, and app names to FILE.apps\n"
        "      --bench            with --read: process as fast as possible and report speed\n"
        "      --repeat N         with --bench: read the file N times\n"
        "\n"
        "Detection:\n"
        "  -s, --signatures FILE  payload signatures (default: the built-in set)\n"
        "      --scan-ports N     ports tried within 10 s that count as a scan (default 20)\n"
        "      --flood-rate N     connection attempts per second that count as a flood (default 100)\n"
        "      --spike-sigma X    standard deviations above usual that count as a spike (default 4)\n"
        "\n"
        "Capture:\n"
        "      --snaplen N        bytes to keep from each packet (default 65535)\n"
        "      --promisc          also capture traffic not addressed to this machine\n"
        "\n"
        "  -h, --help             show this help\n"
        "  -v, --version          show the version\n",
        argv0);
}

bool parseArgs(int argc, char** argv, Options& o, int& exitCode) {
    enum { kSpeed = 1000, kList, kHeadless, kJson, kLog, kBench, kRepeat, kScanPorts, kFloodRate, kSpikeSigma,
           kSnapLen, kPromisc };
    static const option longOpts[] = {
        {"interface", required_argument, nullptr, 'i'},
        {"read", required_argument, nullptr, 'r'},
        {"filter", required_argument, nullptr, 'f'},
        {"signatures", required_argument, nullptr, 's'},
        {"write", required_argument, nullptr, 'w'},
        {"speed", required_argument, nullptr, kSpeed},
        {"list", no_argument, nullptr, kList},
        {"headless", no_argument, nullptr, kHeadless},
        {"json", no_argument, nullptr, kJson},
        {"log", required_argument, nullptr, kLog},
        {"bench", no_argument, nullptr, kBench},
        {"repeat", required_argument, nullptr, kRepeat},
        {"scan-ports", required_argument, nullptr, kScanPorts},
        {"flood-rate", required_argument, nullptr, kFloodRate},
        {"spike-sigma", required_argument, nullptr, kSpikeSigma},
        {"snaplen", required_argument, nullptr, kSnapLen},
        {"promisc", no_argument, nullptr, kPromisc},
        {"help", no_argument, nullptr, 'h'},
        {"version", no_argument, nullptr, 'v'},
        {nullptr, 0, nullptr, 0},
    };
    auto number = [&](const char* name, double& out, double min) {
        char* end = nullptr;
        double v = std::strtod(optarg, &end);
        if (!end || *end || v < min) {
            std::fprintf(stderr, "%s: --%s needs a number of at least %g\n", argv[0], name, min);
            return false;
        }
        out = v;
        return true;
    };
    int c;
    double v = 0;
    while ((c = getopt_long(argc, argv, "i:r:f:s:w:hv", longOpts, nullptr)) != -1) {
        switch (c) {
        case 'i': o.interface = optarg; break;
        case 'r': o.file = optarg; break;
        case 'f': o.filter = optarg; break;
        case 's': o.signatures = optarg; break;
        case 'w': o.writeFile = optarg; break;
        case kSpeed: if (!number("speed", o.speed, 0)) return exitCode = 2, false; break;
        case kList: o.list = true; break;
        case kHeadless: o.headless = true; break;
        case kJson: o.json = true; break;
        case kLog: o.logFile = optarg; break;
        case kBench: o.bench = true; break;
        case kRepeat: if (!number("repeat", v, 1)) return exitCode = 2, false; o.repeat = int(v); break;
        case kScanPorts: if (!number("scan-ports", v, 2)) return exitCode = 2, false; o.detectors.scanPorts = int(v); break;
        case kFloodRate: if (!number("flood-rate", v, 1)) return exitCode = 2, false; o.detectors.floodSynPerSec = v; break;
        case kSpikeSigma: if (!number("spike-sigma", o.detectors.spikeSigma, 1)) return exitCode = 2, false; break;
        case kSnapLen: if (!number("snaplen", v, 64)) return exitCode = 2, false; o.snapLen = int(v); break;
        case kPromisc: o.promisc = true; break;
        case 'v': std::printf("packetmonitor %s\n", kVersion); return exitCode = 0, false;
        case 'h': usage(argv[0]); return exitCode = 0, false;
        default: std::fprintf(stderr, "Try %s --help\n", argv[0]); return exitCode = 2, false;
        }
    }
    if (optind < argc) {
        std::fprintf(stderr, "%s: unexpected argument '%s'\n", argv[0], argv[optind]);
        return exitCode = 2, false;
    }
    if (!o.file.empty() && !o.interface.empty()) {
        std::fprintf(stderr, "%s: use either --interface or --read, not both\n", argv[0]);
        return exitCode = 2, false;
    }
    if (o.repeat > 1 && !o.bench) {
        std::fprintf(stderr, "%s: --repeat only works with --bench\n", argv[0]);
        return exitCode = 2, false;
    }
    if (o.bench && o.file.empty()) {
        std::fprintf(stderr, "%s: --bench needs --read FILE\n", argv[0]);
        return exitCode = 2, false;
    }
    if (o.bench || o.json) o.headless = true;
    if (o.speed < 0) o.speed = (o.headless || o.bench) ? 0 : 1;
    if (o.bench) o.speed = 0;
    return true;
}

int listInterfaces() {
    std::string error;
    auto all = Capture::interfaces(error);
    if (all.empty()) {
        std::fprintf(stderr, "No interfaces found%s%s\n", error.empty() ? "" : ": ", error.c_str());
        return 1;
    }
    std::string def = Capture::defaultInterface(error);
    int width = 0;
    for (const auto& i : all) width = std::max(width, int(i.name.size()));
    for (const auto& i : all) {
        std::string addrs;
        for (const auto& a : i.addresses) addrs += (addrs.empty() ? "" : ", ") + a.str();
        std::printf("%s %-*s  %-8s %s\n", i.name == def ? "*" : " ", width, i.name.c_str(),
                    i.loopback ? "loopback" : i.up ? (i.running ? "up" : "no link") : "down",
                    addrs.empty() ? (i.description.empty() ? "" : i.description.c_str()) : addrs.c_str());
    }
    std::printf("\n* is used when you don't pass --interface\n");
    return 0;
}

bool fileExists(const std::string& p) {
    struct stat st;
    return stat(p.c_str(), &st) == 0;
}

void printSummary(const Engine& e, double seconds, const Options& o, uint64_t captured) {
    const double pps = double(e.packets()) / seconds;
    const double bps = double(e.bytes()) * 8 / seconds;
    char line[160];
    std::printf("PacketMonitor benchmark\n");
    std::printf("  file         %s%s\n", o.file.c_str(), o.repeat > 1 ? (" × " + std::to_string(o.repeat)).c_str() : "");
    std::printf("  packets      %s\n", formatCount(e.packets()).c_str());
    std::printf("  traffic      %s on the wire, of which %s was captured\n", formatBytes(double(e.bytes())).c_str(),
                formatBytes(double(captured)).c_str());
    std::printf("  time         %.3f s\n", seconds);
    std::snprintf(line, sizeof line, "%.2f million packets/s (%.1f Gb/s on the wire, %.1f Gb/s captured)", pps / 1e6,
                  bps / 1e9, double(captured) * 8 / seconds / 1e9);
    std::printf("  throughput   %s\n", line);
    std::printf("  alerts       %s\n", formatCount(e.alertCount()).c_str());
}

}  // namespace

int main(int argc, char** argv) {
    Options o;
    int exitCode = 0;
    if (!parseArgs(argc, argv, o, exitCode)) return exitCode;
    if (o.list) return listInterfaces();

    signal(SIGINT, onSignal);
    signal(SIGTERM, onSignal);
    signal(SIGPIPE, SIG_IGN);

    // Signatures.
    SignatureSet sigs;
    std::string error;
    if (!o.signatures.empty()) {
        if (!sigs.loadFile(o.signatures, error)) {
            std::fprintf(stderr, "packetmonitor: %s\n", error.c_str());
            return 1;
        }
    } else if (!sigs.parse(kDefaultSignatures, error)) {
        std::fprintf(stderr, "packetmonitor: built-in signatures: %s\n", error.c_str());
        return 1;
    }

    // Source.
    Capture cap;
    if (o.file.empty()) {
        if (o.interface.empty()) {
            o.interface = Capture::defaultInterface(error);
            if (o.interface.empty()) {
                std::fprintf(stderr, "packetmonitor: %s\n", error.c_str());
                return 1;
            }
        }
        if (!cap.openLive(o.interface, o.snapLen, o.bufferMb, o.promisc, error)) {
            std::fprintf(stderr, "packetmonitor: %s\n", error.c_str());
            return 1;
        }
    } else if (!cap.openFile(o.file, error)) {
        std::fprintf(stderr, "packetmonitor: %s\n", error.c_str());
        return 1;
    }
    if (!linkTypeSupported(cap.linkType())) {
        std::fprintf(stderr, "packetmonitor: %s uses link type %d, which isn't supported\n", cap.source().c_str(),
                     cap.linkType());
        return 1;
    }
    if (!cap.setFilter(o.filter, error)) {
        std::fprintf(stderr, "packetmonitor: %s\n", error.c_str());
        return 1;
    }
    cap.setReplaySpeed(o.speed);

    std::ofstream appsOut;
    if (!o.writeFile.empty()) {
        if (!cap.writeTo(o.writeFile, error)) {
            std::fprintf(stderr, "packetmonitor: %s\n", error.c_str());
            return 1;
        }
        appsOut.open(o.writeFile + ".apps");
        appsOut << "# App names for " << o.writeFile << ", written by packetmonitor\n";
        for (const auto& a : Capture::localAddresses()) appsOut << "# local " << a.str() << "\n";
    }

    // Which app owns each connection.
    std::unique_ptr<SystemOwners> systemOwners;
    RecordedOwners recordedOwners;
    OwnerLookup* owners = nullptr;
    std::string appsProblem;
    if (cap.live()) {
        systemOwners = std::make_unique<SystemOwners>();
        owners = systemOwners.get();
    } else if (fileExists(o.file + ".apps") && recordedOwners.load(o.file + ".apps", error)) {
        owners = &recordedOwners;
    } else {
        appsProblem = "app names are only known during live capture";
    }

    EngineConfig cfg;
    cfg.linkType = cap.linkType();
    if (cap.live()) cfg.localAddresses = Capture::localAddresses();
    else if (owners) cfg.localAddresses = recordedOwners.localAddresses();
    cfg.detectors = o.detectors;
    cfg.publish = !o.headless;
    cfg.source = cap.source();
    cfg.linkName = linkTypeName(cap.linkType());
    cfg.live = cap.live();
    Engine engine(cfg, &sigs, owners);
    engine.setAppsProblem(appsProblem);
    if (appsOut.is_open()) engine.setOwnerLog(&appsOut);

    std::ofstream log;
    if (!o.logFile.empty()) {
        log.open(o.logFile, std::ios::app);
        if (!log) {
            std::fprintf(stderr, "packetmonitor: can't write %s\n", o.logFile.c_str());
            return 1;
        }
    }
    std::mutex outMu;
    engine.onAlert([&](const Alert& a) {
        std::lock_guard<std::mutex> lk(outMu);
        if (log.is_open()) log << alertToJson(a) << '\n' << std::flush;
        if (!o.headless || o.bench) return;
        if (o.json) {
            std::printf("%s\n", alertToJson(a).c_str());
        } else {
            std::printf("%s  %-6s  %s: %s\n", formatClock(a.tsUsec).c_str(), severityName(a.severity),
                        a.title.c_str(), a.message.c_str());
        }
        std::fflush(stdout);
    });

    // Capture thread -> ring -> engine thread.
    PacketRing ring(64u << 20);
    std::atomic<bool> stop{false}, captureDone{false}, engineDone{false};
    std::atomic<uint64_t> ringDrops{0}, capturedBytes{0};
    const bool lossless = !cap.live();  // files wait for room; live capture never blocks the kernel
    std::string captureError;

    auto push = [&](int64_t ts, const uint8_t* data, uint32_t capLen, uint32_t wireLen) {
        capturedBytes.fetch_add(capLen, std::memory_order_relaxed);
        while (!ring.tryPush(data, capLen, wireLen, ts)) {
            if (!lossless) {
                ringDrops.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            if (stop.load(std::memory_order_relaxed)) return;
            std::this_thread::yield();
        }
    };

    const auto started = std::chrono::steady_clock::now();
    std::thread captureThread([&] {
        int64_t first = 0, last = 0;
        auto firstPass = [&](int64_t ts, const uint8_t* d, uint32_t c, uint32_t w) {
            if (!first) first = ts;
            last = ts;
            push(ts, d, c, w);
        };
        if (!cap.run(firstPass, captureError)) stop = true;
        // A benchmark can read the file again, shifted in time so it continues.
        for (int i = 1; i < o.repeat && !stop; i++) {
            const int64_t offset = int64_t(i) * (last - first + 1000000);
            Capture again;
            std::string e;
            if (!again.openFile(o.file, e) || !again.setFilter(o.filter, e)) break;
            again.setReplaySpeed(0);
            again.run(
                [&](int64_t ts, const uint8_t* d, uint32_t c, uint32_t w) {
                    if (stop.load(std::memory_order_relaxed)) again.stop();
                    push(ts + offset, d, c, w);
                },
                e);
        }
        captureDone = true;
    });

    // How far behind the clock to close each second, so packets still on
    // their way through the ring land in the right one.
    const int64_t lagUsec = int64_t(300000 * std::max(1.0, o.speed));
    std::thread engineThread([&] {
        auto lastStats = std::chrono::steady_clock::now();
        for (;;) {
            size_t n = ring.drain([&](const PacketRecordHeader& h, const uint8_t* d) { engine.process(h, d); }, 4096);
            auto now = std::chrono::steady_clock::now();
            if (!o.bench && now - lastStats > std::chrono::milliseconds(250)) {
                lastStats = now;
                engine.setCaptureDrops(cap.stats().dropped, ringDrops.load());
                if (systemOwners) engine.setAppsProblem(systemOwners->problem());
            }
            if (n == 0) {
                if (captureDone && ring.empty()) break;
                if (stop) break;
                // Nothing waiting: let time pass, so a quiet network still
                // ticks. Only now, so seconds never close ahead of a backlog.
                int64_t clock = o.bench ? 0 : cap.clockUsec();
                if (clock) engine.advanceTo(clock - lagUsec);
                if (o.bench) std::this_thread::yield();
                else std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
        }
        engine.finish();
        engineDone = true;
    });

    // Turns a signal into an orderly stop.
    std::thread watcher([&] {
        while (!engineDone) {
            if (gSignal.load()) stop = true;
            if (stop) cap.stop();
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    });

    int result = 0;
    if (!o.headless) {
        std::string mode = cap.live() ? "live"
                           : o.speed == 1 ? "replay"
                           : o.speed == 0 ? "replay, full speed"
                                          : "replay at " + std::to_string(int(o.speed)) + "×";
        Dashboard dash([&] { return engine.snapshot(); }, mode);
        std::atomic<bool> uiStop{false};
        std::thread relay([&] {
            while (!uiStop) {
                if (gSignal.load()) uiStop = true;
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        });
        std::string uiError;
        if (!dash.run(uiStop, uiError)) {
            std::fprintf(stderr, "packetmonitor: %s\n", uiError.c_str());
            result = 1;
        }
        uiStop = true;
        relay.join();
        stop = true;
        cap.stop();
    }

    captureThread.join();
    engineThread.join();
    stop = true;
    watcher.join();

    if (!captureError.empty()) {
        std::fprintf(stderr, "packetmonitor: %s\n", captureError.c_str());
        result = 1;
    }
    const double seconds =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
    if (o.bench) {
        printSummary(engine, seconds, o, capturedBytes.load());
    } else if (o.headless) {
        std::fprintf(stderr, "%s packets, %s, %s alerts\n", formatCount(engine.packets()).c_str(),
                     formatBytes(double(engine.bytes())).c_str(), formatCount(engine.alertCount()).c_str());
    }
    return result;
}
