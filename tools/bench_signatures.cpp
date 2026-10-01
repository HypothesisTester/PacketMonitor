// Measures payload matching: Aho–Corasick against searching for each
// signature in turn (what PacketMonitor 1.x did), over the same packets, and
// checks that both find the same matches.
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <random>
#include <string>
#include <string_view>
#include <vector>

#include "analysis/Signatures.h"

namespace pm {
extern const char* const kDefaultSignatures;
}

using namespace pm;

int main(int argc, char** argv) {
    const size_t megabytes = argc > 1 ? size_t(std::atoi(argv[1])) : 256;
    SignatureSet sigs;
    std::string error;
    if (!sigs.parse(kDefaultSignatures, error)) {
        std::fprintf(stderr, "%s\n", error.c_str());
        return 1;
    }

    // Packets of 1448 bytes: mostly random (encrypted traffic), some plain
    // HTTP text, and now and then a signature placed at a random offset.
    std::mt19937 rng(7);
    const size_t packetSize = 1448, count = megabytes * 1000000 / packetSize;
    std::vector<std::string> packets(count);
    const std::string http =
        "GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X "
        "14_6) AppleWebKit/605.1.15\r\nAccept: text/html,application/xhtml+xml\r\nAccept-Language: en-IE,en\r\n"
        "Connection: keep-alive\r\n\r\n";
    size_t planted = 0;
    for (auto& p : packets) {
        p.resize(packetSize);
        if (rng() % 4 == 0) {
            for (size_t i = 0; i < packetSize; i++) p[i] = http[i % http.size()];
        } else {
            for (auto& c : p) c = char(rng());
        }
        if (rng() % 1000 == 0) {
            const Signature& s = sigs.signatures()[rng() % sigs.size()];
            size_t at = rng() % (packetSize - s.content.size());
            p.replace(at, s.content.size(), s.content);
            planted++;
        }
    }

    using clock = std::chrono::steady_clock;

    // Aho–Corasick: one pass per packet.
    size_t acMatches = 0;
    auto t0 = clock::now();
    for (const auto& p : packets) {
        SignatureSet::Stream st;
        sigs.scan(st, reinterpret_cast<const uint8_t*>(p.data()), p.size(), [&](uint32_t) { acMatches++; });
    }
    double acSec = std::chrono::duration<double>(clock::now() - t0).count();

    // One search per signature per packet, lower-casing once for the nocase ones.
    std::vector<std::string> lowered;
    for (const auto& s : sigs.signatures()) {
        std::string c = s.content;
        if (s.nocase) std::transform(c.begin(), c.end(), c.begin(), [](unsigned char ch) { return std::tolower(ch); });
        lowered.push_back(c);
    }
    size_t naiveMatches = 0;
    std::string lower;
    t0 = clock::now();
    for (const auto& p : packets) {
        lower.assign(p);
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char ch) { return std::tolower(ch); });
        for (size_t i = 0; i < sigs.size(); i++) {
            std::string_view hay = sigs.signatures()[i].nocase ? std::string_view(lower) : std::string_view(p);
            for (size_t pos = hay.find(lowered[i]); pos != std::string_view::npos; pos = hay.find(lowered[i], pos + 1)) {
                naiveMatches++;
            }
        }
    }
    double naiveSec = std::chrono::duration<double>(clock::now() - t0).count();

    const double mb = double(count * packetSize) / 1e6;
    std::printf("%zu signatures, %zu packets (%.0f MB), %zu planted\n", sigs.size(), count, mb, planted);
    std::printf("  Aho-Corasick          %7.0f MB/s   %zu matches\n", mb / acSec, acMatches);
    std::printf("  one search per rule   %7.0f MB/s   %zu matches\n", mb / naiveSec, naiveMatches);
    std::printf("  speed-up              %7.1fx\n", naiveSec / acSec);
    if (acMatches != naiveMatches) {
        std::printf("MISMATCH\n");
        return 1;
    }
    return 0;
}
