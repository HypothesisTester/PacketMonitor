#include "core/Format.h"

#include <cmath>
#include <cstdio>
#include <ctime>

namespace pm {
namespace {

std::string scaled(double v, const char* const* units, int count) {
    int u = 0;
    while (u + 1 < count && std::fabs(v) >= 999.5) {
        v /= 1000.0;
        u++;
    }
    char buf[32];
    if (u == 0) std::snprintf(buf, sizeof buf, "%.0f %s", v, units[0]);
    else if (std::fabs(v) < 9.995) std::snprintf(buf, sizeof buf, "%.2f %s", v, units[u]);
    else if (std::fabs(v) < 99.95) std::snprintf(buf, sizeof buf, "%.1f %s", v, units[u]);
    else std::snprintf(buf, sizeof buf, "%.0f %s", v, units[u]);
    return buf;
}

}  // namespace

std::string formatBytes(double bytes) {
    static const char* const units[] = {"B", "kB", "MB", "GB", "TB"};
    return scaled(bytes, units, 5);
}

std::string formatRate(double bytesPerSec, bool bits) {
    static const char* const byteUnits[] = {"B/s", "kB/s", "MB/s", "GB/s"};
    static const char* const bitUnits[] = {"b/s", "kb/s", "Mb/s", "Gb/s"};
    return bits ? scaled(bytesPerSec * 8, bitUnits, 4) : scaled(bytesPerSec, byteUnits, 4);
}

std::string formatCount(uint64_t n) {
    std::string digits = std::to_string(n), out;
    int lead = int(digits.size()) % 3;
    for (size_t i = 0; i < digits.size(); i++) {
        if (i != 0 && (int(i) - lead) % 3 == 0) out += ',';
        out += digits[i];
    }
    return out;
}

std::string formatClock(int64_t tsUsec) {
    std::time_t t = static_cast<std::time_t>(tsUsec / 1000000);
    std::tm tm{};
    localtime_r(&t, &tm);
    char buf[16];
    std::strftime(buf, sizeof buf, "%H:%M:%S", &tm);
    return buf;
}

std::string formatIsoUtc(int64_t tsUsec) {
    std::time_t t = static_cast<std::time_t>(tsUsec / 1000000);
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[40];
    size_t n = std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%S", &tm);
    std::snprintf(buf + n, sizeof buf - n, ".%03dZ", int((tsUsec / 1000) % 1000));
    return buf;
}

std::string formatDuration(double s) {
    char buf[32];
    if (s < 60) std::snprintf(buf, sizeof buf, "%.0f s", s);
    else if (s < 3600) std::snprintf(buf, sizeof buf, "%.0f min", s / 60);
    else std::snprintf(buf, sizeof buf, "%d h %d min", int(s / 3600), int(std::fmod(s, 3600) / 60));
    return buf;
}

std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 0x20) {
                char buf[8];
                std::snprintf(buf, sizeof buf, "\\u%04x", c);
                out += buf;
            } else {
                out += char(c);
            }
        }
    }
    return out;
}

}  // namespace pm
