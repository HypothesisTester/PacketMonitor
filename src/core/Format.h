// Human-readable numbers: byte counts, rates, counts with separators, times.
#pragma once

#include <cstdint>
#include <string>

namespace pm {

/** SI units: 999 B, 1.2 kB, 34.5 MB, 1.20 GB. */
std::string formatBytes(double bytes);
/** Bytes per second, or bits per second when bits is set: 1.2 MB/s, 9.6 Mb/s. */
std::string formatRate(double bytesPerSec, bool bits = false);
/** 1234567 -> "1,234,567". */
std::string formatCount(uint64_t n);
/** Local time of day, HH:MM:SS. */
std::string formatClock(int64_t tsUsec);
/** ISO 8601 in UTC with milliseconds: 2026-10-01T09:30:00.123Z. */
std::string formatIsoUtc(int64_t tsUsec);
/** Seconds as "45 s", "3 min", "2 h 5 min". */
std::string formatDuration(double seconds);
/** Escapes a string for use inside JSON quotes. */
std::string jsonEscape(const std::string& s);

}  // namespace pm
