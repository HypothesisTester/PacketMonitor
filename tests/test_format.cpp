#include <gtest/gtest.h>

#include "core/Format.h"

using namespace pm;

TEST(Format, Bytes) {
    EXPECT_EQ(formatBytes(0), "0 B");
    EXPECT_EQ(formatBytes(999), "999 B");
    EXPECT_EQ(formatBytes(1000), "1.00 kB");
    EXPECT_EQ(formatBytes(12345), "12.3 kB");
    EXPECT_EQ(formatBytes(456789), "457 kB");
    EXPECT_EQ(formatBytes(3.2e9), "3.20 GB");
}

TEST(Format, Rates) {
    EXPECT_EQ(formatRate(1.53e3), "1.53 kB/s");
    EXPECT_EQ(formatRate(1e6, true), "8.00 Mb/s");
    EXPECT_EQ(formatRate(40, true), "320 b/s");
}

TEST(Format, Counts) {
    EXPECT_EQ(formatCount(0), "0");
    EXPECT_EQ(formatCount(999), "999");
    EXPECT_EQ(formatCount(1000), "1,000");
    EXPECT_EQ(formatCount(1234567), "1,234,567");
}

TEST(Format, TimesAndJson) {
    EXPECT_EQ(formatIsoUtc(1790168400LL * 1000000 + 123456), "2026-09-23T13:00:00.123Z");
    EXPECT_EQ(formatDuration(45), "45 s");
    EXPECT_EQ(formatDuration(180), "3 min");
    EXPECT_EQ(formatDuration(7500), "2 h 5 min");
    EXPECT_EQ(jsonEscape("a\"b\\c\n\x01"), "a\\\"b\\\\c\\n\\u0001");
}
