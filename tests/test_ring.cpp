#include <gtest/gtest.h>

#include <cstring>
#include <random>
#include <thread>
#include <vector>

#include "core/PacketRing.h"

using namespace pm;

namespace {

std::vector<uint8_t> pattern(uint32_t id, size_t len) {
    std::vector<uint8_t> b(len);
    for (size_t i = 0; i < len; i++) b[i] = uint8_t(id * 31 + i * 7);
    return b;
}

}  // namespace

TEST(PacketRing, KeepsOrderAcrossWraps) {
    PacketRing ring(4096);
    uint32_t pushed = 0, popped = 0;
    std::mt19937 rng(1);
    for (int round = 0; round < 2000; round++) {
        // Push a few, drain some, so records wrap around the end many times.
        for (int k = 0; k < 3; k++) {
            size_t len = rng() % 700;
            auto data = pattern(pushed, len);
            if (!ring.tryPush(data.data(), uint32_t(len), uint32_t(len + 10), int64_t(pushed))) break;
            pushed++;
        }
        ring.drain(
            [&](const PacketRecordHeader& h, const uint8_t* d) {
                ASSERT_EQ(h.tsUsec, int64_t(popped));
                ASSERT_EQ(h.wireLen, h.capLen + 10);
                auto expect = pattern(popped, h.capLen);
                if (h.capLen) {
                    ASSERT_EQ(0, std::memcmp(d, expect.data(), h.capLen));
                }
                popped++;
            },
            2);
    }
    ring.drain([&](const PacketRecordHeader&, const uint8_t*) { popped++; });
    EXPECT_EQ(pushed, popped);
    EXPECT_GT(pushed, 3000u);
    EXPECT_TRUE(ring.empty());
}

TEST(PacketRing, RefusesWhenFullAndTruncatesHugePackets) {
    PacketRing ring(4096);
    std::vector<uint8_t> big(5000, 0xaa);
    ASSERT_TRUE(ring.tryPush(big.data(), uint32_t(big.size()), uint32_t(big.size()), 1));
    size_t more = 0;
    while (ring.tryPush(big.data(), 900, 900, 2)) more++;
    EXPECT_LT(more, 5u);
    ring.drain([&](const PacketRecordHeader& h, const uint8_t*) {
        if (h.tsUsec == 1) {
            EXPECT_EQ(h.capLen, ring.maxPacket());
            EXPECT_EQ(h.wireLen, 5000u);
        }
    });
    EXPECT_TRUE(ring.tryPush(big.data(), 900, 900, 3));
}

TEST(PacketRing, ProducerAndConsumerThreads) {
    PacketRing ring(1 << 16);
    const uint32_t total = 300000;
    std::thread producer([&] {
        std::mt19937 rng(2);
        for (uint32_t i = 0; i < total; i++) {
            size_t len = rng() % 1600;
            auto data = pattern(i, len);
            while (!ring.tryPush(data.data(), uint32_t(len), uint32_t(len), int64_t(i))) std::this_thread::yield();
        }
    });
    uint32_t next = 0;
    bool ok = true;
    while (next < total) {
        ring.drain([&](const PacketRecordHeader& h, const uint8_t* d) {
            if (h.tsUsec != int64_t(next)) ok = false;
            auto expect = pattern(next, h.capLen);
            if (h.capLen && std::memcmp(d, expect.data(), h.capLen) != 0) ok = false;
            next++;
        });
    }
    producer.join();
    EXPECT_TRUE(ok);
    EXPECT_EQ(next, total);
}
