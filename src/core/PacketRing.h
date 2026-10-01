// A lock-free single-producer, single-consumer ring of variable-length packet
// records. The capture thread copies each packet in; the analysis thread reads
// it out. Neither ever blocks the other or takes a lock.
//
// Records are laid out contiguously and aligned to 8 bytes. When a record does
// not fit before the end of the buffer, the producer writes a wrap marker and
// starts again at offset 0. Positions are 64-bit counters that only grow, so
// "full" and "empty" never need a spare slot to tell apart.
#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <new>

namespace pm {

struct PacketRecordHeader {
    uint32_t size;      // bytes in the whole record, header included; kWrap marks a wrap
    uint32_t capLen;
    uint32_t wireLen;
    uint32_t reserved;
    int64_t tsUsec;
};
static_assert(sizeof(PacketRecordHeader) == 24, "unexpected header padding");

class PacketRing {
public:
    static constexpr uint32_t kWrap = 0xffffffffu;

    /** capacityBytes is rounded up to a power of two. */
    explicit PacketRing(size_t capacityBytes) {
        size_t cap = 4096;
        while (cap < capacityBytes) cap <<= 1;
        capacity_ = cap;
        mask_ = cap - 1;
        buffer_.reset(new (std::align_val_t(64)) uint8_t[cap]);
    }

    PacketRing(const PacketRing&) = delete;
    PacketRing& operator=(const PacketRing&) = delete;

    size_t capacity() const { return capacity_; }
    /** The largest packet that can ever be stored. */
    size_t maxPacket() const { return capacity_ / 4 - sizeof(PacketRecordHeader); }

    /** Producer: copies a packet in. Returns false, storing nothing, when the ring is full. */
    bool tryPush(const uint8_t* data, uint32_t capLen, uint32_t wireLen, int64_t tsUsec) {
        if (capLen > maxPacket()) capLen = static_cast<uint32_t>(maxPacket());
        const uint64_t size = align8(sizeof(PacketRecordHeader) + capLen);
        uint64_t head = head_.load(std::memory_order_relaxed);
        uint64_t off = head & mask_;
        uint64_t skip = off + size > capacity_ ? capacity_ - off : 0;

        if (head + skip + size - cachedTail_ > capacity_) {
            cachedTail_ = tail_.load(std::memory_order_acquire);
            if (head + skip + size - cachedTail_ > capacity_) return false;
        }
        if (skip) {
            uint32_t marker = kWrap;
            std::memcpy(buffer_.get() + off, &marker, sizeof marker);
            head += skip;
            off = 0;
        }
        PacketRecordHeader h{static_cast<uint32_t>(size), capLen, wireLen, 0, tsUsec};
        std::memcpy(buffer_.get() + off, &h, sizeof h);
        if (capLen) std::memcpy(buffer_.get() + off + sizeof h, data, capLen);
        head_.store(head + size, std::memory_order_release);
        return true;
    }

    /**
     * Consumer: calls fn(header, bytes) for up to maxRecords records and frees
     * them. Returns how many were handled.
     */
    template <class Fn>
    size_t drain(Fn&& fn, size_t maxRecords = SIZE_MAX) {
        uint64_t tail = tail_.load(std::memory_order_relaxed);
        uint64_t head = head_.load(std::memory_order_acquire);
        size_t n = 0;
        while (tail != head && n < maxRecords) {
            uint64_t off = tail & mask_;
            uint32_t size;
            std::memcpy(&size, buffer_.get() + off, sizeof size);
            if (size == kWrap) {
                tail += capacity_ - off;
                continue;
            }
            PacketRecordHeader h;
            std::memcpy(&h, buffer_.get() + off, sizeof h);
            fn(h, buffer_.get() + off + sizeof h);
            tail += size;
            n++;
            // Free space in batches so the producer sees it without a store per packet.
            if ((n & 63) == 0) tail_.store(tail, std::memory_order_release);
        }
        tail_.store(tail, std::memory_order_release);
        return n;
    }

    bool empty() const {
        return tail_.load(std::memory_order_acquire) == head_.load(std::memory_order_acquire);
    }

private:
    static uint64_t align8(uint64_t x) { return (x + 7) & ~uint64_t(7); }

    struct AlignedDelete {
        void operator()(uint8_t* p) const { ::operator delete[](p, std::align_val_t(64)); }
    };

    std::unique_ptr<uint8_t[], AlignedDelete> buffer_;
    size_t capacity_ = 0;
    uint64_t mask_ = 0;

    alignas(64) std::atomic<uint64_t> head_{0};  // written by the producer
    uint64_t cachedTail_ = 0;                    // producer's last view of tail_
    alignas(64) std::atomic<uint64_t> tail_{0};  // written by the consumer
};

}  // namespace pm
