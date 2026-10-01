// Aho–Corasick multi-pattern matching. All patterns are found in one pass over
// the data, costing one table lookup per byte however many patterns there are.
// The automaton is a full DFA, and the scan state is a single integer, so
// matching can continue across the packets of a stream.
//
// Scanning a DFA is bound by memory latency, since each byte's lookup depends
// on the one before. So the table is kept small and the lookup short: bytes
// that appear in no pattern share one column (a byte class), and each entry
// holds the next state's row offset rather than its number, which saves a
// multiplication on every byte. At the start state, bytes that can't begin a
// pattern are skipped in a tight loop.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pm {

class AhoCorasick {
public:
    static constexpr uint32_t kStart = 0;

    /** foldCase matches ASCII letters case-insensitively. Empty patterns are ignored. */
    void build(const std::vector<std::string>& patterns, bool foldCase);

    bool empty() const { return patterns_ == 0; }
    size_t stateCount() const { return states_; }
    size_t classCount() const { return classes_; }
    size_t tableBytes() const { return delta_.size() * sizeof(uint32_t); }

    /**
     * Feeds bytes to the automaton from state and returns the new state.
     * onMatch(patternIndex, offsetOfLastByte) is called for every match,
     * including overlapping ones.
     */
    template <class OnMatch>
    uint32_t scan(uint32_t state, const uint8_t* data, size_t len, OnMatch&& onMatch) const {
        if (patterns_ == 0) return state;
        const uint32_t* delta = delta_.data();
        const uint8_t* cls = class_;
        const uint8_t* leaves = leavesStart_;
        uint32_t s = state;
        for (size_t i = 0; i < len; i++) {
            // At the start state, skip ahead to a byte that can begin a
            // pattern. That loop has no dependency between iterations, so it
            // runs several times faster than the automaton, and most bytes of
            // encrypted traffic take it.
            if (s == kStart) {
                while (i < len && !leaves[data[i]]) i++;
                if (i == len) break;
            }
            uint32_t next = delta[s + cls[data[i]]];
            s = next & kOffsetMask;
            if (next & kHasOutput) {
                const uint32_t id = s / uint32_t(classes_);
                for (uint32_t k = outStart_[id]; k < outStart_[id + 1]; k++) onMatch(outIds_[k], i);
            }
        }
        return s;
    }

private:
    static constexpr uint32_t kHasOutput = 0x80000000u;
    static constexpr uint32_t kOffsetMask = 0x7fffffffu;

    std::vector<uint32_t> delta_;     // row offset + class -> next row offset, high bit if it has output
    std::vector<uint32_t> outStart_;  // outputs of state s are outIds_[outStart_[s] .. outStart_[s+1])
    std::vector<uint32_t> outIds_;
    uint8_t class_[256] = {};
    uint8_t leavesStart_[256] = {};  // bytes that move the start state elsewhere
    size_t classes_ = 1, states_ = 0, patterns_ = 0;
};

}  // namespace pm
