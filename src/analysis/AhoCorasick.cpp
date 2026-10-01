#include "analysis/AhoCorasick.h"

#include <algorithm>
#include <deque>

namespace pm {

void AhoCorasick::build(const std::vector<std::string>& patterns, bool foldCase) {
    // 1. Byte classes: each byte used in a pattern (after case folding) gets
    //    its own class; every other byte is class 0.
    uint8_t fold[256];
    for (int c = 0; c < 256; c++) fold[c] = uint8_t(foldCase && c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
    int id[256];
    std::fill(std::begin(id), std::end(id), 0);
    classes_ = 1;
    for (const auto& p : patterns) {
        for (unsigned char ch : p) {
            if (id[fold[ch]] == 0) id[fold[ch]] = int(classes_++);
        }
    }
    if (classes_ > 256) {  // every byte value is used: classes are just the bytes
        classes_ = 256;
        for (int c = 0; c < 256; c++) id[c] = c;
    }
    for (int c = 0; c < 256; c++) class_[c] = uint8_t(id[fold[c]]);
    const size_t K = classes_;

    // 2. A trie of the patterns over classes.
    std::vector<int32_t> go(K, -1);  // state * K + class -> child, or -1
    std::vector<std::vector<uint32_t>> out(1);
    patterns_ = 0;
    for (uint32_t pid = 0; pid < patterns.size(); pid++) {
        const std::string& p = patterns[pid];
        if (p.empty()) continue;
        patterns_++;
        size_t s = 0;
        for (unsigned char ch : p) {
            size_t c = class_[ch];
            if (go[s * K + c] < 0) {
                go[s * K + c] = int32_t(out.size());
                out.emplace_back();
                go.resize(go.size() + K, -1);
            }
            s = size_t(go[s * K + c]);
        }
        out[s].push_back(pid);
    }
    const size_t n = out.size();
    states_ = n;

    // 3. Failure links in breadth-first order, filling in every missing
    //    transition so the result is a DFA. A state's failure target is
    //    shallower, so it is complete (outputs included) before the state.
    std::vector<uint32_t> delta(n * K, 0), fail(n, 0);
    std::deque<uint32_t> queue;
    for (size_t c = 0; c < K; c++) {
        int32_t v = go[c];
        if (v >= 0) {
            delta[c] = uint32_t(v);
            queue.push_back(uint32_t(v));
        }
    }
    while (!queue.empty()) {
        uint32_t u = queue.front();
        queue.pop_front();
        for (uint32_t pid : out[fail[u]]) out[u].push_back(pid);
        for (size_t c = 0; c < K; c++) {
            int32_t v = go[size_t(u) * K + c];
            if (v >= 0) {
                fail[size_t(v)] = delta[size_t(fail[u]) * K + c];
                delta[size_t(u) * K + c] = uint32_t(v);
                queue.push_back(uint32_t(v));
            } else {
                delta[size_t(u) * K + c] = delta[size_t(fail[u]) * K + c];
            }
        }
    }

    // 4. Flatten the outputs.
    outStart_.assign(n + 1, 0);
    outIds_.clear();
    for (size_t s = 0; s < n; s++) {
        std::sort(out[s].begin(), out[s].end());
        out[s].erase(std::unique(out[s].begin(), out[s].end()), out[s].end());
        outStart_[s] = uint32_t(outIds_.size());
        outIds_.insert(outIds_.end(), out[s].begin(), out[s].end());
    }
    outStart_[n] = uint32_t(outIds_.size());
    auto hasOutput = [&](uint32_t s) { return outStart_[s] != outStart_[s + 1]; };

    // Entries hold the next state's row offset, so a lookup is one add.
    delta_.resize(delta.size());
    for (size_t i = 0; i < delta.size(); i++) {
        delta_[i] = uint32_t(delta[i] * K) | (hasOutput(delta[i]) ? kHasOutput : 0);
    }
    for (int c = 0; c < 256; c++) leavesStart_[c] = delta_[class_[c]] != 0;
}

}  // namespace pm
