#include <gtest/gtest.h>

#include <map>
#include <random>
#include <set>
#include <string>
#include <vector>

#include "analysis/AhoCorasick.h"

using namespace pm;

namespace {

using Matches = std::multiset<std::pair<uint32_t, size_t>>;  // (pattern, end offset)

Matches scanAll(const AhoCorasick& ac, const std::string& s) {
    Matches m;
    ac.scan(AhoCorasick::kStart, reinterpret_cast<const uint8_t*>(s.data()), s.size(),
            [&](uint32_t id, size_t end) { m.insert({id, end}); });
    return m;
}

Matches naive(const std::vector<std::string>& pats, const std::string& s, bool fold) {
    auto lower = [&](std::string x) {
        if (fold) {
            for (auto& c : x) c = char(std::tolower(static_cast<unsigned char>(c)));
        }
        return x;
    };
    std::string hay = lower(s);
    Matches m;
    for (uint32_t i = 0; i < pats.size(); i++) {
        std::string p = lower(pats[i]);
        if (p.empty()) continue;
        for (size_t pos = hay.find(p); pos != std::string::npos; pos = hay.find(p, pos + 1)) {
            m.insert({i, pos + p.size() - 1});
        }
    }
    return m;
}

}  // namespace

TEST(AhoCorasick, TextbookExample) {
    AhoCorasick ac;
    std::vector<std::string> pats = {"he", "she", "his", "hers"};
    ac.build(pats, false);
    Matches m = scanAll(ac, "ushers");
    Matches expect = {{1, 3}, {0, 3}, {3, 5}};  // she and he end at 3, hers at 5
    EXPECT_EQ(m, expect);
}

TEST(AhoCorasick, CaseFolding) {
    AhoCorasick ac;
    ac.build({"Union Select"}, true);
    EXPECT_EQ(scanAll(ac, "id=1 UNION SELECT pw").size(), 1u);
    EXPECT_EQ(scanAll(ac, "union select").size(), 1u);
    AhoCorasick exact;
    exact.build({"Union Select"}, false);
    EXPECT_EQ(scanAll(exact, "UNION SELECT").size(), 0u);
}

TEST(AhoCorasick, BinaryPatternsAndEmptyOnes) {
    AhoCorasick ac;
    std::string zero("\x00\xff\x00", 3);
    ac.build({"", zero}, false);
    EXPECT_FALSE(ac.empty());
    std::string data = std::string("ab") + zero + "cd" + zero;
    Matches m = scanAll(ac, data);
    ASSERT_EQ(m.size(), 2u);
    EXPECT_EQ(m.begin()->first, 1u);

    AhoCorasick none;
    none.build({""}, false);
    EXPECT_TRUE(none.empty());
    EXPECT_TRUE(scanAll(none, "anything").empty());
}

TEST(AhoCorasick, StreamingMatchesAcrossChunkBoundaries) {
    AhoCorasick ac;
    std::vector<std::string> pats = {"${jndi:", "EICAR", "abcab", "bca"};
    ac.build(pats, false);
    const std::string s = "xx${jn" "di:ldap}EIC" "ARabcabcabx";
    Matches whole = scanAll(ac, s);
    ASSERT_FALSE(whole.empty());
    for (size_t cut = 0; cut <= s.size(); cut++) {
        Matches m;
        uint32_t st = AhoCorasick::kStart;
        st = ac.scan(st, reinterpret_cast<const uint8_t*>(s.data()), cut,
                     [&](uint32_t id, size_t end) { m.insert({id, end}); });
        ac.scan(st, reinterpret_cast<const uint8_t*>(s.data()) + cut, s.size() - cut,
                [&](uint32_t id, size_t end) { m.insert({id, end + cut}); });
        EXPECT_EQ(m, whole) << "cut at " << cut;
    }
}

TEST(AhoCorasick, AgreesWithNaiveSearchOnRandomInput) {
    std::mt19937 rng(99);
    for (int trial = 0; trial < 200; trial++) {
        const bool fold = trial % 2;
        const char* alphabet = fold ? "aAbB" : "ab";
        const int letters = fold ? 4 : 2;
        std::vector<std::string> pats(1 + rng() % 12);
        for (auto& p : pats) {
            p.resize(rng() % 6);
            for (auto& c : p) c = alphabet[rng() % letters];
        }
        std::string text(rng() % 300, ' ');
        for (auto& c : text) c = alphabet[rng() % letters];
        AhoCorasick ac;
        ac.build(pats, fold);
        ASSERT_EQ(scanAll(ac, text), naive(pats, text, fold)) << "trial " << trial;
    }
}
