#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "analysis/Signatures.h"

namespace pm {
extern const char* const kDefaultSignatures;
}

using namespace pm;

namespace {

std::vector<uint32_t> matchesIn(const SignatureSet& set, const std::vector<std::string>& chunks) {
    std::vector<uint32_t> found;
    SignatureSet::Stream st;
    for (const auto& c : chunks) {
        set.scan(st, reinterpret_cast<const uint8_t*>(c.data()), c.size(), [&](uint32_t id) { found.push_back(id); });
    }
    return found;
}

}  // namespace

TEST(Signatures, ParsesTheFormat) {
    SignatureSet set;
    std::string error;
    ASSERT_TRUE(set.parse(R"(# comment

high   crlf-pass   "|0d 0a|PASS "               : Password in the clear
medium quoted      "say \"hi\" \\ |7c| \|"  nocase
low    tabs	"a	b"
)",
                          error))
        << error;
    ASSERT_EQ(set.size(), 3u);
    const auto& s = set.signatures();
    EXPECT_EQ(s[0].name, "crlf-pass");
    EXPECT_EQ(s[0].content, "\r\nPASS ");
    EXPECT_EQ(s[0].severity, Severity::High);
    EXPECT_EQ(s[0].message, "Password in the clear");
    EXPECT_FALSE(s[0].nocase);
    EXPECT_EQ(s[1].content, "say \"hi\" \\ | |");
    EXPECT_TRUE(s[1].nocase);
    EXPECT_EQ(s[1].message, "Matched quoted");
    EXPECT_EQ(s[2].content, "a\tb");
    EXPECT_EQ(set.longestContent(), s[1].content.size());
}

TEST(Signatures, AcceptsTheOldOneLinePerPatternFormat) {
    SignatureSet set;
    std::string error;
    ASSERT_TRUE(set.parse("SELECT * FROM\n<script>\n", error));
    ASSERT_EQ(set.size(), 2u);
    EXPECT_EQ(set.signatures()[1].content, "<script>");
    EXPECT_EQ(matchesIn(set, {"GET /?q=<script>x"}).size(), 1u);
}

TEST(Signatures, ReportsErrorsWithLineNumbers) {
    struct Case {
        const char* text;
        const char* expect;
    } cases[] = {
        {"# ok\nsevere x \"a\"", "line 2: severity must be"},
        {"high x \"abc", "line 1: the content has no closing quote"},
        {"high x \"|0g|\"", "not a hex digit"},
        {"high x \"|0|\"", "odd number of hex digits"},
        {"high x \"|41\"", "without its closing"},
        {"high x \"a\" loud", "unknown option 'loud'"},
        {"high x \"\\n\"", "unknown escape"},
        {"high \"a\"", "expected <severity> <name>"},
        {"high x \"\"", "empty content"},
    };
    for (const auto& c : cases) {
        SignatureSet set;
        std::string error;
        EXPECT_FALSE(set.parse(c.text, error)) << c.text;
        EXPECT_NE(error.find(c.expect), std::string::npos) << c.text << " gave: " << error;
    }
}

TEST(Signatures, BuiltInSetParsesAndFindsEicarSplitAcrossPackets) {
    SignatureSet set;
    std::string error;
    ASSERT_TRUE(set.parse(kDefaultSignatures, error)) << error;
    EXPECT_GE(set.size(), 25u);
    const std::string eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    auto found = matchesIn(set, {"HTTP/1.1 200 OK\r\n\r\n" + eicar.substr(0, 20), eicar.substr(20)});
    ASSERT_EQ(found.size(), 1u);
    EXPECT_EQ(set.signatures()[found[0]].name, "eicar-test-file");

    // Mixed case for nocase rules, and exact case for the rest.
    EXPECT_EQ(matchesIn(set, {"GET /x?id=1 UnIoN SeLeCt password FROM users"}).size(), 1u);
    EXPECT_EQ(matchesIn(set, {"x5o!p%@ap[4\\pzx54(p^)7cc)7}$eicar-standard-antivirus-test-file!"}).size(), 0u);
    EXPECT_TRUE(matchesIn(set, {"GET / HTTP/1.1\r\nHost: a\r\nUser-Agent: Mozilla/5.0\r\n\r\n"}).empty());
}
