#include <gtest/gtest.h>

#include "Builders.h"
#include "analysis/Tls.h"

using namespace pm;
using namespace pmtest;

TEST(Tls, FindsTheServerName) {
    Bytes h = clientHello("GitHub.com");
    std::string host;
    ASSERT_EQ(extractSni(h.data(), h.size(), host), SniResult::Found);
    EXPECT_EQ(host, "github.com");
    EXPECT_TRUE(looksLikeTlsHandshake(h.data(), h.size()));
}

TEST(Tls, NameAfterALargeKeyShareNeedsTheSecondSegment) {
    Bytes h = clientHello("www.example.com", 1500);
    std::string host;
    EXPECT_EQ(extractSni(h.data(), 1448, host), SniResult::NeedMore);
    EXPECT_EQ(extractSni(h.data(), h.size(), host), SniResult::Found);
    EXPECT_EQ(host, "www.example.com");
}

TEST(Tls, EveryPrefixIsNeedMoreUntilTheNameArrives) {
    Bytes h = clientHello("a.example.net", 200);
    size_t firstFound = 0;
    for (size_t n = 0; n <= h.size(); n++) {
        Bytes prefix(h.begin(), h.begin() + long(n));
        std::string host;
        SniResult r = extractSni(prefix.data(), prefix.size(), host);
        if (r == SniResult::Found) {
            if (!firstFound) firstFound = n;
            EXPECT_EQ(host, "a.example.net");
        } else {
            EXPECT_EQ(r, SniResult::NeedMore) << "at " << n;
            EXPECT_EQ(firstFound, 0u) << "found, then lost, at " << n;
        }
    }
    EXPECT_GT(firstFound, 200u);
}

TEST(Tls, CompleteHelloWithoutAName) {
    Bytes h = clientHello("", 0, false);
    std::string host;
    EXPECT_EQ(extractSni(h.data(), h.size(), host), SniResult::NoSni);
}

TEST(Tls, NotTls) {
    Bytes http = text("GET / HTTP/1.1\r\n");
    std::string host;
    EXPECT_EQ(extractSni(http.data(), http.size(), host), SniResult::NotTls);
    Bytes appData = {0x17, 0x03, 0x03, 0x00, 0x10, 0x01};
    EXPECT_EQ(extractSni(appData.data(), appData.size(), host), SniResult::NotTls);
}

TEST(Tls, RejectsBadNamesAndLengths) {
    Bytes bad = clientHello("evil host\x01");
    std::string host;
    EXPECT_EQ(extractSni(bad.data(), bad.size(), host), SniResult::NoSni);

    Bytes h = clientHello("ok.example");
    h[43] = 0xff;  // session id length > 32
    EXPECT_EQ(extractSni(h.data(), h.size(), host), SniResult::NotTls);
}
