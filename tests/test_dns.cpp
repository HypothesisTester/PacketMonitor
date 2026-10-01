#include <gtest/gtest.h>

#include "Builders.h"
#include "analysis/Dns.h"

using namespace pm;
using namespace pmtest;

TEST(Dns, ResponseWithCnameAndCompression) {
    Bytes r = dnsResponse("www.YouTube.com", {ip("142.250.187.238"), ip("142.250.187.206")}, "youtube-ui.l.google.com");
    DnsMessage m;
    ASSERT_TRUE(parseDns(r.data(), r.size(), m));
    EXPECT_TRUE(m.response);
    EXPECT_EQ(m.id, 0xbeef);
    EXPECT_EQ(m.question, "www.youtube.com");  // lower-cased
    EXPECT_EQ(m.qtype, kDnsA);
    ASSERT_EQ(m.answers.size(), 3u);
    EXPECT_EQ(m.answers[0].type, kDnsCname);
    EXPECT_EQ(m.answers[0].target, "youtube-ui.l.google.com");
    EXPECT_EQ(m.answers[1].name, "youtube-ui.l.google.com");  // via a pointer into the CNAME's data
    EXPECT_EQ(m.answers[1].addr.str(), "142.250.187.238");
    EXPECT_EQ(m.answers[2].addr.str(), "142.250.187.206");
    EXPECT_EQ(m.answers[1].ttl, 60u);
}

TEST(Dns, NxDomain) {
    Bytes r = dnsResponse("nope.example", {}, "", 3);
    DnsMessage m;
    ASSERT_TRUE(parseDns(r.data(), r.size(), m));
    EXPECT_EQ(m.rcode, 3);
    EXPECT_TRUE(m.answers.empty());
}

TEST(Dns, OverTcp) {
    Bytes msg = dnsResponse("github.com", {ip("140.82.121.4")});
    Bytes framed;
    put16(framed, uint16_t(msg.size()));
    append(framed, msg);
    DnsMessage m;
    ASSERT_TRUE(parseDnsTcp(framed.data(), framed.size(), m));
    EXPECT_EQ(m.answers.at(0).addr.str(), "140.82.121.4");
    EXPECT_FALSE(parseDnsTcp(framed.data(), framed.size() - 1, m));  // not all here yet
}

TEST(Dns, RejectsPointerLoops) {
    Bytes r;
    put16(r, 1);
    put16(r, 0x8180);
    put16(r, 1);
    put16(r, 0);
    put16(r, 0);
    put16(r, 0);
    put16(r, 0xc00c);  // the question's name points at itself
    put16(r, 1);
    put16(r, 1);
    DnsMessage m;
    EXPECT_FALSE(parseDns(r.data(), r.size(), m));

    Bytes far = r;
    far[12] = 0xc0;
    far[13] = 0xff;  // past the end
    EXPECT_FALSE(parseDns(far.data(), far.size(), m));
}

TEST(Dns, RejectsBadLabelsAndLongNames) {
    Bytes r;
    put16(r, 1);
    put16(r, 0x8180);
    put16(r, 1);
    put16(r, 0);
    put16(r, 0);
    put16(r, 0);
    Bytes reserved = r;
    reserved.push_back(0x40);  // label type 01, reserved
    reserved.push_back(0);
    DnsMessage m;
    EXPECT_FALSE(parseDns(reserved.data(), reserved.size(), m));

    Bytes longName = r;
    for (int i = 0; i < 5; i++) {
        longName.push_back(60);
        longName.insert(longName.end(), 60, 'a');
    }
    longName.push_back(0);
    put16(longName, 1);
    put16(longName, 1);
    EXPECT_FALSE(parseDns(longName.data(), longName.size(), m));
}

TEST(Dns, KeepsAnswersBeforeATruncation) {
    Bytes r = dnsResponse("a.example", {ip("1.1.1.1"), ip("2.2.2.2")});
    DnsMessage m;
    ASSERT_TRUE(parseDns(r.data(), r.size() - 2, m));
    ASSERT_EQ(m.answers.size(), 1u);
    EXPECT_EQ(m.answers[0].addr.str(), "1.1.1.1");
}

TEST(Dns, QueriesAreNotResponses) {
    Bytes q;
    put16(q, 7);
    put16(q, 0x0100);
    put16(q, 1);
    put16(q, 0);
    put16(q, 0);
    put16(q, 0);
    dnsName(q, "example.org");
    put16(q, 28);
    put16(q, 1);
    DnsMessage m;
    ASSERT_TRUE(parseDns(q.data(), q.size(), m));
    EXPECT_FALSE(m.response);
    EXPECT_EQ(m.question, "example.org");
    EXPECT_STREQ(dnsTypeName(m.qtype), "AAAA");
}
