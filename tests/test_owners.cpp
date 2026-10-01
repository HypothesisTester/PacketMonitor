#include <gtest/gtest.h>

#include <cstdio>
#include <fstream>

#include "Builders.h"
#include "procs/Owners.h"

using namespace pm;
using namespace pmtest;

TEST(SocketTable, PrefersTheExactConnectionOverAListener) {
    SocketTable t;
    SocketEntry listen;
    listen.proto = kProtoTcp;
    listen.local = ip("0.0.0.0");
    listen.localPort = 8080;
    listen.pid = 10;
    listen.app = t.internApp("server");
    t.add(listen);

    SocketEntry conn = listen;
    conn.local = ip("192.168.1.2");
    conn.remote = ip("10.0.0.9");
    conn.remotePort = 51000;
    conn.pid = 11;
    conn.app = t.internApp("worker");
    t.add(conn);
    t.index();

    Owner o;
    ASSERT_TRUE(t.find(kProtoTcp, ip("192.168.1.2"), 8080, ip("10.0.0.9"), 51000, o));
    EXPECT_EQ(o.app, "worker");
    ASSERT_TRUE(t.find(kProtoTcp, ip("192.168.1.2"), 8080, ip("10.0.0.10"), 51000, o));
    EXPECT_EQ(o.app, "server");
    EXPECT_FALSE(t.find(kProtoUdp, ip("192.168.1.2"), 8080, ip("10.0.0.9"), 51000, o));
    EXPECT_FALSE(t.find(kProtoTcp, ip("192.168.1.2"), 8081, ip("10.0.0.9"), 51000, o));
}

TEST(SocketTable, MatchesIpv4MappedAddresses) {
    SocketTable t;
    SocketEntry e;
    e.proto = kProtoTcp;
    e.local = ip("::ffff:192.168.1.2");
    e.localPort = 55555;
    e.remote = ip("::ffff:140.82.121.4");
    e.remotePort = 443;
    e.app = t.internApp("git");
    t.add(e);
    t.index();
    Owner o;
    ASSERT_TRUE(t.find(kProtoTcp, ip("192.168.1.2"), 55555, ip("140.82.121.4"), 443, o));
    EXPECT_EQ(o.app, "git");
}

TEST(ProcNet, ParsesTcpAndTcp6Lines) {
    const uint16_t one = 1;
    if (*reinterpret_cast<const uint8_t*>(&one) != 1) GTEST_SKIP() << "sample lines are from a little-endian host";
    SocketEntry e;
    unsigned long inode = 0;
    ASSERT_TRUE(parseProcNetLine(
        "   0: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 23457 1 "
        "0000000000000000 100 0 0 10 0",
        kProtoTcp, false, e, inode));
    EXPECT_EQ(e.local.str(), "127.0.0.1");
    EXPECT_EQ(e.localPort, 631);
    EXPECT_EQ(e.remotePort, 0);
    EXPECT_EQ(inode, 23457ul);

    const std::string tail =
        " 01 00000000:00000000 00:00000000 00000000  1000        0 99 1 0000000000000000 20 4 30 10 -1";
    EXPECT_FALSE(parseProcNetLine("   3: 0000000000000000FFFF00001701A8C0:D431 0000000000000000FFFF0000479528C:01BB" +
                                      tail,
                                  kProtoTcp, true, e, inode))
        << "a 31-digit address must be rejected";
    ASSERT_TRUE(parseProcNetLine("   3: 0000000000000000FFFF00001701A8C0:D431 0000000000000000FFFF00000479528C:01BB" +
                                     tail,
                                 kProtoTcp, true, e, inode));
    EXPECT_EQ(e.local.unmapped().str(), "192.168.1.23");
    EXPECT_EQ(e.localPort, 0xd431);
    EXPECT_EQ(e.remote.unmapped().str(), "140.82.121.4");
    EXPECT_EQ(e.remotePort, 443);
    EXPECT_FALSE(parseProcNetLine("  sl  local_address rem_address   st tx_queue", kProtoTcp, false, e, inode));
}

TEST(AppNames, BundlesOnMacOs) {
    EXPECT_EQ(appNameFromPath("/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/"
                              "Versions/130.0/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper"),
              "Google Chrome");
    EXPECT_EQ(appNameFromPath("/Applications/Spotify.app/Contents/MacOS/Spotify"), "Spotify");
    EXPECT_EQ(appNameFromPath("/System/Applications/Mail.app/Contents/MacOS/Mail"), "Mail");
    // A command-line tool inside a bundle is itself, not the bundle.
    EXPECT_EQ(appNameFromPath("/Applications/Xcode.app/Contents/Developer/usr/bin/git"), "git");
    EXPECT_EQ(appNameFromPath("/usr/libexec/apsd"), "apsd");
    EXPECT_EQ(appNameFromPath("curl"), "curl");
}

TEST(RecordedOwners, RoundTripWithSpacesAndListeners) {
    const std::string path = ::testing::TempDir() + "owners.apps";
    {
        std::ofstream f(path);
        f << "# comment\n# local 10.0.0.9\n";
        f << RecordedOwners::line(kProtoTcp, ip("10.0.0.2"), 5000, ip("1.2.3.4"), 443, "Google Chrome") << "\n";
        f << RecordedOwners::line(kProtoTcp, ip("10.0.0.2"), 3000, ip("0.0.0.0"), 0, "node") << "\n";
        f << "garbage\n";
    }
    RecordedOwners r;
    std::string error;
    ASSERT_TRUE(r.load(path, error)) << error;
    EXPECT_EQ(r.size(), 2u);
    ASSERT_EQ(r.localAddresses().size(), 2u);
    EXPECT_EQ(r.localAddresses()[0].str(), "10.0.0.9");
    EXPECT_EQ(r.localAddresses()[1].str(), "10.0.0.2");
    Owner o;
    ASSERT_TRUE(r.find(kProtoTcp, ip("10.0.0.2"), 5000, ip("1.2.3.4"), 443, o));
    EXPECT_EQ(o.app, "Google Chrome");
    ASSERT_TRUE(r.find(kProtoTcp, ip("10.0.0.2"), 3000, ip("9.9.9.9"), 1234, o));
    EXPECT_EQ(o.app, "node");
    EXPECT_FALSE(r.find(kProtoUdp, ip("10.0.0.2"), 5000, ip("1.2.3.4"), 443, o));
    std::remove(path.c_str());
}
