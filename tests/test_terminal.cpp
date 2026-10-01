#include <gtest/gtest.h>

#include "ui/Dashboard.h"
#include "ui/Terminal.h"

using namespace pm;

TEST(Text, Widths) {
    EXPECT_EQ(textWidth("hello"), 5);
    EXPECT_EQ(textWidth("↓ 1.2 MB/s"), 10);
    EXPECT_EQ(textWidth("日本"), 4);
    EXPECT_EQ(textWidth("e\xcc\x81"), 1);  // e + combining acute
    EXPECT_EQ(fitText("www.example.com", 8), "www.exa…");
    EXPECT_EQ(textWidth(fitText("日本語のアプリ", 5)), 5);
    EXPECT_EQ(fitText("short", 10), "short");
    EXPECT_EQ(fitText("abc", 0), "");
}

TEST(Screen, ClipsAndHandlesWideCharacters) {
    Screen s;
    s.resize(6, 2);
    EXPECT_EQ(s.put(4, 0, "abcdef"), 6);
    EXPECT_EQ(s.rowText(0), "    ab");
    s.put(0, 1, "日本語");  // 6 columns exactly
    EXPECT_EQ(s.rowText(1), "日本語");
    s.put(1, 1, "x");  // overwrites the right half of 日
    EXPECT_EQ(s.rowText(1), " x本語");
    s.put(5, 0, "日");  // doesn't fit in the last column
    EXPECT_EQ(s.rowText(0), "    ab");
    s.put(0, 5, "offscreen");
    s.put(-2, 0, "xyz");
    EXPECT_EQ(s.rowText(0), "z   ab");
}

TEST(Screen, DiffSendsOnlyChanges) {
    Screen a, b;
    a.resize(20, 3);
    a.put(0, 0, "PacketMonitor", attr(kBold));
    Screen empty;
    std::string full = a.diff(empty);
    EXPECT_NE(full.find("\x1b[2J"), std::string::npos);
    EXPECT_NE(full.find("PacketMonitor"), std::string::npos);

    b = a;
    EXPECT_TRUE(b.diff(a).empty());
    b.put(0, 2, "X", fg(208));
    std::string d = b.diff(a);
    EXPECT_NE(d.find("\x1b[3;1H"), std::string::npos);
    EXPECT_NE(d.find("38;5;208"), std::string::npos);
    EXPECT_EQ(d.find("PacketMonitor"), std::string::npos);
}

TEST(Dashboard, DrawsAnEmptySnapshotAtAnySize) {
    Snapshot snap;
    snap.source = "en0";
    Dashboard dash([] { return nullptr; }, "live");
    for (auto [w, h] : {std::pair{20, 5}, {60, 16}, {80, 24}, {120, 40}, {250, 80}}) {
        Screen s;
        s.resize(w, h);
        dash.draw(s, snap);
        EXPECT_NE(s.rowText(0).find("PacketMonitor"), std::string::npos) << w << "x" << h;
    }
    Screen s;
    s.resize(100, 30);
    dash.draw(s, snap);
    std::string all;
    for (int y = 0; y < 30; y++) all += s.rowText(y) + "\n";
    EXPECT_NE(all.find("Waiting for traffic"), std::string::npos);
    EXPECT_NE(all.find("No connections yet."), std::string::npos);
}

TEST(Dashboard, KeysSwitchViewsAndQuit) {
    Dashboard dash([] { return nullptr; }, "live");
    Snapshot snap;
    snap.apps.push_back(GroupRow{"Spotify", "audio.example", "TLS", 1, 1000, 10, 5000, 50});
    Screen s;
    s.resize(100, 30);
    dash.handleKey('2');
    dash.draw(s, snap);
    std::string all;
    for (int y = 0; y < 30; y++) all += s.rowText(y) + "\n";
    EXPECT_NE(all.find("Spotify"), std::string::npos);
    EXPECT_NE(all.find("Busiest host"), std::string::npos);
    EXPECT_FALSE(dash.quitRequested());
    dash.handleKey('q');
    EXPECT_TRUE(dash.quitRequested());
}
