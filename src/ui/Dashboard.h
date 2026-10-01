// The live dashboard: throughput, connections by app and host, protocols,
// DNS lookups and alerts, redrawn once a second from the engine's snapshot.
#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <string>

#include "analysis/Snapshot.h"
#include "ui/Terminal.h"

namespace pm {

class Dashboard {
public:
    using Source = std::function<std::shared_ptr<const Snapshot>()>;

    /** mode describes the run in the header, e.g. "live" or "replay at 8×". */
    Dashboard(Source source, std::string mode);

    /** Runs until q is pressed or stop becomes true. False if the terminal can't be used. */
    bool run(const std::atomic<bool>& stop, std::string& error);

    /** Draws one frame. Public so it can be tested without a terminal. */
    void draw(Screen& screen, const Snapshot& snap) const;
    void handleKey(int key);
    bool quitRequested() const { return quit_; }

    enum class View { Connections, Apps, Hosts };
    void setView(View v) { view_ = v; }

private:
    void drawHeader(Screen& s, const Snapshot& snap) const;
    void drawChart(Screen& s, const Snapshot& snap, int y, int height) const;
    void drawTable(Screen& s, const Snapshot& snap, int x, int y, int w, int h) const;
    void drawSide(Screen& s, const Snapshot& snap, int x, int y, int w, int h) const;
    void drawAlerts(Screen& s, const Snapshot& snap, int y, int rows) const;
    void drawFooter(Screen& s) const;
    std::string rate(double bytesPerSec) const;

    Source source_;
    std::string mode_;
    View view_ = View::Connections;
    mutable int scroll_ = 0;
    bool bits_ = false;
    bool paused_ = false;
    bool quit_ = false;
};

}  // namespace pm
