#include "ui/Dashboard.h"

#include <algorithm>
#include <cmath>

#include "core/Format.h"

namespace pm {
namespace {

// xterm-256 colours chosen to read on both light and dark terminals.
constexpr int16_t kIn = 38;     // deep sky blue
constexpr int16_t kOut = 208;   // orange
constexpr int16_t kHigh = 160;  // red
constexpr int16_t kMedium = 172;
constexpr int16_t kLow = 33;
constexpr int16_t kBar = 67;

const Style kDimStyle = attr(kDim);
const Style kBoldStyle = attr(kBold);

const char* const kVBlocks[] = {" ", "▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"};
const char* const kHBlocks[] = {"", "▏", "▎", "▍", "▌", "▋", "▊", "▉", "█"};

int16_t severityColor(Severity s) {
    switch (s) {
    case Severity::High: return kHigh;
    case Severity::Medium: return kMedium;
    case Severity::Low: return kLow;
    }
    return kLow;
}

std::string historySpan(int seconds) {
    if (seconds < 120) return "last " + std::to_string(seconds) + " s";
    return "last " + std::to_string(seconds / 60) + " min";
}

}  // namespace

Dashboard::Dashboard(Source source, std::string mode) : source_(std::move(source)), mode_(std::move(mode)) {}

std::string Dashboard::rate(double v) const { return formatRate(v, bits_); }

bool Dashboard::run(const std::atomic<bool>& stop, std::string& error) {
    Terminal term;
    if (!term.enter(error)) return false;
    Screen screen;
    std::shared_ptr<const Snapshot> shown;
    int w = 0, h = 0;
    bool dirty = true;
    while (!stop.load() && !quit_) {
        if (!paused_) {
            auto s = source_();
            if (s != shown) {
                shown = std::move(s);
                dirty = true;
            }
        }
        int nw = 80, nh = 24;
        term.size(nw, nh);
        if (nw != w || nh != h) {
            w = nw;
            h = nh;
            screen.resize(w, h);
            term.invalidate();
            dirty = true;
        }
        if (dirty && shown) {
            screen.clear();
            draw(screen, *shown);
            term.present(screen);
            dirty = false;
        }
        int key = term.readKey(100);
        if (key != kKeyNone) {
            handleKey(key);
            dirty = true;
        }
    }
    term.leave();
    return true;
}

void Dashboard::handleKey(int key) {
    switch (key) {
    case 'q': case 'Q': case 3: quit_ = true; break;
    case kKeyTab: case kKeyRight:
        view_ = View((int(view_) + 1) % 3);
        scroll_ = 0;
        break;
    case kKeyLeft:
        view_ = View((int(view_) + 2) % 3);
        scroll_ = 0;
        break;
    case '1': view_ = View::Connections; scroll_ = 0; break;
    case '2': view_ = View::Apps; scroll_ = 0; break;
    case '3': view_ = View::Hosts; scroll_ = 0; break;
    case kKeyDown: case 'j': scroll_++; break;
    case kKeyUp: case 'k': scroll_ = std::max(0, scroll_ - 1); break;
    case kKeyPageDown: scroll_ += 10; break;
    case kKeyPageUp: scroll_ = std::max(0, scroll_ - 10); break;
    case kKeyHome: scroll_ = 0; break;
    case 'b': bits_ = !bits_; break;
    case 'p': case ' ': paused_ = !paused_; break;
    default: break;
    }
}

void Dashboard::draw(Screen& s, const Snapshot& snap) const {
    const int W = s.width(), H = s.height();
    if (W < 60 || H < 16) {
        s.put(1, 0, "PacketMonitor", kBoldStyle);
        s.put(1, 2, "Make the window at least 60 × 16 (it's " + std::to_string(W) + " × " + std::to_string(H) + ").",
              kDimStyle, W - 2);
        return;
    }
    drawHeader(s, snap);

    const int chartRows = std::clamp(H / 4, 4, 10);
    drawChart(s, snap, 3, chartRows);

    const int alertRows = H >= 36 ? 5 : H >= 28 ? 4 : H >= 22 ? 3 : 2;
    const int alertsY = H - 3 - alertRows;
    const int midY = 3 + 1 + chartRows + 1;
    const int midH = alertsY - 1 - midY;

    const bool side = W >= 110;
    const int sideW = side ? 34 : 0;
    const int tableW = W - 2 - (side ? sideW + 4 : 0);
    if (midH >= 3) {
        drawTable(s, snap, 1, midY, tableW, midH);
        if (side) drawSide(s, snap, W - 1 - sideW, midY, sideW, midH);
    }
    drawAlerts(s, snap, alertsY, alertRows);
    drawFooter(s);
}

void Dashboard::drawHeader(Screen& s, const Snapshot& snap) const {
    const int W = s.width();
    int x = s.put(1, 0, "PacketMonitor", kBoldStyle);
    x = s.put(x + 3, 0, snap.source);
    std::string mode = snap.finished ? "replay finished" : mode_;
    if (paused_) mode += " · paused";
    s.put(x, 0, "  " + mode, kDimStyle);
    if (snap.nowUsec) s.putRight(W - 1, 0, formatClock(snap.nowUsec), kDimStyle);

    x = s.put(1, 1, "↓ ", fg(kIn));
    x = s.put(x, 1, rate(snap.rateIn), kBoldStyle);
    x = s.put(x + 4, 1, "↑ ", fg(kOut));
    x = s.put(x, 1, rate(snap.rateOut), kBoldStyle);
    x = s.put(x + 4, 1, formatCount(uint64_t(snap.packetsPerSec)));
    x = s.put(x, 1, " packets/s", kDimStyle);
    x = s.put(x + 4, 1, formatCount(snap.activeFlows));
    s.put(x, 1, snap.activeFlows == 1 ? " connection" : " connections", kDimStyle);

    uint64_t dropped = snap.kernelDrops + snap.ringDrops;
    if (dropped) {
        s.putRight(W - 1, 1, formatCount(dropped) + " packets dropped", fg(kHigh));
    } else {
        int rx = s.putRight(W - 1, 1, formatBytes(double(snap.totalBytes)));
        s.putRight(rx, 1, "total ", kDimStyle);
    }
}

void Dashboard::drawChart(Screen& s, const Snapshot& snap, int y, int rows) const {
    const int W = s.width();
    const int cols = W - 2;
    const int top = (rows + 1) / 2, bottom = rows / 2;

    const auto& h = snap.history;
    const size_t n = std::min(h.size(), size_t(cols));
    const size_t from = h.size() - n;
    double peakIn = 0, peakOut = 0;
    for (size_t i = from; i < h.size(); i++) {
        peakIn = std::max(peakIn, double(h[i].bytesIn));
        peakOut = std::max(peakOut, double(h[i].bytesOut));
    }

    // Each direction has its own scale, labelled with its peak, as uploads
    // are usually far smaller than downloads.
    int x = s.put(1, y, "Throughput", kBoldStyle);
    s.put(x + 2, y, historySpan(cols), kDimStyle);
    int rx = s.putRight(W - 1, y, rate(peakOut), kDimStyle);
    rx = s.putRight(rx, y, "↑ peak ", fg(kOut));
    rx = s.putRight(rx - 3, y, rate(peakIn), kDimStyle);
    s.putRight(rx, y, "↓ peak ", fg(kIn));

    auto eighths = [](double v, double peak, int cells) {
        if (v <= 0 || peak <= 0) return 0;
        return std::max(1, int(std::lround(v / peak * cells * 8)));
    };
    for (size_t i = 0; i < n; i++) {
        const auto& sample = h[from + i];
        const int cx = 1 + cols - int(n) + int(i);
        // Inbound grows up from the middle.
        int e = eighths(double(sample.bytesIn), peakIn, top);
        for (int r = 0; r < top; r++) {
            int fill = std::clamp(e - (top - 1 - r) * 8, 0, 8);
            if (fill) s.put(cx, y + 1 + r, kVBlocks[fill], fg(kIn));
        }
        // Outbound grows down from the middle. There are no "upper n/8"
        // blocks, so draw the lower remainder in reverse video instead.
        e = eighths(double(sample.bytesOut), peakOut, bottom);
        for (int r = 0; r < bottom; r++) {
            int fill = std::clamp(e - r * 8, 0, 8);
            if (fill == 8) s.put(cx, y + 1 + top + r, "█", fg(kOut));
            else if (fill) s.put(cx, y + 1 + top + r, kVBlocks[8 - fill], fg(kOut, kReverse));
        }
    }
    if (n == 0) s.put(1, y + 1 + top - 1, "Waiting for traffic…", kDimStyle);
}

void Dashboard::drawTable(Screen& s, const Snapshot& snap, int x0, int y, int w, int h) const {
    // Tabs.
    static const char* const names[] = {"Connections", "Apps", "Hosts"};
    int x = x0;
    for (int i = 0; i < 3; i++) {
        bool on = int(view_) == i;
        x = s.put(x, y, names[i], on ? attr(kBold | kUnderline) : kDimStyle);
        x += 3;
    }

    const int rateW = 9, gap = 2;
    const int totalX = x0 + w - rateW;
    const int outX = totalX - gap - rateW;
    const int inX = outX - gap - rateW;
    const int headY = y + 1;
    const int firstRow = y + 2;
    const int visible = h - 2;

    size_t count = view_ == View::Connections ? snap.flows.size() : view_ == View::Apps ? snap.apps.size() : snap.hosts.size();
    scroll_ = std::clamp(scroll_, 0, std::max(0, int(count) - visible));
    if (count > size_t(visible)) {
        std::string range = std::to_string(scroll_ + 1) + "–" +
                            std::to_string(std::min<size_t>(count, size_t(scroll_ + visible))) + " of " +
                            std::to_string(count);
        s.putRight(x0 + w, y, range, kDimStyle);
    } else if (view_ != View::Hosts && !snap.appsProblem.empty()) {
        s.putRight(x0 + w, y, fitText(snap.appsProblem, w - (x - x0) - 2), kDimStyle);
    }

    s.putRight(inX + rateW, headY, "↓ In", kDimStyle);
    s.putRight(outX + rateW, headY, "↑ Out", kDimStyle);
    s.putRight(totalX + rateW, headY, "Total", kDimStyle);

    auto rateCell = [&](int cx, int cy, double v, Style st) {
        if (v <= 0) s.putRight(cx + rateW, cy, "–", kDimStyle);
        else s.putRight(cx + rateW, cy, rate(v), st);
    };

    if (count == 0) {
        s.put(x0, firstRow, view_ == View::Connections ? "No connections yet." : "Nothing yet.", kDimStyle);
        return;
    }

    if (view_ == View::Connections) {
        const int protoW = 5;
        const int protoX = inX - gap - protoW;
        const int appW = std::clamp(w / 5, 10, 22);
        const int hostX = x0 + appW + gap;
        const int hostW = protoX - gap - hostX;
        s.put(x0, headY, "App", kDimStyle);
        s.put(hostX, headY, "Host", kDimStyle);
        s.put(protoX, headY, "Proto", kDimStyle);
        for (int i = 0; i < visible && size_t(scroll_ + i) < count; i++) {
            const FlowRow& r = snap.flows[size_t(scroll_ + i)];
            const int ry = firstRow + i;
            const Style base = r.active ? Style{} : kDimStyle;
            if (r.app.empty()) s.put(x0, ry, "—", kDimStyle);
            else s.put(x0, ry, fitText(r.app, appW), base);
            s.put(hostX, ry, fitText(r.host, hostW), base);
            s.put(protoX, ry, r.service, kDimStyle);
            rateCell(inX, ry, r.rateIn, base);
            rateCell(outX, ry, r.rateOut, base);
            s.putRight(totalX + rateW, ry, formatBytes(double(r.totalIn + r.totalOut)), kDimStyle);
        }
        return;
    }

    const std::vector<GroupRow>& rows = view_ == View::Apps ? snap.apps : snap.hosts;
    const int countW = 5;
    const int countX = inX - gap - countW;
    const int avail = countX - gap - x0;
    const int nameW = view_ == View::Apps ? std::clamp(avail * 2 / 5, 12, 22) : std::clamp(avail * 3 / 5, 16, 44);
    const int detailX = x0 + nameW + gap;
    const int detailW = countX - gap - detailX;
    s.put(x0, headY, view_ == View::Apps ? "App" : "Host", kDimStyle);
    s.put(detailX, headY, view_ == View::Apps ? "Busiest host" : "App", kDimStyle);
    s.putRight(countX + countW, headY, "Conns", kDimStyle);
    for (int i = 0; i < visible && size_t(scroll_ + i) < count; i++) {
        const GroupRow& r = rows[size_t(scroll_ + i)];
        const int ry = firstRow + i;
        const Style base = r.flows ? Style{} : kDimStyle;
        if (r.name.empty()) s.put(x0, ry, view_ == View::Apps ? "Unknown" : "—", kDimStyle);
        else s.put(x0, ry, fitText(r.name, nameW), base);
        std::string detail = r.detail;
        if (view_ == View::Hosts && detail.empty() && r.flows) detail = "—";
        s.put(detailX, ry, fitText(detail, detailW), kDimStyle);
        if (r.flows) s.putRight(countX + countW, ry, std::to_string(r.flows), base);
        rateCell(inX, ry, r.rateIn, base);
        rateCell(outX, ry, r.rateOut, base);
        s.putRight(totalX + rateW, ry, formatBytes(double(r.totalIn + r.totalOut)), kDimStyle);
    }
}

void Dashboard::drawSide(Screen& s, const Snapshot& snap, int x0, int y, int w, int h) const {
    s.put(x0, y, "Protocols", kBoldStyle);
    s.putRight(x0 + w, y, "last minute", kDimStyle);
    uint64_t total = 0;
    for (const auto& sv : snap.services) total += sv.bytes;
    const int protoRows = std::min<int>(int(snap.services.size()), std::max(1, std::min(6, h / 2 - 1)));
    const int nameW = 6, pctW = 4;
    const int barW = w - nameW - pctW - 2;
    for (int i = 0; i < protoRows; i++) {
        const auto& sv = snap.services[size_t(i)];
        const int ry = y + 1 + i;
        const double share = total ? double(sv.bytes) / double(total) : 0;
        s.put(x0, ry, sv.name);
        int e = int(std::lround(share * barW * 8));
        if (sv.bytes && e == 0) e = 1;
        int bx = x0 + nameW;
        for (int c = 0; c < barW && e > 0; c++, e -= 8) s.put(bx + c, ry, kHBlocks[std::min(e, 8)], fg(kBar));
        std::string pct = share < 0.01 ? "<1%" : std::to_string(int(std::lround(share * 100))) + "%";
        s.putRight(x0 + w, ry, pct, kDimStyle);
    }
    if (snap.services.empty()) s.put(x0, y + 1, "Nothing yet.", kDimStyle);

    const int ly = y + 1 + std::max(protoRows, 1) + 1;
    const int lookRows = y + h - ly - 1;
    if (lookRows < 1) return;
    s.put(x0, ly, "Lookups", kBoldStyle);
    if (snap.lookups.empty()) {
        s.put(x0, ly + 1, "No DNS seen yet.", kDimStyle);
        return;
    }
    for (int i = 0; i < lookRows && size_t(i) < snap.lookups.size(); i++) {
        const Lookup& l = snap.lookups[size_t(i)];
        int lx = s.put(x0, ly + 1 + i, formatClock(l.tsUsec), kDimStyle);
        std::string name = l.failed ? l.name + " (not found)" : l.name;
        s.put(lx + 2, ly + 1 + i, fitText(name, x0 + w - lx - 2), l.failed ? kDimStyle : Style{});
    }
}

void Dashboard::drawAlerts(Screen& s, const Snapshot& snap, int y, int rows) const {
    const int W = s.width();
    int x = s.put(1, y, "Alerts", kBoldStyle);
    if (snap.alertCount) s.put(x + 2, y, formatCount(snap.alertCount), kDimStyle);
    if (snap.alerts.empty()) {
        s.put(1, y + 1, "Nothing suspicious yet. Port scans, SYN floods, traffic spikes and payload signatures appear here.",
              kDimStyle, W - 2);
        return;
    }
    for (int i = 0; i < rows && size_t(i) < snap.alerts.size(); i++) {
        const Alert& a = snap.alerts[size_t(i)];
        const int ry = y + 1 + i;
        int ax = s.put(1, ry, formatClock(a.tsUsec), kDimStyle);
        ax = s.put(ax + 2, ry, "●", fg(severityColor(a.severity)));
        ax = s.put(ax + 1, ry, fitText(a.title, W * 2 / 5), kBoldStyle);
        s.put(ax + 2, ry, fitText(a.message, W - 2 - (ax + 2)), kDimStyle);
    }
}

void Dashboard::drawFooter(Screen& s) const {
    const int y = s.height() - 1;
    int x = 1;
    auto keyHint = [&](const char* key, const char* what) {
        x = s.put(x, y, key);
        x = s.put(x + 1, y, what, kDimStyle);
        x += 3;
    };
    keyHint("q", "quit");
    keyHint("tab", "view");
    keyHint("↑↓", "scroll");
    keyHint("b", bits_ ? "bytes" : "bits");
    keyHint("p", paused_ ? "resume" : "pause");
}

}  // namespace pm
