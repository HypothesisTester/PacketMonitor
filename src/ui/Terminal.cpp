#include "ui/Terminal.h"

#include <poll.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>

namespace pm {
namespace {

/** Decodes one code point at s[i], advancing i. Invalid bytes become U+FFFD. */
uint32_t nextCodepoint(std::string_view s, size_t& i) {
    unsigned char c = static_cast<unsigned char>(s[i]);
    int len = c < 0x80 ? 1 : (c >> 5) == 6 ? 2 : (c >> 4) == 14 ? 3 : (c >> 3) == 30 ? 4 : 0;
    if (len == 0 || i + size_t(len) > s.size()) {
        i++;
        return 0xfffd;
    }
    uint32_t cp = len == 1 ? c : len == 2 ? c & 0x1f : len == 3 ? c & 0x0f : c & 0x07;
    for (int k = 1; k < len; k++) {
        unsigned char cc = static_cast<unsigned char>(s[i + size_t(k)]);
        if ((cc & 0xc0) != 0x80) {
            i++;
            return 0xfffd;
        }
        cp = cp << 6 | (cc & 0x3f);
    }
    i += size_t(len);
    return cp;
}

void encode(uint32_t cp, char* out) {
    if (cp < 0x80) {
        out[0] = char(cp);
        out[1] = 0;
    } else if (cp < 0x800) {
        out[0] = char(0xc0 | cp >> 6);
        out[1] = char(0x80 | (cp & 0x3f));
        out[2] = 0;
    } else if (cp < 0x10000) {
        out[0] = char(0xe0 | cp >> 12);
        out[1] = char(0x80 | ((cp >> 6) & 0x3f));
        out[2] = char(0x80 | (cp & 0x3f));
        out[3] = 0;
    } else {
        out[0] = char(0xf0 | cp >> 18);
        out[1] = char(0x80 | ((cp >> 12) & 0x3f));
        out[2] = char(0x80 | ((cp >> 6) & 0x3f));
        out[3] = char(0x80 | (cp & 0x3f));
        out[4] = 0;
    }
}

void appendStyle(std::string& out, const Style& s) {
    out += "\x1b[0";
    if (s.attr & kBold) out += ";1";
    if (s.attr & kDim) out += ";2";
    if (s.attr & kUnderline) out += ";4";
    if (s.attr & kReverse) out += ";7";
    if (s.fg >= 0) out += ";38;5;" + std::to_string(s.fg);
    if (s.bg >= 0) out += ";48;5;" + std::to_string(s.bg);
    out += 'm';
}

}  // namespace

int codepointWidth(uint32_t cp) {
    if (cp == 0) return 0;
    if ((cp >= 0x0300 && cp <= 0x036f) || (cp >= 0x1ab0 && cp <= 0x1aff) || (cp >= 0x1dc0 && cp <= 0x1dff) ||
        (cp >= 0x20d0 && cp <= 0x20ff) || (cp >= 0xfe20 && cp <= 0xfe2f) || (cp >= 0x200b && cp <= 0x200f) ||
        (cp >= 0xfe00 && cp <= 0xfe0f)) {
        return 0;
    }
    if ((cp >= 0x1100 && cp <= 0x115f) || (cp >= 0x2e80 && cp <= 0xa4cf) || (cp >= 0xac00 && cp <= 0xd7a3) ||
        (cp >= 0xf900 && cp <= 0xfaff) || (cp >= 0xfe30 && cp <= 0xfe4f) || (cp >= 0xff00 && cp <= 0xff60) ||
        (cp >= 0xffe0 && cp <= 0xffe6) || (cp >= 0x1f300 && cp <= 0x1faff) || (cp >= 0x20000 && cp <= 0x3fffd)) {
        return 2;
    }
    return 1;
}

int textWidth(std::string_view s) {
    int w = 0;
    for (size_t i = 0; i < s.size();) w += codepointWidth(nextCodepoint(s, i));
    return w;
}

std::string fitText(std::string_view s, int width) {
    if (width <= 0) return "";
    if (textWidth(s) <= width) return std::string(s);
    std::string out;
    int w = 0;
    for (size_t i = 0; i < s.size();) {
        size_t start = i;
        int cw = codepointWidth(nextCodepoint(s, i));
        if (w + cw > width - 1) break;
        out.append(s.substr(start, i - start));
        w += cw;
    }
    return out + "…";
}

// ---- Screen ---------------------------------------------------------------

void Screen::resize(int w, int h) {
    w_ = w > 0 ? w : 0;
    h_ = h > 0 ? h : 0;
    cells_.assign(size_t(w_) * size_t(h_), Cell{});
}

void Screen::clear() { std::fill(cells_.begin(), cells_.end(), Cell{}); }

int Screen::put(int x, int y, std::string_view s, Style style, int maxWidth) {
    if (y < 0 || y >= h_) return x;
    int limit = maxWidth < 0 ? w_ : std::min(w_, x + maxWidth);
    for (size_t i = 0; i < s.size();) {
        uint32_t cp = nextCodepoint(s, i);
        if (cp < 0x20 || cp == 0x7f) cp = '?';
        int cw = codepointWidth(cp);
        if (cw == 0) continue;
        if (x + cw > limit) break;
        if (x < 0) {
            x += cw;
            continue;
        }
        Cell* c = at(x, y);
        if (c->continuation && x > 0) *at(x - 1, y) = Cell{};
        if (x + 1 < w_ && at(x + 1, y)->continuation) *at(x + 1, y) = Cell{};
        encode(cp, c->glyph);
        c->style = style;
        c->continuation = false;
        if (cw == 2) {
            Cell* r = at(x + 1, y);
            if (x + 2 < w_ && at(x + 2, y)->continuation) *at(x + 2, y) = Cell{};
            *r = Cell{};
            r->glyph[0] = 0;
            r->style = style;
            r->continuation = true;
        }
        x += cw;
    }
    return x;
}

int Screen::putRight(int xEnd, int y, std::string_view s, Style style) {
    int w = textWidth(s);
    put(xEnd - w, y, s, style);
    return xEnd - w;
}

void Screen::fill(int x, int y, int w, std::string_view glyph, Style s) {
    for (int i = 0; i < w; i++) put(x + i, y, glyph, s, 1);
}

std::string Screen::rowText(int y) const {
    std::string out;
    for (int x = 0; x < w_; x++) {
        const Cell* c = at(x, y);
        if (!c->continuation) out += c->glyph;
    }
    return out;
}

Style Screen::styleAt(int x, int y) const { return at(x, y)->style; }

std::string Screen::diff(const Screen& prev) const {
    std::string out;
    const bool full = prev.w_ != w_ || prev.h_ != h_;
    if (full) out += "\x1b[0m\x1b[H\x1b[2J";
    Style cur;
    bool styleKnown = false;
    int cx = -1, cy = -1;
    for (int y = 0; y < h_; y++) {
        for (int x = 0; x < w_; x++) {
            const Cell* c = at(x, y);
            if (c->continuation) continue;
            bool wide = x + 1 < w_ && at(x + 1, y)->continuation;
            if (!full && *c == *prev.at(x, y) && (!wide || *at(x + 1, y) == *prev.at(x + 1, y))) continue;
            if (full && c->glyph[0] == ' ' && c->glyph[1] == 0 && c->style == Style{}) continue;
            if (cx != x || cy != y) {
                out += "\x1b[" + std::to_string(y + 1) + ";" + std::to_string(x + 1) + "H";
                cx = x;
                cy = y;
            }
            if (!styleKnown || cur != c->style) {
                appendStyle(out, c->style);
                cur = c->style;
                styleKnown = true;
            }
            out += c->glyph;
            cx += wide ? 2 : 1;
        }
    }
    if (styleKnown) out += "\x1b[0m";
    return out;
}

// ---- Terminal -------------------------------------------------------------

struct Terminal::Saved {
    termios tio;
};

Terminal::~Terminal() { leave(); }

bool Terminal::enter(std::string& error) {
    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
        error = "the dashboard needs a terminal (use --headless to print alerts instead)";
        return false;
    }
    saved_ = new Saved;
    if (tcgetattr(STDIN_FILENO, &saved_->tio) != 0) {
        error = std::string("can't read terminal settings: ") + std::strerror(errno);
        delete saved_;
        saved_ = nullptr;
        return false;
    }
    termios raw = saved_->tio;
    raw.c_lflag &= ~tcflag_t(ICANON | ECHO | IEXTEN);  // keep ISIG so Ctrl-C still works
    raw.c_iflag &= ~tcflag_t(IXON | ICRNL);
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
    active_ = true;
    write("\x1b[?1049h\x1b[?25l\x1b[H\x1b[2J");
    force_ = true;
    return true;
}

void Terminal::leave() {
    if (!active_) return;
    write("\x1b[0m\x1b[?25h\x1b[?1049l");
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved_->tio);
    delete saved_;
    saved_ = nullptr;
    active_ = false;
}

bool Terminal::size(int& w, int& h) const {
    winsize ws{};
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) != 0 || ws.ws_col == 0) return false;
    w = ws.ws_col;
    h = ws.ws_row;
    return true;
}

void Terminal::write(const std::string& s) {
    size_t off = 0;
    while (off < s.size()) {
        ssize_t n = ::write(STDOUT_FILENO, s.data() + off, s.size() - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return;
        }
        off += size_t(n);
    }
}

void Terminal::present(const Screen& s) {
    if (force_) {
        last_ = Screen{};
        force_ = false;
    }
    write(s.diff(last_));
    last_ = s;
}

int Terminal::readKey(int timeoutMs) {
    if (pending_.empty()) {
        pollfd pfd{STDIN_FILENO, POLLIN, 0};
        if (poll(&pfd, 1, timeoutMs) <= 0) return kKeyNone;
        char buf[64];
        ssize_t n = ::read(STDIN_FILENO, buf, sizeof buf);
        if (n <= 0) return kKeyNone;
        pending_.assign(buf, size_t(n));
    }
    auto take = [this](size_t n, int key) {
        pending_.erase(0, n);
        return key;
    };
    const std::string& p = pending_;
    if (p[0] != 27) return take(1, static_cast<unsigned char>(p[0]));
    if (p.size() >= 3 && (p[1] == '[' || p[1] == 'O')) {
        switch (p[2]) {
        case 'A': return take(3, kKeyUp);
        case 'B': return take(3, kKeyDown);
        case 'C': return take(3, kKeyRight);
        case 'D': return take(3, kKeyLeft);
        case 'H': return take(3, kKeyHome);
        case 'F': return take(3, kKeyEnd);
        default: break;
        }
        if (p.size() >= 4 && p[3] == '~') {
            switch (p[2]) {
            case '5': return take(4, kKeyPageUp);
            case '6': return take(4, kKeyPageDown);
            case '1': case '7': return take(4, kKeyHome);
            case '4': case '8': return take(4, kKeyEnd);
            default: break;
            }
        }
        // Some other sequence: drop it.
        size_t end = 2;
        while (end < p.size() && !(p[end] >= 0x40 && p[end] <= 0x7e)) end++;
        return take(std::min(end + 1, p.size()), kKeyNone);
    }
    return take(1, kKeyEscape);
}

}  // namespace pm
