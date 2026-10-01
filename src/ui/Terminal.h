// A small terminal toolkit with no dependencies: raw input, an off-screen grid
// of styled cells, and a renderer that only sends the cells that changed.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace pm {

enum Attr : uint8_t { kBold = 1, kDim = 2, kReverse = 4, kUnderline = 8 };

/** Colours are xterm-256 indexes; -1 is the terminal's own default. */
struct Style {
    int16_t fg = -1, bg = -1;
    uint8_t attr = 0;
    bool operator==(const Style& o) const { return fg == o.fg && bg == o.bg && attr == o.attr; }
    bool operator!=(const Style& o) const { return !(*this == o); }
};

inline Style fg(int16_t color, uint8_t attr = 0) { return Style{color, -1, attr}; }
inline Style attr(uint8_t a) { return Style{-1, -1, a}; }

/** Display width of a code point: 0, 1 or 2 columns. */
int codepointWidth(uint32_t cp);
/** Display width of UTF-8 text. */
int textWidth(std::string_view utf8);
/** Cuts UTF-8 text to at most width columns, ending with "…" if cut. */
std::string fitText(std::string_view utf8, int width);

class Screen {
public:
    void resize(int w, int h);
    int width() const { return w_; }
    int height() const { return h_; }
    void clear();

    /** Writes text at (x, y), clipped to maxWidth columns and the screen. Returns the next x. */
    int put(int x, int y, std::string_view utf8, Style s = {}, int maxWidth = -1);
    /** Right-aligns text so it ends just before column xEnd. */
    int putRight(int xEnd, int y, std::string_view utf8, Style s = {});
    void fill(int x, int y, int w, std::string_view glyph, Style s = {});

    /** The escape sequences that turn `previous` into this screen. */
    std::string diff(const Screen& previous) const;
    /** Plain text of one row, for tests. */
    std::string rowText(int y) const;
    Style styleAt(int x, int y) const;

private:
    struct Cell {
        char glyph[5] = {' ', 0, 0, 0, 0};
        Style style;
        bool continuation = false;  // right half of a wide character
        bool operator==(const Cell& o) const {
            return continuation == o.continuation && style == o.style && std::string_view(glyph) == o.glyph;
        }
    };
    Cell* at(int x, int y) { return &cells_[size_t(y) * size_t(w_) + size_t(x)]; }
    const Cell* at(int x, int y) const { return &cells_[size_t(y) * size_t(w_) + size_t(x)]; }

    int w_ = 0, h_ = 0;
    std::vector<Cell> cells_;
};

enum Key : int {
    kKeyNone = -1,
    kKeyUp = 0x1000,
    kKeyDown,
    kKeyLeft,
    kKeyRight,
    kKeyPageUp,
    kKeyPageDown,
    kKeyHome,
    kKeyEnd,
    kKeyTab = '\t',
    kKeyEscape = 27,
};

class Terminal {
public:
    ~Terminal();
    /** Switches to the alternate screen and raw input. False if not a terminal. */
    bool enter(std::string& error);
    void leave();

    bool size(int& w, int& h) const;
    /** Waits up to timeoutMs for a key; kKeyNone if none. */
    int readKey(int timeoutMs);
    void write(const std::string& s);

    /** Draws the screen, sending only what changed since the last call. */
    void present(const Screen& s);
    void invalidate() { force_ = true; }

private:
    bool active_ = false;
    bool force_ = true;
    Screen last_;
    std::string pending_;  // bytes of an escape sequence read so far
    struct Saved;
    Saved* saved_ = nullptr;
};

}  // namespace pm
