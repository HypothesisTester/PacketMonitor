#!/usr/bin/env python3
"""Records the dashboard replaying the sample capture as a GIF and a PNG.

Runs packetmonitor in a pseudo-terminal, reads the screen with pyte, draws
each frame with Pillow and joins them with ffmpeg. Used for the README:

    pip install pyte pillow
    python3 tools/record_demo.py build/packetmonitor build/sample.pcap docs/
"""
import os
import pty
import select
import struct
import subprocess
import sys
import tempfile
import time
import fcntl
import termios

import pyte
import pyte.graphics
from PIL import Image, ImageDraw, ImageFont

COLS, ROWS = 118, 34
SPEED = 6
FONT_SIZE = 15
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
BG = (17, 19, 24)
FG = (215, 218, 224)
PAD = 18

# pyte has no "faint" attribute; borrow blink, which the dashboard never uses.
pyte.graphics.TEXT[2] = "+blink"
pyte.graphics.TEXT[22] = "-blink"

font = ImageFont.truetype(FONT, FONT_SIZE)
bold = ImageFont.truetype(FONT_BOLD, FONT_SIZE)
CW = round(font.getlength("M"))
CH = round(FONT_SIZE * 1.3)


def color(value, default):
    if value == "default":
        return default
    try:
        return tuple(int(value[i:i + 2], 16) for i in (0, 2, 4))
    except ValueError:
        named = {"black": (0, 0, 0), "red": (205, 49, 49), "green": (13, 188, 121), "yellow": (229, 229, 16),
                 "blue": (36, 114, 200), "magenta": (188, 63, 188), "cyan": (17, 168, 205), "white": (229, 229, 229)}
        return named.get(value, default)


def mix(a, b, t):
    return tuple(round(x * (1 - t) + y * t) for x, y in zip(a, b))


def block(draw, ch, x, y, fg):
    """Block elements drawn as rectangles, so bars have no gaps between rows."""
    code = ord(ch)
    if 0x2581 <= code <= 0x2588:  # lower eighths
        h = CH * (code - 0x2580) / 8
        draw.rectangle([x, y + CH - h, x + CW - 1, y + CH - 1], fill=fg)
        return True
    if 0x2589 <= code <= 0x258F:  # left eighths
        w = CW * (0x2590 - code) / 8
        draw.rectangle([x, y, x + w - 1, y + CH - 1], fill=fg)
        return True
    return False


def render(screen):
    img = Image.new("RGB", (COLS * CW + 2 * PAD, ROWS * CH + 2 * PAD), BG)
    draw = ImageDraw.Draw(img)
    for row in range(ROWS):
        line = screen.buffer[row]
        for col in range(COLS):
            c = line[col]
            fg = color(c.fg, FG)
            bg = color(c.bg, BG)
            if c.reverse:
                fg, bg = bg, fg
            if c.blink:  # faint
                fg = mix(fg, bg, 0.45)
            x, y = PAD + col * CW, PAD + row * CH
            if bg != BG:
                draw.rectangle([x, y, x + CW - 1, y + CH - 1], fill=bg)
            ch = c.data
            if not ch or ch == " ":
                continue
            if block(draw, ch, x, y, fg):
                continue
            draw.text((x, y + (CH - FONT_SIZE) / 2 - 1), ch, font=bold if c.bold else font, fill=fg)
            if c.underscore:
                draw.line([x, y + CH - 2, x + CW, y + CH - 2], fill=fg)
    return img


def main():
    binary, capture, outdir = sys.argv[1:4]
    duration = float(sys.argv[4]) if len(sys.argv) > 4 else 31
    fps = 5
    # Keys pressed during the recording: show the Apps and Hosts views too.
    keys = {17.0: b"2", 21.0: b"3", 25.0: b"1"}

    pid, fd = pty.fork()
    if pid == 0:
        os.environ["TERM"] = "xterm-256color"
        os.execv(binary, [binary, "--read", capture, "--speed", str(SPEED)])
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))

    screen = pyte.Screen(COLS, ROWS)
    stream = pyte.ByteStream(screen)
    frames = tempfile.mkdtemp()
    start = time.time()
    n = 0
    next_frame = start + 0.8
    sent = set()
    while time.time() - start < duration:
        r, _, _ = select.select([fd], [], [], 0.02)
        if r:
            try:
                stream.feed(os.read(fd, 65536))
            except OSError:
                break
        now = time.time() - start
        for at, key in keys.items():
            if now >= at and at not in sent:
                os.write(fd, key)
                sent.add(at)
        if time.time() >= next_frame:
            render(screen).save(os.path.join(frames, f"f{n:04d}.png"))
            n += 1
            next_frame += 1 / fps
    os.write(fd, b"q")
    time.sleep(0.3)

    os.makedirs(outdir, exist_ok=True)
    # The still: near the end, with every incident found.
    still = os.path.join(frames, f"f{min(n - 1, int(28.6 * fps)):04d}.png")
    Image.open(still).save(os.path.join(outdir, "dashboard.png"), optimize=True)
    gif = os.path.join(outdir, "demo.gif")
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-framerate", str(fps), "-i",
                    os.path.join(frames, "f%04d.png"), "-vf",
                    "split[a][b];[a]palettegen=max_colors=64:stats_mode=diff[p];[b][p]paletteuse=dither=none:diff_mode=rectangle",
                    gif], check=True)
    print(f"{n} frames -> {gif} ({os.path.getsize(gif) // 1024} kB)")


if __name__ == "__main__":
    main()
