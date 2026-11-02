#!/usr/bin/env python3
"""Make the 1024x1024 app icon from docs/assets/karambit-logo.svg (standard library only).

The SVG is pixel art: one <rect> per run of pixels on a 22x22 grid. This script draws the
macOS icon grid (824 px rounded square, 100 px margin) and scales each logo pixel by 36,
so the edges stay sharp. Then make the app icon set:

    python3 scripts/app-icon.py /tmp/karambit-icon.png
    (cd app && npx tauri icon /tmp/karambit-icon.png -o src-tauri/icons)
    # keep only the files that tauri.conf.json lists (macOS); delete the rest
"""
import re
import struct
import sys
import zlib
from pathlib import Path

SIZE, MARGIN, RADIUS, SCALE, GRID = 1024, 100, 185, 36, 22
BG = (0x14, 0x18, 0x1F)
svg = (Path(__file__).resolve().parent.parent / "docs/assets/karambit-logo.svg").read_text()

img = [[(0, 0, 0, 0)] * SIZE for _ in range(SIZE)]

# Rounded square, with 4x4 supersampled corners for a smooth edge.
lo, hi = MARGIN, SIZE - MARGIN
for y in range(lo, hi):
    for x in range(lo, hi):
        hits = 0
        for sy in range(4):
            for sx in range(4):
                px, py = x + (sx + 0.5) / 4, y + (sy + 0.5) / 4
                cx = min(max(px, lo + RADIUS), hi - RADIUS)
                cy = min(max(py, lo + RADIUS), hi - RADIUS)
                hits += (px - cx) ** 2 + (py - cy) ** 2 <= RADIUS ** 2
        if hits:
            img[y][x] = (*BG, round(255 * hits / 16))

# Logo pixels, centred. The full-size background rect is skipped.
off = (SIZE - GRID * SCALE) // 2
for m in re.finditer(r'<rect ([^>]*)/>', svg):
    a = dict(re.findall(r'(\w+)="([^"]*)"', m.group(1)))
    if "x" not in a:
        continue
    x0, y0, w, h = (int(a[k]) for k in ("x", "y", "width", "height"))
    c = tuple(int(a["fill"][i:i + 2], 16) for i in (1, 3, 5))
    for y in range(off + y0 * SCALE, off + (y0 + h) * SCALE):
        for x in range(off + x0 * SCALE, off + (x0 + w) * SCALE):
            img[y][x] = (*c, 255)

raw = b"".join(b"\x00" + bytes(v for p in row for v in p) for row in img)
def chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", SIZE, SIZE, 8, 6, 0, 0, 0))
       + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))
Path(sys.argv[1] if len(sys.argv) > 1 else "karambit-icon.png").write_bytes(png)
