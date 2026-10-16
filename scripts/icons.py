"""Build original Shellport PNG icons from its vector geometry; no external assets."""
import math
import pathlib
import struct
import zlib

root = pathlib.Path(__file__).resolve().parents[1] / "web" / "public"
segments = [(118, 47, 143, 47), (143, 47, 143, 145), (143, 145, 118, 145), (52, 67, 81, 96), (81, 96, 52, 125), (89, 126, 111, 126)]

def distance(x, y, line):
    ax, ay, bx, by = line
    dx, dy = bx - ax, by - ay
    t = max(0, min(1, ((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy)))
    return math.hypot(x - ax - t * dx, y - ay - t * dy)

def chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

for size in [192, 512]:
    rows = bytearray()
    for y in range(size):
        rows.append(0)
        for x in range(size):
            px, py = (x + .5) * 192 / size, (y + .5) * 192 / size
            d = min(distance(px, py, seg) for seg in segments)
            alpha = max(0, min(1, (5.5 - d) * size / 192))
            rows.extend(round(a + (b - a) * alpha) for a, b in zip((16, 19, 21), (237, 189, 114)))
    data = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(bytes(rows))) + chunk(b"IEND", b"")
    (root / f"icon-{size}.png").write_bytes(data)
