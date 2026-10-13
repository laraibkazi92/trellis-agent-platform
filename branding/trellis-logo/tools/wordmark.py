#!/usr/bin/env python3
"""Outline a wordmark from an installed font into SVG paths (production-grade, no <text>).

Usage:
  python3 wordmark.py "Trellis" --font /path/to/FiraSans-SemiBold.otf \
      --tracking -8 --out wordmark.svg
Prints metrics (advance width, cap height, x-height) so callers can compose lockups.
"""
import argparse
from fontTools.ttLib import TTFont
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.boundsPen import BoundsPen


def load(font_path):
    font = TTFont(font_path)
    return {
        "font": font,
        "upem": font["head"].unitsPerEm,
        "cmap": font.getBestCmap(),
        "glyphset": font.getGlyphSet(),
        "hmtx": font["hmtx"],
        "kern": _kern(font),
        "cap": _cap(font),
        "xheight": _xheight(font),
    }


def _kern(font):
    kern = {}
    if "kern" in font:
        for st in font["kern"].kernTables:
            kern.update(st.kernTable)
    return kern


def _cap(font, ch="H"):
    g = font.getBestCmap()[ord(ch)]
    pen = BoundsPen(font.getGlyphSet())
    font.getGlyphSet()[g].draw(pen)
    return pen.bounds[3] if pen.bounds else 0


def _xheight(font, ch="x"):
    g = font.getBestCmap()[ord(ch)]
    pen = BoundsPen(font.getGlyphSet())
    font.getGlyphSet()[g].draw(pen)
    return pen.bounds[3] if pen.bounds else 0


def glyph_paths(f, text, tracking=0.0):
    """Return [(glyphname, x_offset, svg_path_d)] laid out left-to-right on a 0 baseline."""
    out, x, prev = [], 0.0, None
    for ch in text:
        gname = f["cmap"][ord(ch)]
        if prev is not None:
            x += f["kern"].get((prev, gname), 0)
        pen = SVGPathPen(f["glyphset"])
        f["glyphset"][gname].draw(pen)
        out.append((gname, x, pen.getCommands()))
        x += f["hmtx"][gname][0] + tracking
        prev = gname
    return out, x


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("text")
    ap.add_argument("--font", required=True)
    ap.add_argument("--tracking", type=float, default=0.0)
    ap.add_argument("--color", default="#111111")
    ap.add_argument("--first-color", default=None,
                    help="colour for the first glyph (e.g. accent on the initial)")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    f = load(a.font)
    paths, advance = glyph_paths(f, a.text, a.tracking)
    upem = f["upem"]

    # Tight bbox in font units (glyph bounds shifted by their x offset).
    x0 = y0 = float("inf")
    x1 = y1 = float("-inf")
    for gname, x, d in paths:
        pen = BoundsPen(f["glyphset"])
        f["glyphset"][gname].draw(pen)
        if not pen.bounds:
            continue
        bx0, by0, bx1, by1 = pen.bounds
        x0, y0 = min(x0, bx0 + x), min(y0, by0)
        x1, y1 = max(x1, bx1 + x), max(y1, by1)
    print(f"font        {a.font}")
    print(f"unitsPerEm  {upem}")
    print(f"cap height  {f['cap']}")
    print(f"x-height    {f['xheight']}")
    print(f"advance     {advance:.1f}")

    parts = []
    for i, (gname, x, d) in enumerate(paths):
        color = a.color
        if i == 0 and a.first_color:
            color = a.first_color
        parts.append(
            f'  <path fill="{color}" transform="translate({x:g} 0) scale(1 -1)" d="{d}"/>'
        )

    svg = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{x0:g} {-y1:g} {x1 - x0:g} {y1 - y0:g}" '
        f'width="{x1 - x0:g}" height="{y1 - y0:g}" role="img" aria-label="{a.text} wordmark">\n'
        '  <title>' + a.text + ' wordmark (Fira Sans SemiBold, outlined)</title>\n'
        '  <g>\n' + "\n".join(parts) + "\n  </g>\n</svg>\n"
    )
    with open(a.out, "w") as fh:
        fh.write(svg)
    print(f"wrote       {a.out}")


if __name__ == "__main__":
    main()
