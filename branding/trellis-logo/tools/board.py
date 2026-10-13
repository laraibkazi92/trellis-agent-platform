#!/usr/bin/env python3
"""Build a one-page Trellis brand sheet (SVG) and render it to PNG."""
import re
import subprocess

PINE = "#123B2E"
AMBER = "#E8A33D"
INK = "#14212B"
MUTED = "#5B6B73"
LINE = "#E3E7E6"
PAPER = "#FFFFFF"
WASH = "#F4F6F4"

W = 1400
SANS = "Fira Sans, DejaVu Sans, sans-serif"
MONO = "Fira Code, DejaVu Sans Mono, monospace"

svg_out = []


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def text(x, y, s, size=15, fill=INK, weight="400", family=SANS, anchor="start", ls=0, op=1):
    svg_out.append(
        f'<text x="{x}" y="{y}" font-family="{family}" font-size="{size}" font-weight="{weight}" '
        f'fill="{fill}" text-anchor="{anchor}" letter-spacing="{ls}" opacity="{op}">{esc(s)}</text>'
    )


def rect(x, y, w, h, fill, rx=0, stroke=None, sw=1, op=1):
    s = f' stroke="{stroke}" stroke-width="{sw}"' if stroke else ""
    svg_out.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}"{s} opacity="{op}"/>')


def line(x1, y1, x2, y2, stroke=LINE, sw=1):
    svg_out.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{stroke}" stroke-width="{sw}"/>')


def vb_of(path):
    s = open(path).read()
    m = re.search(r'viewBox="([-\d.]+) ([-\d.]+) ([-\d.]+) ([-\d.]+)"', s)
    return [float(v) for v in m.groups()]


def body_of(path):
    s = open(path).read()
    s = re.sub(r"^.*?<svg[^>]*>", "", s, flags=re.S)
    s = re.sub(r"</svg>\s*$", "", s)
    s = re.sub(r"<title[^>]*>.*?</title>", "", s, flags=re.S)
    return s.strip()


def place(path, x, y, w=None, h=None, op=1):
    vx, vy, vw, vh = vb_of(path)
    s = w / vw if w else h / vh
    bx = x - vx * s
    by = y - vy * s
    g = f'<g transform="translate({bx:.2f} {by:.2f}) scale({s:.5f})" opacity="{op}">\n{body_of(path)}\n</g>'
    svg_out.append(g)
    return vw * s, vh * s


def section(y, title, sub=""):
    text(72, y, title.upper(), 13, PINE, "700", ls=1.6)
    if sub:
        text(72 + 8 * len(title) + 24, y, sub, 13.5, MUTED)
    line(72, y + 14, W - 72, y + 14)
    return y + 46


def swatch(x, y, name, hexv, use, size=54):
    rect(x, y, size, size, hexv, rx=10, stroke=LINE if hexv.upper() == "#FFFFFF" else None)
    text(x + size + 16, y + 20, name, 15, INK, "600")
    text(x + size + 16, y + 39, hexv.upper(), 13, MUTED, family=MONO)
    text(x + size + 16, y + 56, use, 12.5, MUTED)
    return x + size + 16 + 240


print("building sheet")
rect(0, 0, W, 2900, PAPER)

# ------------------------------------------------------------------- header
rect(0, 0, W, 200, PINE)
place("svg/trellis-horizontal-on-dark.svg", 72, 26, w=404)
text(72, 178, "Self-hosted, polyglot LLM agent framework", 16, "#B9CEC5")
text(W - 72, 74, "LOGO KIT", 13, AMBER, "700", anchor="end", ls=2)
text(W - 72, 100, "Round 3 · final direction", 13, "#B9CEC5", anchor="end")
text(W - 72, 122, "Grown T · fence lattice", 13, "#B9CEC5", anchor="end")

y = 256
y = section(y, "The mark", "A fence lattice with a grown T — the two members that carry the T are bolder than the frame.")
place("masters/trellis-symbol.svg", 72, y - 8, w=300)
text(410, y + 26, "The trellis is drawn as a fence lattice: canes that thicken toward the base,", 15.5, INK)
text(410, y + 50, "rails that bow, uneven member lengths — organic, not machined. The middle", 15.5, INK)
text(410, y + 74, "post and top rail are the heaviest lines and read as a T; the T sits forward", 15.5, INK)
text(410, y + 98, "and, in colour, is the only amber element.", 15.5, INK)
text(410, y + 132, "Sizes", 13, MUTED, "700", ls=1.2)
sx = 410
for sz in (16, 32, 64, 128):
    place("masters/trellis-symbol.svg", sx, y + 150 + (128 - sz), w=sz)
    text(sx + sz / 2, y + 150 + 128 + 22, f"{sz}px", 11.5, MUTED, anchor="middle")
    sx += sz + 42
y += 300 + 40

# ------------------------------------------------------------------- colour
y = section(y, "Colour", "Two colours, with a clear job each. The palette avoids the default blue of developer tools.")
x = 72
x = swatch(x, y, "Pine", PINE, "Lattice, headings, key UI", 58)
x = swatch(x, y, "Amber", AMBER, "The T, accents, focus", 58)
x = swatch(x, y, "Ink", INK, "Body text, one-colour mark", 58)
x = swatch(x, y, "Paper", PAPER, "Backgrounds", 58)
y += 96
text(72, y, "Pine 5535 C (approx.) · Amber 143 C (approx.) — verify against a Pantone guide before print.", 13, MUTED)
text(72, y + 24, "The T keeps its own colour on light and dark; in one-colour use it still reads because it is the heaviest element.", 13, MUTED)
y += 66

# ------------------------------------------------------------------ variants
y = section(y, "Variants", "Every mark ships in full colour, one colour, and reversed.")
cw = 200
gapx = 34
cards = [
    ("Full colour", "masters/trellis-symbol.svg", PAPER),
    ("One colour", "svg/trellis-symbol-mono-pine.svg", PAPER),
    ("On dark", "svg/trellis-symbol-on-dark.svg", PINE),
    ("Reversed", "svg/trellis-symbol-white.svg", PINE),
]
for i, (label, path, bg) in enumerate(cards):
    x = 72 + i * (cw + gapx)
    rect(x, y, cw, cw, bg, rx=14, stroke=LINE)
    place(path, x + 30, y + 30, w=cw - 60)
    text(x + cw / 2, y + cw + 24, label, 13.5, MUTED, anchor="middle")
y += cw + 74

# ------------------------------------------------------------------- lockups
y = section(y, "Lockups", "Horizontal is primary. One unit = the width of a lattice cane.")
place("masters/trellis-horizontal.svg", 72, y + 20, w=520)
text(72, y + 244, "Horizontal — primary", 13.5, MUTED)
place("masters/trellis-stacked.svg", 700, y + 1, w=240)
text(700, y + 244, "Stacked — square formats, social", 13.5, MUTED)
place("masters/trellis-wordmark.svg", 1030, y + 55, w=300)
text(1030, y + 244, "Wordmark — where the symbol is already known", 13.5, MUTED)
y += 300

# --------------------------------------------------------------- small sizes
y = section(y, "Icons & small sizes", "At 16 px the thin frame becomes texture — a simplified cut keeps the T sharp.")
place("svg/trellis-favicon.svg", 72, y, w=150)
text(72, y + 176, "App / favicon tile", 13.5, MUTED)
rect(250, y, 150, 150, PAPER, rx=14, stroke=LINE)
place("masters/trellis-symbol-small.svg", 265, y + 12, w=120)
text(250, y + 176, "Small cut (≥16 px)", 13.5, MUTED)
# pixel test
px = 435
for sz, lbl in ((16, "16"), (24, "24"), (32, "32"), (48, "48")):
    place("svg/trellis-favicon.svg", px, y + 96 - sz / 2, w=sz)
    text(px + sz / 2, y + 120, lbl, 11, MUTED, anchor="middle")
    px += sz + 46
text(435, y + 176, "Tile at real size", 13.5, MUTED)
px = 720
for sz in (16, 24, 32, 48):
    place("masters/trellis-symbol-small.svg", px, y + 96 - sz / 2, w=sz)
    text(px + sz / 2, y + 120, f"{sz}", 11, MUTED, anchor="middle")
    px += sz + 46
text(720, y + 176, "Small cut at real size", 13.5, MUTED)
place("svg/trellis-symbol-black.svg", 1010, y + 16, w=118)
text(1010, y + 176, "Black, one colour", 13.5, MUTED)
y += 232

# ---------------------------------------------------------------- in context
y = section(y, "In context", "")
# browser tab
rect(72, y, 360, 150, WASH, rx=12)
rect(88, y + 16, 200, 40, PAPER, rx=9, stroke=LINE)
place("svg/trellis-favicon.svg", 102, y + 22, w=28)
text(140, y + 42, "Trellis", 15, INK, "600")
rect(296, y + 16, 120, 40, PAPER, rx=9, stroke=LINE)
text(356, y + 42, "Agents", 15, MUTED, anchor="middle")
text(88, y + 92, "Browser tab", 13.5, MUTED)
text(88, y + 116, "favicon.svg + favicon.ico", 12, MUTED, family=MONO)

# terminal
tx = 470
rect(tx, y, 400, 150, "#0B1512", rx=12)
rect(tx, y, 400, 30, "#152621", rx=12)
for i, c in enumerate(("#F2685E", "#E8A33D", "#7ECB6A")):
    svg_out.append(f'<circle cx="{tx + 20 + i * 20}" cy="{y + 15}" r="5" fill="{c}"/>')
text(tx + 16, y + 58, "$ trellis agent run --tool search", 13, "#9FD3BC", family=MONO)
text(tx + 16, y + 80, "> routed via rules engine", 13, "#6F8C82", family=MONO)
text(tx + 16, y + 102, "> 3 agents online", 13, "#6F8C82", family=MONO)
place("svg/trellis-symbol-on-dark.svg", tx + 330, y + 60, w=54)
text(tx, y + 176, "Terminal / dark UI", 13.5, MUTED)
text(tx, y + 200, "use the *-on-dark variant", 12, MUTED, family=MONO)

# readme / docs
rx = 930
rect(rx, y, 398, 160, PAPER, rx=12, stroke=LINE)
place("masters/trellis-horizontal.svg", rx + 22, y + 18, w=240)
rect(rx + 22, y + 100, 250, 9, LINE, rx=4.5)
rect(rx + 22, y + 118, 340, 9, "#EDF0EF", rx=4.5)
text(rx, y + 186, "README header", 13.5, MUTED)
text(rx, y + 210, "horizontal lockup", 12, MUTED, family=MONO)
y += 250

# ------------------------------------------------------------------ clear space
y = section(y, "Clear space & minimum size", "")
rect(72, y, 190, 190, PAPER, rx=10, stroke=LINE)
place("masters/trellis-symbol.svg", 92, y + 20, w=150)
rect(72, y, 190, 190, "none", rx=10, stroke=AMBER, sw=1.5)
text(300, y + 30, "Clear space", 14, INK, "600")
text(300, y + 54, "Keep a margin of 1 × cane width (≈ 7 % of the mark) on all sides.", 14, MUTED)
text(300, y + 78, "Nothing enters that zone — no type, no rules, no edges.", 14, MUTED)
text(300, y + 118, "Minimum size", 14, INK, "600")
text(300, y + 142, "Symbol: 16 px screen / 6 mm print (use the small cut).", 14, MUTED)
text(300, y + 166, "Horizontal lockup: 130 px wide screen / 34 mm print.", 14, MUTED)
y += 232

# --------------------------------------------------------------------------
text(72, y + 20, "Files: /svg (masters + variants) · /png (rasters 16–1600 px) · /web (favicon.ico, PWA icons, manifest)",
     13, MUTED, family=MONO)
text(72, y + 44, "Trademark: this is original artwork, but a professional clearance search is still recommended before registration.",
     13, MUTED)
text(72, y + 68, "Wordmark: Fira Sans (SIL Open Font License) delivered as outlined paths — no font dependency.",
     13, MUTED)
H = y + 110

svg = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H:.0f}" width="{W}" height="{H:.0f}">\n'
    '  <title>Trellis brand sheet</title>\n' + "\n".join(svg_out) + "\n</svg>\n"
)
open("trellis-brand-sheet.svg", "w").write(svg)
print("wrote trellis-brand-sheet.svg")
subprocess.run(["rsvg-convert", "-w", "1400", "trellis-brand-sheet.svg", "-o", "trellis-brand-sheet.png"], check=True)
print("wrote trellis-brand-sheet.png")
