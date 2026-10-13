#!/usr/bin/env python3
"""Compose Trellis lockups from the outlined wordmark + the symbol."""
import re
import sys

sys.path.insert(0, "tools")
from wordmark import load, glyph_paths  # noqa: E402

PINE = "#123B2E"
AMBER = "#E8A33D"
FONT = "/usr/share/fonts/OTF/FiraSans-Medium.otf"
TRACKING = -8
TEXT = "Trellis"
CAP = 692.0
WM_X0, WM_X1, WM_TOP, WM_BOT = 10.0, 2753.0, -803.0, 16.0
SYM_CONTENT = (14.0, 244.0, 30.0, 238.0)  # x0, x1, y0, y1 of the symbol's artwork


def symbol_body(path="masters/trellis-symbol.svg"):
    s = open(path).read()
    s = re.sub(r"^.*?<svg[^>]*>", "", s, flags=re.S)
    s = re.sub(r"</svg>\s*$", "", s)
    s = re.sub(r"<title[^>]*>.*?</title>", "", s, flags=re.S)
    return s.strip()


def wordmark_paths(scale, tx, ty):
    f = load(FONT)
    paths, _ = glyph_paths(f, TEXT, TRACKING)
    out = []
    for i, (gname, x, d) in enumerate(paths):
        color = AMBER if i == 0 else PINE
        out.append(
            f'<path fill="{color}" transform="translate({tx + x * scale:.3f} {ty}) '
            f'scale({scale} -{scale})" d="{d}"/>'
        )
    return "\n".join(out)


def svg(viewbox, title, body):
    w, h = viewbox.split()[2], viewbox.split()[3]
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{viewbox}" width="{w}" height="{h}" '
        f'role="img" aria-labelledby="t">\n  <title id="t">{title}</title>\n{body}\n</svg>\n'
    )


def write(path, content):
    open(path, "w").write(content)
    print("wrote path".replace("path", path))


# ---------------------------------------------------------------- horizontal
SYM_W = 242.0                      # symbol box width
S = SYM_W / 256.0
sym_cx = (SYM_CONTENT[0] + SYM_CONTENT[1]) / 2 * S
sym_cy = (SYM_CONTENT[2] + SYM_CONTENT[3]) / 2 * S
sym_y = 128 - sym_cy               # centre the artwork in a 256-tall canvas
sym_right = SYM_CONTENT[1] * S
cap = 142.0
ws = cap / CAP
tx = sym_right + 58 - WM_X0 * ws
ty = 128 + cap / 2                 # cap band centred on the artwork centre
width = tx + WM_X1 * ws + 16
body = (
    f'  <g transform="translate(0 {sym_y:.2f}) scale({S:.6f})">\n{symbol_body()}\n  </g>\n'
    f'  <g>\n{wordmark_paths(ws, tx, ty)}\n  </g>'
)
write("masters/trellis-horizontal.svg", svg(f"0 0 {width:.0f} 256", "Trellis — horizontal lockup", body))

# ------------------------------------------------------------------- stacked
SYM_W2 = 268.0
S2 = SYM_W2 / 256.0
cap2 = 118.0
ws2 = cap2 / CAP
wm_w = (WM_X1 - WM_X0) * ws2
canvas_w = max((SYM_CONTENT[1] - SYM_CONTENT[0]) * S2, wm_w)
sym_dx = canvas_w / 2 - (SYM_CONTENT[0] + SYM_CONTENT[1]) / 2 * S2
wm_dx = canvas_w / 2 - (WM_X0 + WM_X1) / 2 * ws2
sym_bottom = SYM_CONTENT[3] * S2
ty2 = sym_bottom + 30 - WM_TOP * ws2   # gap of 30 above the tallest glyph (the i dot)
canvas_h = ty2 + WM_BOT * ws2 + 24
body2 = (
    f'  <g transform="translate({sym_dx:.2f} 0) scale({S2:.6f})">\n{symbol_body()}\n  </g>\n'
    f'  <g>\n{wordmark_paths(ws2, wm_dx, ty2)}\n  </g>'
)
write("masters/trellis-stacked.svg", svg(f"0 0 {canvas_w:.0f} {canvas_h:.0f}", "Trellis — stacked lockup", body2))

# ------------------------------------------------------------ wordmark alone
pad = 24
body3 = (
    f'  <g transform="translate({pad - WM_X0:.1f} {pad - WM_TOP:.1f})">\n'
    f'{wordmark_paths(1.0, 0, 0)}\n  </g>'
)
write(
    "masters/trellis-wordmark.svg",
    svg(
        f"0 0 {WM_X1 - WM_X0 + 2 * pad:.0f} {WM_BOT - WM_TOP + 2 * pad:.0f}",
        "Trellis — wordmark",
        body3,
    ),
)

# ------------------------------------------------- small-size symbol cut (16px)
small = f"""  <g fill="{PINE}">
    <rect x="44" y="34" width="17" height="172" rx="8.5"/>
    <rect x="195" y="34" width="17" height="196" rx="8.5"/>
  </g>
  <g fill="{AMBER}">
    <rect x="14" y="58" width="228" height="27"/>
    <rect x="113" y="58" width="30" height="184"/>
  </g>"""
write("masters/trellis-symbol-small.svg", svg("0 0 256 256", "Trellis symbol — small-size cut", small))
