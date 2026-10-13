#!/usr/bin/env python3
"""Generate the full Trellis delivery set (variants, rasters, web icons) without the skill scripts."""
import os
import re
import subprocess

OUT = "."
MASTERS = "masters"
PINE = "#123B2E"
AMBER = "#E8A33D"
WHITE = "#FFFFFF"
BLACK = "#000000"
NAME = "trellis"


def read(p):
    return open(p).read()


def write(p, s):
    open(p, "w").write(s)
    print("  svg", p)


def recolor(svg, mapping):
    for a, b in mapping.items():
        svg = svg.replace(a, b)
    return svg


def body_of(path):
    s = read(path)
    s = re.sub(r"^.*?<svg[^>]*>", "", s, flags=re.S)
    s = re.sub(r"</svg>\s*$", "", s)
    s = re.sub(r"<title[^>]*>.*?</title>", "", s, flags=re.S)
    return s.strip()


def wrap(viewbox, title, body, w=None, h=None):
    w, h = w or viewbox.split()[2], h or viewbox.split()[3]
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{viewbox}" width="{w}" height="{h}" '
        f'role="img" aria-labelledby="t">\n  <title id="t">{title}</title>\n{body}\n</svg>\n'
    )


def render(svg, png, w, h=None):
    cmd = ["rsvg-convert", "-w", str(w)]
    if h:
        cmd += ["-h", str(h)]
    cmd += [svg, "-o", png]
    subprocess.run(cmd, check=True)


# ------------------------------------------------------------------ variants
def main():
    os.makedirs(f"{OUT}/svg", exist_ok=True)
    os.makedirs(f"{OUT}/png", exist_ok=True)
    os.makedirs(f"{OUT}/web", exist_ok=True)

    pairs = {
        "symbol": f"{MASTERS}/trellis-symbol.svg",
        "horizontal": f"{MASTERS}/trellis-horizontal.svg",
        "stacked": f"{MASTERS}/trellis-stacked.svg",
        "wordmark": f"{MASTERS}/trellis-wordmark.svg",
        "symbol-small": f"{MASTERS}/trellis-symbol-small.svg",
    }

    print("one-colour + reversed variants")
    for key, src in pairs.items():
        s = read(src)
        title = re.search(r"<title[^>]*>(.*?)</title>", s, flags=re.S).group(1)
        title = title.replace("—", "-")
        for tag, mapping in [
            ("black", {PINE: BLACK, AMBER: BLACK}),
            ("white", {PINE: WHITE, AMBER: WHITE}),
            ("mono-pine", {PINE: PINE, AMBER: PINE}),
            ("on-dark", {PINE: WHITE, AMBER: AMBER}),
        ]:
            write(f"{OUT}/svg/{NAME}-{key}-{tag}.svg", recolor(s, mapping))

    print("app icon + favicon tiles (pine tile, white lattice, amber T)")
    sym = body_of(f"{MASTERS}/trellis-symbol.svg")
    sym_dark = recolor(sym, {PINE: WHITE, AMBER: AMBER})
    small = body_of(f"{MASTERS}/trellis-symbol-small.svg")
    small_dark = recolor(small, {PINE: WHITE, AMBER: AMBER})

    app = (
        f'  <rect width="256" height="256" rx="56" fill="{PINE}"/>\n'
        f'  <g transform="translate(128 128) scale(0.70) translate(-128 -128)">\n{sym_dark}\n  </g>'
    )
    write(f"{OUT}/svg/{NAME}-app-icon.svg", wrap("0 0 256 256", "Trellis app icon", app))

    fav = (
        f'  <rect width="256" height="256" rx="52" fill="{PINE}"/>\n'
        f'  <g transform="translate(128 128) scale(0.74) translate(-128 -128)">\n{small_dark}\n  </g>'
    )
    write(f"{OUT}/svg/{NAME}-favicon.svg", wrap("0 0 256 256", "Trellis favicon", fav))
    write(f"{OUT}/svg/{NAME}-favicon-flat.svg",
          wrap("0 0 256 256", "Trellis favicon, flat", recolor(fav, {PINE: BLACK})))

    # ------------------------------------------------------------- rasters
    print("rasters")
    render(f"{MASTERS}/trellis-symbol.svg", f"{OUT}/png/{NAME}-symbol-1024.png", 1024, 1024)
    render(f"{MASTERS}/trellis-horizontal.svg", f"{OUT}/png/{NAME}-horizontal-1600.png", 1600)
    render(f"{MASTERS}/trellis-stacked.svg", f"{OUT}/png/{NAME}-stacked-1024.png", 1024)
    render(f"{OUT}/svg/{NAME}-symbol-white.svg", f"{OUT}/png/{NAME}-symbol-white-1024.png", 1024, 1024)
    for size in (512, 256, 128, 64, 32, 16):
        render(f"{MASTERS}/trellis-symbol.svg", f"{OUT}/png/{NAME}-symbol-{size}.png", size, size)
    for size in (512, 256, 64, 32, 16):
        render(f"{OUT}/svg/{NAME}-app-icon.svg", f"{OUT}/png/{NAME}-icon-{size}.png", size, size)

    # ---------------------------------------------------------- web icons
    print("web icon set")
    for size in (16, 32, 48):
        render(f"{OUT}/svg/{NAME}-favicon.svg", f"{OUT}/web/favicon-{size}.png", size, size)
    render(f"{OUT}/svg/{NAME}-app-icon.svg", f"{OUT}/web/apple-touch-icon.png", 180, 180)
    render(f"{OUT}/svg/{NAME}-app-icon.svg", f"{OUT}/web/icon-192.png", 192, 192)
    render(f"{OUT}/svg/{NAME}-app-icon.svg", f"{OUT}/web/icon-512.png", 512, 512)
    render(f"{OUT}/svg/{NAME}-app-icon.svg", f"{OUT}/web/icon-maskable-512.png", 512, 512)

    from PIL import Image

    im = Image.open(f"{OUT}/web/favicon-48.png").convert("RGBA")
    im.save(f"{OUT}/web/favicon.ico", sizes=[(16, 16), (32, 32), (48, 48)])
    for s in (16, 32, 48):
        Image.open(f"{OUT}/web/favicon-{s}.png").convert("RGBA").save(
            f"{OUT}/web/favicon-{s}.png")
    print("  ico out/web/favicon.ico")

    write(f"{OUT}/web/site.webmanifest", """{
  "name": "Trellis",
  "short_name": "Trellis",
  "icons": [
    { "src": "/icon-192.png", "sizes": "192x192", "type": "image/png" },
    { "src": "/icon-512.png", "sizes": "512x512", "type": "image/png" },
    { "src": "/icon-maskable-512.png", "sizes": "512x512", "type": "image/png", "purpose": "maskable" }
  ],
  "theme_color": "#123B2E",
  "background_color": "#FFFFFF",
  "display": "standalone"
}
""".replace("  svg", "  file"))
    write(f"{OUT}/web/head-snippet.html", """<!-- Trellis icons -->
<link rel="icon" href="/favicon.ico" sizes="32x32">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="manifest" href="/site.webmanifest">
<meta name="theme-color" content="#123B2E">
""".replace("  svg", "  link"))
    print("done")


if __name__ == "__main__":
    main()
