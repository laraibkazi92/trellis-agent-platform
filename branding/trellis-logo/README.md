# Trellis logo kit

Final direction: **Grown T · fence lattice**, with the T in its own colour.

## Contents

```
masters/     hand-off masters (edit these, not the exports)
  trellis-symbol.svg              primary symbol (full colour)
  trellis-symbol-small.svg        simplified cut for ≤ 24 px
  trellis-horizontal.svg          primary lockup
  trellis-stacked.svg             stacked lockup
  trellis-wordmark.svg            wordmark only (outlined, no font needed)
svg/         one-colour · mono · reversed · on-dark · app-icon · favicon
png/         rasters: symbol 16–1024, lockups, variants
web/         favicon.ico + favicon.svg, apple-touch-icon, 192/512/maskable, manifest, head snippet
trellis-brand-sheet.svg|png      one-page brand sheet
GUIDELINES.md                    usage guide
tools/                           reproducible builders
```

## Colours

| Name | HEX | Role |
|---|---|---|
| Pine | `#123B2E` | Lattice (the frame) |
| Amber | `#E8A33D` | The T |
| Ink | `#14212B` | Body text / one-colour |
| Paper | `#FFFFFF` | Backgrounds |

## Rebuild

Run from this directory (`python3`):

```bash
# 1. wordmark — outline Fira Sans Medium to paths (writes into masters/)
python3 tools/wordmark.py "Trellis" --font /usr/share/fonts/OTF/FiraSans-Medium.otf \
    --tracking -8 --first-color "#E8A33D" --color "#123B2E" \
    --out masters/trellis-wordmark.svg

# 2. lockups + small cut  (re-uses masters/trellis-symbol.svg)
python3 tools/compose.py

# 3. variants, rasters and web icons
python3 tools/export.py

# 4. brand sheet
python3 tools/board.py
```

`masters/trellis-symbol.svg` is the hand-authored master — everything else is derived from it.
`tools/export.py` and `tools/board.py` need `rsvg-convert`; `export.py` also uses `Pillow` for the `.ico`.
