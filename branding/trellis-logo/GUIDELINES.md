# Trellis — Logo Guidelines (compact)

> One page, written for non-designers. The mark is fixed; everything here is the *correct* way to use it.

## 1. The logo

- **Idea** — A fence lattice with a **grown T**. The frame is drawn like a garden trellis: canes that
  thicken toward the base, rails that bow, deliberately uneven ends. The middle post and the top rail
  are the two heaviest members, so they read as the letter **T** — the framework and the initial in one mark.
- **Colour roles** — the T is the only amber element; the lattice stays pine. This is what makes the letter
  step forward without shouting.
- **Versions** — primary (horizontal) · stacked · symbol-only · wordmark-only.
- **Files** — `svg/` masters and variants (screens, print, cutting) · `png/` rasters 16–1600 px · `web/`
  favicon + PWA icon set + manifest. Use **SVG** wherever you can.

## 2. Clear space

Keep a margin of **1 × cane width** (≈ **7 % of the mark's width**) on all sides. The zone scales with the
logo — never use a fixed millimetre value. Nothing enters it: no type, rules, images or page edges.

## 3. Minimum size

| Version | Screen | Print |
|---|---|---|
| Horizontal lockup | 130 px wide | 34 mm wide |
| Stacked lockup | 90 px wide | 24 mm wide |
| Symbol | 24 px (16 px with the small cut) | 6 mm |
| Wordmark | 80 px wide | 22 mm wide |

Use `trellis-symbol-small.svg` (the simplified cut) below 24 px — at 16 px the full lattice becomes texture.

## 4. Colour

| Name | HEX | RGB | CMYK (indicative) | Pantone (approx.) | Use |
|---|---|---|---|---|---|
| Pine | `#123B2E` | 18 59 46 | 69 0 22 77 | 5535 C | Lattice, headings, key UI |
| Amber | `#E8A33D` | 232 163 61 | 0 30 74 9 | 143 C | The T, accents, focus |
| Ink | `#14212B` | 20 33 43 | 54 23 0 83 | Black 6 C | Body text, one-colour mark |
| Paper | `#FFFFFF` | 255 255 255 | 0 0 0 0 | — | Backgrounds |

*CMYK and Pantone values are indicative — verify against a physical guide before print.* Amber is a light
colour: keep it for graphics and accents, never for small text on white.

**Approved logo/background pairs**
- Full colour on Paper (primary)
- `-on-dark` on Pine and on Ink (the lattice goes white, the T stays amber)
- One-colour Pine or Ink on Paper
- Reversed white on Pine / Ink / photography (use `-white`)

On photos, place the mark on a calm area, or give it a container.

## 5. Typography

- **Logo wordmark** — Fira Sans **Medium**, title case, tracking ≈ −0.8 %, delivered as **outlined paths**
  (no font needed to display it). The leading **T** carries the amber.
- **Brand typeface** — Fira Sans (SIL Open Font License, free for commercial/logo use). Use SemiBold for
  headlines, Regular for body.
- **Web fallback stack** — `system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif`.
- **Monospace** (docs, code, terminal) — any system mono; the mark never sits in mono text.

## 6. Don'ts

Don't stretch or squash · don't recolour outside the palette · don't put the T and the lattice in the same
colour (the emphasis is the point) · don't rotate or add effects (shadows, outlines, gradients, glows) ·
don't rearrange or separately resize the parts of a lockup · don't place on a busy background without a
container · don't retype the wordmark — always use the supplied artwork.

## 7. Handover notes

**Done:** geometry on a 256 grid; one-colour, mono, reversed and on-dark variants; horizontal / stacked /
symbol / wordmark lockups; simplified small cut; favicon + PWA icon set (`favicon.ico`, `favicon.svg`,
`apple-touch-icon.png`, 192/512/maskable, `site.webmanifest`, head snippet); outlined wordmark (no font
dependency).

**Remaining before launch:**
1. **Trademark** — this is original artwork, but run a professional clearance search (and a reverse image
   search) before registering. "Trellis" is used by others in unrelated sectors.
2. **Outline + union the master** — open `trellis-symbol.svg` in a vector editor and run *Outline Stroke*
   (none needed — everything is already filled) and *Path > Union* if a vinyl cutter or embroidery house asks
   for truly merged contours. All shapes are already fills, so this is optional for screen/print.
3. **Reversed weight** — white-on-dark looks slightly heavier; the `-on-dark` and `-white` files are the same
   geometry. If it feels bold in print, ask for a 3 % thinned reversal.
4. **Pantone** — match Pine and Amber to a physical guide.
5. **Tagline** — none is included; if one is added, fix its size ratio and drop it below 130 px wide.
