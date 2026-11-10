---
name: fora-brand
description: Apply the FORA protocol brand and claims rules. Use when making any slide, post, article, diagram, page, video frame or graphic that names or depicts FORA.
---

# FORA brand

This skill carries the official FORA logo files, color and type tokens, and the
rules for naming FORA and describing what it does. Use the files as they are.
Do not redraw, retype, recolor or "improve" anything in `assets/`.

Source of truth: <https://fora-protocol.org/brand/>. If this skill and that page
disagree, the page wins.

## 1. Logo

The mark is a blue wax seal pressed with the open forum: an open square with no
walls around one point. The seal is the signature anyone can check; the
impression is the open market it seals. Below 32 px the impression cannot be
read, so small uses get the plain seal.

Pick the file by background and by size. Never build the logo from text or
shapes yourself.

| Background | Lockup, 32 px tall and up | Lockup, under 32 px | Mark, 32 px and up | Mark, under 32 px |
|---|---|---|---|---|
| Dark (ink, navy, dark photo) | `fora-lockup-on-dark.svg` | `fora-lockup-small-on-dark.svg` | `fora-mark-on-dark.svg` | `fora-mark-small.svg` |
| Light (white, off-white) | `fora-lockup-on-light.svg` | `fora-lockup-small-on-light.svg` | `fora-mark-on-light.svg` | `fora-mark-small.svg` |
| FORA Blue or a busy photo | `fora-lockup-mono-white.svg` | `fora-lockup-small-mono-white.svg` | `fora-mark-mono-white.svg` | `fora-mark-small-mono-white.svg` |
| One-color print, emboss | `fora-lockup-mono-black.svg` | `fora-lockup-small-mono-black.svg` | `fora-mark-mono-black.svg` | `fora-mark-small-mono-black.svg` |

All files are in `assets/`. PNG copies sit next to the SVGs for tools that
cannot take SVG. `fora-icon.svg` is the square avatar (seal on an ink tile).
`fora-social-card.png` is a ready 1200×630 link preview.

Rules:
- Use the lockup by default. Use the mark alone only where space is square or
  tiny (avatars, favicons, a corner bug on a video) or where "FORA" is already
  written nearby.
- "32 px" means the rendered height of the seal itself. In print, 32 px ≈ 8 mm.
- Clear space on every side: at least one quarter of the seal's height. The
  SVGs already include part of it; add the rest around them.
- Minimum size: plain seal 16 px; lockup 100 px wide.
- The seal is always FORA Blue, except in the mono files. The impression is
  cut through the seal, so the background shows in it; that is intended.
- Scale proportionally. No stretching, rotating, outlines, shadows, glows,
  gradients, wax textures or 3D effects. The flat seal is the logo.
- Do not put the logo on mid-grey or mid-blue where neither the dark nor the
  light file has contrast; change the background instead.
- Do not set "fora protocol" in a font yourself as a logo, do not put a
  different emblem in the seal, and do not combine the mark with any other word
  (product names, event names, "certified").

## 2. Color

Tokens are in `tokens/tokens.css` (CSS custom properties) and `tokens/tokens.json`.
The brand is dark-first: ink background, white text, one blue accent.

| Token | Hex | Use |
|---|---|---|
| `--fora-ink` | `#0a0a0f` | Default background; text on light |
| `--fora-near-black` | `#12121a` | Cards and panels on ink |
| `--fora-dark` | `#1a1a26` | Raised surfaces, code blocks |
| `--fora-line` | `#2a2a3a` | Borders and dividers on dark |
| `--fora-gray` | `#a5a5b8` | Secondary text on dark |
| `--fora-white` | `#f5f5fa` | Primary text on dark |
| `--fora-paper` | `#fafafa` | Light background |
| `--fora-blue` | `#4f6df5` | FORA Blue: the accent. Buttons, the logo point, one highlight per view |
| `--fora-blue-text` | `#9aaeff` | Blue for text on dark (headline highlight, links) |
| `--fora-blue-dark` | `#3d58d6` | Blue for text and links on light; button hover; fill behind small white text |

Rules:
- One accent. Blue is the only brand color; do not add oranges, greens or
  rainbow palettes. Status colors in UI or charts are fine if they stay muted.
- On dark, colored text uses `--fora-blue-text`, never `--fora-blue` (too dim).
- On light, colored text and links use `--fora-blue-dark`.
- White text under 18 px on a blue fill goes on `--fora-blue-dark`, not
  `--fora-blue` (contrast).
- Hero backgrounds may use the site glow: a soft radial of FORA Blue at about 20%
  opacity from the top centre over ink. Nothing louder.

## 3. Type

- **Instrument Sans** for everything: headlines 700, UI and subheads 600, body
  400–500. Headlines get tight tracking (−0.03em).
- **DM Mono** for code, RPC and field names (`ExecuteTransaction`,
  `/.well-known/fora.json`), IDs, prices in receipts, and small all-caps labels.
- Both are free on Google Fonts. Fallbacks: system sans (`-apple-system`,
  `Segoe UI`, `Roboto`) and system mono.
- Sentence case for headlines and buttons. No title case, no all-caps
  headlines.
- The highlight pattern from the site: a two-line headline whose second line is
  in blue text, e.g. "Make your website or music catalog licensable.
  *Instantly.*"

## 4. Layout

- Generous dark space, a single column of argument, thin `--fora-line`
  dividers, 3 px corner radius on buttons, 8–12 px on cards.
- Diagrams: boxes in `--fora-near-black` with `--fora-line` borders, labels in
  white, the step or path that matters in blue. Arrows thin and grey.
- Slides: one idea per slide, lockup small in a top corner, slide number and
  "fora-protocol.org" small in the footer.

## 5. Name and words

Read `reference/messaging.md` before writing any copy. The short version:

- **Lead with the owner's outcome:** FORA makes a website or a music catalog
  licensable to AI agents, instantly. Then the mechanism: set your terms once,
  and every page or track becomes a signed offer any agent can find, buy and
  verify, with no deal per buyer. "Instantly" means once connected, not zero
  setup; never promise minutes or one click.
- Write **FORA** in prose. "The FORA protocol" or "FORA Protocol" when you need
  the noun. The lowercase "fora protocol" exists only inside the logo.
- It stands for **Federated Open Resource Access**. Spell it out once, if at all.
- Never "Fora", "F.O.R.A.", or the old name "RAMP".
- FORA is an **open protocol**, not an "industry standard" and not adopted by any
  standards body.
- Do not claim customers, partners, pilots, prices or numbers that are not on
  fora-protocol.org. If the user gives you such a claim, keep it but tell them
  it must be public before publishing.
- Demo licenses are test money and grant no real rights. Say so wherever a
  demo appears.

## 6. Before you hand it over

Check every item:

1. Logo is an unmodified file from `assets/`, the right variant for the
   background and for its size (plain seal under 32 px), with clear space.
2. Only the palette above; blue used sparingly; text contrast as in section 2.
3. Instrument Sans and DM Mono (or the stated fallbacks).
4. "FORA" spelled right; no "RAMP"; "open protocol", not "standard".
   Copy for rights holders leads with "licensable, instantly", not with the
   protocol mechanics.
5. Every factual claim is in `reference/messaging.md` or on fora-protocol.org,
   or flagged to the user as unverified.
6. A link to <https://fora-protocol.org> is present where the format allows.

If a check fails and you cannot fix it inside the format (for example a tool
that cannot place an SVG), say which check failed and why in your reply.
