"""Generate the FORA logo set: the wax seal, lockups, favicon, icon, social card.

The mark is a wax seal pressed with the open forum.
- The seal: before signatures and cryptography, a wax seal proved who sent a
  letter and that nobody opened it on the way, and any recipient could check
  it without asking a central office. FORA's signed offers and acceptances.
- The impression: an open square with no walls (the forum, open to anyone)
  around one point, the transaction.
Below 32 px the impression cannot survive, so small uses get the plain seal.

All text is outlined, so no file depends on a font being installed.
Needs: fontTools, shapely. Fonts: the @fontsource/instrument-sans npm package,
unpacked; point FORA_FONTS at its package/files directory.

    FORA_FONTS=/path/to/package/files python3 generate.py out
"""
import math, os, sys
sys.path.insert(0, os.path.dirname(__file__))
from glyphs import outline
from shapely.geometry import Point, Polygon, box
from shapely import affinity
from fontTools.pens.boundsPen import BoundsPen
from fontTools.ttLib import TTFont

OUT = sys.argv[1]
FONTS = os.environ.get('FORA_FONTS', os.path.join(os.path.dirname(__file__), 'fonts'))
SANS600 = f'{FONTS}/instrument-sans-latin-600-normal.woff'
SANS700 = f'{FONTS}/instrument-sans-latin-700-normal.woff'
SANS400 = f'{FONTS}/instrument-sans-latin-400-normal.woff'

INK, WHITE, BLUE, GRAY, BLUE_TEXT = '#0a0a0f', '#f5f5fa', '#4f6df5', '#a5a5b8', '#9aaeff'


# ---------- geometry (64-unit grid) ----------

def _puddle(n=720):
    """An irregular wax puddle with one drip; low lobes so it reads as wax, not a badge."""
    pts = []
    for k in range(n):
        a = 2 * math.pi * k / n
        r = (26 + 1.4 * math.sin(2 * a + 0.4) + 1.2 * math.sin(3 * a + 2.2)
             + 0.9 * math.sin(5 * a + 1.1) + 0.35 * math.sin(11 * a))
        da = math.atan2(math.sin(a - 0.9), math.cos(a - 0.9))
        r += 2.6 * math.exp(-(da / 0.22) ** 2)
        pts.append((32 + r * math.cos(a), 32 + r * math.sin(a)))
    p = Polygon(pts).buffer(0.8).buffer(-0.8)
    minx, miny, maxx, maxy = p.bounds                      # centre the puddle in the box
    return affinity.translate(p, 32 - (minx + maxx) / 2, 32 - (miny + maxy) / 2)

SEAL = _puddle()
C = (32, 32)

def _ring(r, w):
    return Point(C).buffer(r + w / 2, quad_segs=64).difference(Point(C).buffer(r - w / 2, quad_segs=64))

def _corners(a=21.5, b=42.5, arm=8.5, w=4.2):
    parts = []
    for (x, y, sx, sy) in ((a, a, 1, 1), (b, a, -1, 1), (b, b, -1, -1), (a, b, 1, -1)):
        x2, y2 = x + sx * arm, y + sy * arm
        parts.append(box(min(x, x2), min(y, y + sy * w), max(x, x2), max(y, y + sy * w)))
        parts.append(box(min(x, x + sx * w), min(y, y2), max(x, x + sx * w), max(y, y2)))
    return parts

IMPRESSION = [_ring(19.5, 2.2)] + _corners()
POINT = Point(C).buffer(3.3, quad_segs=32)

FULL = SEAL
for part in IMPRESSION:
    FULL = FULL.difference(part)
SEAL_BOUNDS = SEAL.bounds


def _d(geom, tol=0.04):
    geom = geom.simplify(tol)
    polys = [geom] if geom.geom_type == 'Polygon' else list(geom.geoms)
    out = ''
    for p in polys:
        for ring in [p.exterior, *p.interiors]:
            pts = list(ring.coords)[:-1]
            out += 'M' + 'L'.join(f'{x:.2f} {y:.2f}' for x, y in pts) + 'Z'
    return out

D_FULL, D_SIMPLE, D_POINT = _d(FULL), _d(SEAL), _d(POINT)
D_FULL_MONO = _d(FULL.difference(POINT))                   # point pressed in too


def mark(kind, seal, point=None, tx=0, ty=0, scale=1):
    """kind: 'full' or 'simple'. point: colour of the centre point (full colour versions only)."""
    if kind == 'simple':
        body = f'<path fill="{seal}" d="{D_SIMPLE}"/>'
    elif point is None:
        body = f'<path fill="{seal}" fill-rule="evenodd" d="{D_FULL_MONO}"/>'
    else:
        body = f'<path fill="{seal}" fill-rule="evenodd" d="{D_FULL}"/><path fill="{point}" d="{D_POINT}"/>'
    return f'<g transform="translate({tx:g} {ty:g}) scale({scale:g})">{body}</g>'


def svg(w, h, body, title):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w:g} {h:g}" '
            f'width="{w:g}" height="{h:g}" role="img" aria-label="{title}">'
            f'<title>{title}</title>{body}</svg>\n')

def write(name, text):
    with open(os.path.join(OUT, name), 'w') as f:
        f.write(text)


os.makedirs(OUT, exist_ok=True)

# Variants: name -> (seal colour, point colour or None for mono, wordmark colour)
VARIANTS = {
    'on-dark': (BLUE, WHITE, WHITE),
    'on-light': (BLUE, INK, INK),
    'mono-white': (WHITE, None, WHITE),
    'mono-black': (INK, None, INK),
}

# 1. Marks: full (32 px and up) and simple (below 32 px).
for v, (sc, pc, _) in VARIANTS.items():
    write(f'fora-mark-{v}.svg', svg(64, 64, mark('full', sc, pc), 'FORA'))
write('fora-mark-small.svg', svg(64, 64, mark('simple', BLUE), 'FORA'))
write('fora-mark-small-mono-white.svg', svg(64, 64, mark('simple', WHITE), 'FORA'))
write('fora-mark-small-mono-black.svg', svg(64, 64, mark('simple', INK), 'FORA'))

# 2. Lockups. The seal spans the wordmark's full height: ascender top to descender bottom.
SIZE = 100
_f = TTFont(SANS600); _gs = _f.getGlyphSet(); _cm = _f.getBestCmap(); _u = _f['head'].unitsPerEm
def _ext(ch):
    bp = BoundsPen(_gs); _gs[_cm[ord(ch)]].draw(bp); return bp.bounds
ASC = max(_ext(c)[3] for c in 'flt') * SIZE / _u
DESC = -_ext('p')[1] * SIZE / _u
SPAN = ASC + DESC
minx, miny, maxx, maxy = SEAL_BOUNDS
s = SPAN / (maxy - miny) * 1.12             # wax looks lighter than type; give it a little more height
seal_h = (maxy - miny) * s
pad = 0.10 * seal_h
seal_top = pad
mark_ty = seal_top - miny * s
seal_left = pad
mark_tx = seal_left - minx * s
centre_y = seal_top + seal_h / 2
base = centre_y + (ASC - DESC) / 2            # centre the type's ascender-descender span on the seal
GAP = 0.30 * seal_h
d_word, w_word = outline(SANS600, 'fora protocol', SIZE, 0, base, tracking_em=-0.03)
word_x = seal_left + (maxx - minx) * s + GAP
total_w = word_x + w_word + pad
lock_h = seal_h + 2 * pad

def lockup(kind, sc, pc, wc):
    return (mark(kind, sc, pc, mark_tx, mark_ty, s)
            + f'<g transform="translate({word_x:g} 0)"><path fill="{wc}" d="{d_word}"/></g>')

for v, (sc, pc, wc) in VARIANTS.items():
    write(f'fora-lockup-{v}.svg', svg(round(total_w, 1), round(lock_h, 1), lockup('full', sc, pc, wc), 'FORA protocol'))
    small_sc = BLUE if pc is not None else sc
    write(f'fora-lockup-small-{v}.svg', svg(round(total_w, 1), round(lock_h, 1), lockup('simple', small_sc, None, wc), 'FORA protocol'))

# 3. Favicon: the plain seal; blue reads on light and dark tabs alike.
write('favicon.svg', f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><path fill="{BLUE}" d="{D_SIMPLE}"/></svg>\n')

# 4. Avatar: the full seal on an ink tile (GitHub org, social profiles).
write('fora-icon.svg', svg(512, 512, f'<rect width="512" height="512" fill="{INK}"/>' + mark('full', BLUE, WHITE, 64, 64, 6), 'FORA'))

# 5. Social card 1200x630.
d_h1, _ = outline(SANS700, 'Licensed content access', 72, 96, 330, tracking_em=-0.03)
d_h2, _ = outline(SANS700, 'for AI agents.', 72, 96, 418, tracking_em=-0.03)
d_sub, _ = outline(SANS400, 'Open protocol · Apache 2.0 · fora-protocol.org', 28, 96, 520)
card = (f'<defs><radialGradient id="g" cx="50%" cy="0%" r="80%">'
        f'<stop offset="0" stop-color="{BLUE}" stop-opacity=".22"/><stop offset="1" stop-color="{BLUE}" stop-opacity="0"/></radialGradient></defs>'
        f'<rect width="1200" height="630" fill="{INK}"/><rect width="1200" height="630" fill="url(#g)"/>'
        f'<g transform="translate(88 84) scale(0.55)">{lockup("full", BLUE, WHITE, WHITE)}</g>'
        f'<path fill="{WHITE}" d="{d_h1}"/><path fill="{BLUE_TEXT}" d="{d_h2}"/><path fill="{GRAY}" d="{d_sub}"/>')
write('fora-social-card.svg', svg(1200, 630, card, 'FORA protocol: licensed content access for AI agents'))

print('lockup', round(total_w, 1), 'x', round(lock_h, 1))
