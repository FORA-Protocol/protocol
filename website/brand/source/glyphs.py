"""Outline text to SVG path data with fontTools, applying GPOS pair kerning."""
from fontTools.ttLib import TTFont
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen

def _pair_kern(font):
    kern = {}
    if 'GPOS' not in font: return kern
    gpos = font['GPOS'].table
    idx = set()
    for fr in gpos.FeatureList.FeatureRecord:
        if fr.FeatureTag == 'kern': idx.update(fr.Feature.LookupListIndex)
    for i in idx:
        lk = gpos.LookupList.Lookup[i]
        subs = lk.SubTable
        if lk.LookupType == 9: subs = [s.ExtSubTable for s in subs]
        for st in subs:
            if getattr(st, 'LookupType', 2) != 2 and lk.LookupType not in (2, 9): continue
            cov = st.Coverage.glyphs
            if st.Format == 1:
                for g, ps in zip(cov, st.PairSet):
                    for r in ps.PairValueRecord:
                        v = r.Value1.XAdvance if r.Value1 and hasattr(r.Value1, 'XAdvance') else 0
                        if v: kern.setdefault((g, r.SecondGlyph), v)
            elif st.Format == 2:
                c1 = st.ClassDef1.classDefs; c2 = st.ClassDef2.classDefs
                return_c = (c1, c2, st, set(cov))
                kern.setdefault('__class__', []).append(return_c)
    return kern

def kern_value(kern, a, b):
    if (a, b) in kern: return kern[(a, b)]
    for c1, c2, st, cov in kern.get('__class__', []):
        if a not in cov: continue
        r = st.Class1Record[c1.get(a, 0)].Class2Record[c2.get(b, 0)]
        v = getattr(r.Value1, 'XAdvance', 0) if r.Value1 else 0
        if v: return v
    return 0

def outline(path, text, size, x=0.0, y=0.0, tracking_em=0.0):
    """Return (svg path d, width) for text at font size `size`, baseline at y."""
    f = TTFont(path)
    gs = f.getGlyphSet(); cmap = f.getBestCmap(); upm = f['head'].unitsPerEm
    hmtx = f['hmtx']; kern = _pair_kern(f)
    s = size / upm; names = [cmap[ord(ch)] for ch in text]
    pen = SVGPathPen(gs); cx = 0.0
    for i, n in enumerate(names):
        tp = TransformPen(pen, (s, 0, 0, -s, x + cx * s, y))
        gs[n].draw(tp)
        adv = hmtx[n][0]
        if i + 1 < len(names): adv += kern_value(kern, n, names[i + 1]) + tracking_em * upm
        cx += adv
    return pen.getCommands(), cx * s

def metrics(path):
    f = TTFont(path); os2 = f['OS/2']; upm = f['head'].unitsPerEm
    return dict(upm=upm, xh=os2.sxHeight, cap=os2.sCapHeight, asc=f['hhea'].ascent, desc=f['hhea'].descent)
