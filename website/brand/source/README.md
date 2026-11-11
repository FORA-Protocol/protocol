# Brand source

`generate.py` draws every logo file from geometry: the wax seal, the open-forum
impression, the compact seal for small sizes, and the wordmark outlined from
Instrument Sans 600 (via `glyphs.py`). Edit the geometry here, never the SVGs.

Needs Python with `fontTools` and `shapely`, and `rsvg-convert` for the PNGs.
Fonts come from the `@fontsource/instrument-sans` npm package.

```sh
npm pack @fontsource/instrument-sans && tar -xzf fontsource-instrument-sans-*.tgz
FORA_FONTS=$PWD/package/files python3 generate.py out
cd out
for f in fora-mark-*.svg fora-icon.svg; do rsvg-convert -w 512 "$f" -o "${f%.svg}-512.png"; done
for f in fora-lockup-*.svg; do rsvg-convert -h 240 "$f" -o "${f%.svg}.png"; done
rsvg-convert -w 1200 fora-social-card.svg -o fora-social-card.png
rsvg-convert -w 32 favicon.svg -o ../../../public/favicon-32.png
rsvg-convert -w 180 fora-icon.svg -o ../../../public/apple-touch-icon.png
cp favicon.svg ../../../public/
cp fora-* ../../fora-brand/assets/ && cp fora-* ../../../public/brand/
cp fora-lockup-small-on-dark.svg fora-lockup-small-on-light.svg ../../../src/assets/brand/
cd ../.. && rm -f ../public/brand/fora-brand.zip && zip -r ../public/brand/fora-brand.zip fora-brand -x '*.DS_Store'
```

The skill in `../fora-brand/` is what `/brand/fora-brand.zip` serves; rebuild the
zip whenever the skill or the logos change.
