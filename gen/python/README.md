# Generated Python types export

Generated from [`proto/`](../../proto) via JSON Schema. **Do not edit by hand** —
regenerate with `scripts/gen-sdk-types.sh` and commit the result (CI drift-gates it).

A **types export**, not a full SDK: Pydantic models + registered vocabulary constants.
Transport (Connect), request signing (RFC 9421), and key management are a separate,
hand-written SDK layer.

Contents:
- `wire/base.py` — **`WireModel`**, the single base class every model extends (the one
  seam: SDK-wide config + your override point; neutral name so a protocol rename never
  touches consumer imports). **Hand-written, not regenerated.**
- `wire/models.py` — Pydantic v2 models for every message (`License`, `Pricing`,
  `LicenseTerm`, `Offer`, …), all extending `WireModel`. They carry **shape + per-field
  validation**: enums (named from the proto descriptor, `*_UNSPECIFIED` dropped),
  string patterns, length/item bounds. Nested messages reference the same model
  (`LicenseTerm.license` is a `License`), so the whole tree hydrates as typed models.
  **Cross-field rules are NOT here** — enforced server-side by the Exchange/Broker.
- `wire/schemas.py` — **`load(name, strict=False)`** and **`names()`**: the published JSON
  Schemas (draft 2020-12), one self-contained file per message, shipped as package data
  under `wire/jsonschema/`. `strict=True` selects the variant that refuses unknown fields
  at every depth; a conformance check uses it. The files are generated into
  [`gen/jsonschema/`](../jsonschema) (in this repository `wire/jsonschema` is a symlink to
  it), whose README records how they treat field naming, `google.protobuf.Struct` and
  64-bit integers. **Hand-written loader; needs no validator library.**
- `vocab/` — registered vocabulary constants per axis (`pricingunits`, …) with
  `is_registered()`, plus the accepted aliases authored beside the tokens (`ALIASES`,
  `canonical()` — an exact lookup; the SDK folds case before it looks up).

```python
from wire.models import LicenseTerm, License
from wire.base import WireModel          # subclass this to customize ALL models at once

term = LicenseTerm.model_validate(incoming_json)   # raises on shape/per-field violations
assert isinstance(term.license, License)           # full nested hierarchy, typed

from jsonschema import Draft202012Validator        # any draft 2020-12 validator
from wire import schemas
Draft202012Validator(schemas.load("fora.v1.LicenseTerm", strict=True)).validate(incoming_json)
```

Install (from this directory): `pip install .`

## Import names and PyPI

The distribution is published on PyPI as `fora-protocol`. Its import packages are the
generic top-level names `wire` and `vocab`, so it can collide with any other distribution
that owns either name; install it into an environment that does not. This is a deliberate
tradeoff: a rename to a namespaced package would break every consumer that installs from
this repository by git ref, so the names stay as they are.

```sh
pip install fora-protocol
```
