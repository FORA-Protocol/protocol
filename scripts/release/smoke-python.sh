#!/usr/bin/env bash
# Smoke test for the published Python packages.
# Installs the given requirements into a fresh virtualenv outside the checkout,
# with no PYTHONPATH, imports fora_sdk and calls one L1 function, and loads a published
# JSON Schema from the fora-protocol package data. Arguments are
# wheel paths, sdist paths (each sdist is first rebuilt into a wheel in an
# isolated build environment) or PyPI specs.
#   scripts/release/smoke-python.sh dist/fora_protocol-1.2.3-py3-none-any.whl dist/fora_protocol_sdk-1.2.3-py3-none-any.whl
#   scripts/release/smoke-python.sh dist/fora_protocol-1.2.3.tar.gz dist/fora_protocol_sdk-1.2.3.tar.gz
#   scripts/release/smoke-python.sh fora-protocol==1.2.3 fora-protocol-sdk==1.2.3
# Leading --constraint SPEC arguments become a constraints file: a constraint
# narrows the resolution without requesting the package. uv before 0.12.0 accepts
# a prerelease only for a package the install itself names, so under it a
# prerelease of fora-protocol-sdk installs through its exact fora-protocol pin
# only with --constraint fora-protocol==<the same version>. uv 0.12.0 and later
# follow the pin without it, as pip does (uv 0.12.0's release notes: "Prefer stable
# releases before falling back to pre-releases"). The pin still has to pull
# fora-protocol in, and a pin on another version conflicts with the constraint.
#   scripts/release/smoke-python.sh --constraint fora-protocol==1.3.0b1 fora-protocol-sdk==1.3.0b1
# A failed install or rebuild exits 1, whatever status uv returned, with a plain
# message: verify-pypi.sh retries it, so a failed try is not yet an error.
set -euo pipefail
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
constraints=()
while [ $# -gt 0 ] && [ "$1" = --constraint ]; do
  [ $# -ge 2 ] || { echo "::error::--constraint needs a requirement spec"; exit 2; }
  printf '%s\n' "$2" >> "$work/constraints.txt"; constraints=(-c "$work/constraints.txt"); shift 2
done
reqs=()
for r in "$@"; do
  case "$r" in
    *.tar.gz)
      uv build -q --wheel --out-dir "$work/rebuilt" "$r" || { echo "smoke-python: cannot rebuild $r into a wheel" >&2; exit 1; }
      reqs+=("$work/rebuilt/$(basename "${r%.tar.gz}")-py3-none-any.whl") ;;
    *.whl) reqs+=("$(cd "$(dirname "$r")" && pwd)/$(basename "$r")") ;;
    *) reqs+=("$r") ;;
  esac
done
cd "$work"
uv venv -q .venv || { echo "smoke-python: cannot create a virtualenv" >&2; exit 1; }
uv pip install -q --python .venv ${constraints[@]+"${constraints[@]}"} "${reqs[@]}" \
  || { echo "smoke-python: cannot install $*" >&2; exit 1; }
env -u PYTHONPATH .venv/bin/python -I - <<'PY'
import fora_sdk
from fora_sdk.thumbprint import thumbprint
from wire.models import Offer
from vocab import pricingunits
from wire import schemas
got = thumbprint(bytes(32))
assert got == "ogRZbCR5KTrPFCAfuYmCMwj0w7Yuk3Lr6YWQWfpkbf0", got
assert pricingunits.is_registered("fetches")
assert "exchange" in Offer.model_fields
# the published JSON Schemas ship as package data in both variants
strict = schemas.load("fora.v1.ResourceResponse", strict=True)
assert strict["$id"] == "fora.v1.ResourceResponse.schema.strict.json", strict["$id"]
assert strict["additionalProperties"] is False
assert "additionalProperties" not in schemas.load("fora.v1.ResourceResponse")
assert len(schemas.names()) > 0
print("fora_sdk import + thumbprint + JSON Schemas ok")
PY
echo "smoke-python ok: $*"
