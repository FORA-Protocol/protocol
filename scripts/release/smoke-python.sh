#!/usr/bin/env bash
# Smoke test for the published Python packages (FORA-291).
# Installs the given requirements into a fresh virtualenv outside the checkout,
# with no PYTHONPATH, imports fora_sdk and calls one L1 function. Arguments are
# wheel paths, sdist paths (each sdist is first rebuilt into a wheel in an
# isolated build environment) or PyPI specs.
#   scripts/release/smoke-python.sh dist/fora_protocol-1.2.3-py3-none-any.whl dist/fora_protocol_sdk-1.2.3-py3-none-any.whl
#   scripts/release/smoke-python.sh dist/fora_protocol-1.2.3.tar.gz dist/fora_protocol_sdk-1.2.3.tar.gz
#   scripts/release/smoke-python.sh fora-protocol==1.2.3 fora-protocol-sdk==1.2.3
set -euo pipefail
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
reqs=()
for r in "$@"; do
  case "$r" in
    *.tar.gz)
      uv build -q --wheel --out-dir "$work/rebuilt" "$r"
      reqs+=("$work/rebuilt/$(basename "${r%.tar.gz}")-py3-none-any.whl") ;;
    *.whl) reqs+=("$(cd "$(dirname "$r")" && pwd)/$(basename "$r")") ;;
    *) reqs+=("$r") ;;
  esac
done
cd "$work"
uv venv -q .venv
uv pip install -q --python .venv "${reqs[@]}"
env -u PYTHONPATH .venv/bin/python -I - <<'PY'
import fora_sdk
from fora_sdk.thumbprint import thumbprint
from wire.models import Offer
from vocab import pricingunits
got = thumbprint(bytes(32))
assert got == "ogRZbCR5KTrPFCAfuYmCMwj0w7Yuk3Lr6YWQWfpkbf0", got
assert pricingunits.is_registered("fetches")
assert "exchange" in Offer.model_fields
print("fora_sdk import + thumbprint ok")
PY
echo "smoke-python ok: $*"
