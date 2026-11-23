#!/usr/bin/env bash
#
# The Python gates' tools, and the step the three Python gates (gate-python-format.sh,
# gate-python-lint.sh and gate-python-types.sh) share.
#
# The tools are ruff and mypy. Their versions are pinned in one place, the `gates`
# dependency group of sdk/python/pyproject.toml, and locked in sdk/python/uv.lock.
# They are installed into the SDK's own environment, sdk/python/.venv, because mypy
# reads the types of the SDK's dependencies from the environment it runs in; so the
# whole environment, not only the two tools, has to match the lock.
#
# Usage:
#   scripts/gates/python-tools.sh check
#       Exit 1 and print the install command unless sdk/python/.venv holds exactly
#       what sdk/python/uv.lock pins for the SDK, its test extra and the gates group.
#   scripts/gates/python-tools.sh install
#       Create or update sdk/python/.venv from the lock (.github/workflows/gates.yml
#       runs this).
#   scripts/gates/python-tools.sh ratchet GATE FORMAT BASELINE [record] [ARG...] -- CMD...
#       Run `check`, then CMD through ratchet.py for the gate script GATE, with
#       FORMAT and BASELINE, with sdk/python/.venv/bin first on PATH and the
#       hand-written Python files appended to CMD. A first ARG of `record` shrinks
#       the baseline; the other ARGs, such as --base-ref REF, go to ratchet.py.

set -euo pipefail
cd "$(dirname "$0")/../.."
source scripts/gates/tool-helper.sh

VENV=sdk/python/.venv
SYNC=(uv sync --project sdk/python --locked --extra test --group gates)

check() {
  local out
  if ! command -v uv >/dev/null 2>&1; then
    gate_refuse python-tools.sh "uv is not installed" \
      "the uv installer, https://docs.astral.sh/uv/getting-started/installation/"
  fi
  if ! out=$("${SYNC[@]}" --check 2>&1); then
    printf '%s\n' "$out" >&2
    gate_refuse python-tools.sh "$VENV does not match sdk/python/uv.lock"
  fi
}

usage="usage: $0 check|install|ratchet GATE FORMAT BASELINE [record] [ARG...] -- CMD..."
case "${1:-}" in
  check)
    check
    ;;
  install)
    command -v uv >/dev/null 2>&1 || check
    "${SYNC[@]}"
    ;;
  ratchet)
    [ "$#" -ge 4 ] || { echo "$usage" >&2; exit 2; }
    check
    # The hand-written Python files, as scripts/gates/scope.py defines them. Read
    # line by line rather than with mapfile, which the bash 3.2 of macOS lacks.
    listed=$(python3 scripts/gates/scope.py files --language python)
    files=()
    while IFS= read -r f; do files+=("$f"); done <<<"$listed"
    [ -n "$listed" ] || { echo "python-tools.sh: scope.py listed no Python file" >&2; exit 1; }
    export PATH="$PWD/$VENV/bin:$PATH"
    shift
    gate_ratchet "$@" "${files[@]}"
    ;;
  *)
    echo "$usage" >&2
    exit 2
    ;;
esac
