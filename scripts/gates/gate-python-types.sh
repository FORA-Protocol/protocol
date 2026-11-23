#!/usr/bin/env bash
#
# Python type gate: mypy --strict over the hand-written Python, against
# scripts/gates/baselines/python-types.json. The files are the ones
# scripts/gates/scope.py lists, the pinned mypy is checked by
# scripts/gates/python-tools.sh, and the settings are in mypy.ini.
#
# Usage:  scripts/gates/gate-python-types.sh [--base-ref REF]          check the tree
#         scripts/gates/gate-python-types.sh record [--base-ref REF]   shrink the baseline
# record carries the entry of a finding that moved; with --base-ref, also across a
# renamed or copied file, and across a change to mypy.ini or the mypy pin (the
# gates group of sdk/python/pyproject.toml, locked in sdk/python/uv.lock), the
# gate's tool files (--tool-file).

set -euo pipefail
cd "$(dirname "$0")/../.."
exec scripts/gates/python-tools.sh ratchet "scripts/gates/${0##*/}" mypy scripts/gates/baselines/python-types.json \
  "$@" --tool-file mypy.ini --tool-file scripts/gates/python-tools.sh \
  --tool-file sdk/python/pyproject.toml --tool-file sdk/python/uv.lock \
  -- mypy --config-file mypy.ini --output json
