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
# renamed or copied file, and across a change of the gate's tool alone: a file passed
# with --tool-file below, a pin that python-tools.sh passes, or the reader in formats.py.

set -euo pipefail
cd "$(dirname "$0")/../.."
exec scripts/gates/python-tools.sh ratchet "scripts/gates/${0##*/}" mypy scripts/gates/baselines/python-types.json \
  "$@" --tool-file mypy.ini \
  -- mypy --config-file mypy.ini --output json
