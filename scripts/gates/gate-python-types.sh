#!/usr/bin/env bash
#
# Python type gate: mypy --strict over the hand-written Python, against
# scripts/gates/baselines/python-types.json. The files are the ones
# scripts/gates/scope.py lists, the pinned mypy is checked by
# scripts/gates/python-tools.sh, and the settings are in mypy.ini.
#
# Usage:  scripts/gates/gate-python-types.sh [--base-ref REF]   check the tree
#         scripts/gates/gate-python-types.sh record             shrink the baseline

set -euo pipefail
cd "$(dirname "$0")/../.."
exec scripts/gates/python-tools.sh ratchet "scripts/gates/${0##*/}" mypy scripts/gates/baselines/python-types.json \
  "$@" -- mypy --config-file mypy.ini --output json
