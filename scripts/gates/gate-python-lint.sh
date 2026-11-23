#!/usr/bin/env bash
#
# Python lint gate: `ruff check` over the hand-written Python, against
# scripts/gates/baselines/python-lint.json. The files are the ones
# scripts/gates/scope.py lists, the pinned ruff is checked by
# scripts/gates/python-tools.sh, and the rule set is in ruff.toml, which
# sdk/python/pyproject.toml extends.
#
# Usage:  scripts/gates/gate-python-lint.sh [--base-ref REF]          check the tree
#         scripts/gates/gate-python-lint.sh record [--base-ref REF]   shrink the baseline
# record carries the entry of a finding that moved; with --base-ref, also across a
# renamed or copied file, and across a change of the gate's tool alone: a file passed
# with --tool-file below, a pin that python-tools.sh passes, or the reader in formats.py.

set -euo pipefail
cd "$(dirname "$0")/../.."
exec scripts/gates/python-tools.sh ratchet "scripts/gates/${0##*/}" ruff scripts/gates/baselines/python-lint.json \
  "$@" --tool-file ruff.toml --tool-file sdk/python/pyproject.toml#tool.ruff \
  -- ruff check --no-fix --output-format json
