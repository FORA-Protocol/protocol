#!/usr/bin/env bash
#
# Python SDK API gate: griffe check over the public API of fora_sdk, comparing the tree
# with the last release (the newest vX.Y.Z tag reachable from HEAD), against the
# shrink-only baseline scripts/gates/baselines/api-python.json. Each breakage griffe
# reports (a removed, renamed or changed public object or parameter) is a finding,
# unless the release is a major version and sdk/python/CHANGELOG.md lists the symbol
# under Breaking (scripts/gates/api_rules.py). scripts/gates/api_diff.py runs griffe;
# the pinned griffe is checked by scripts/gates/python-tools.sh. --base-ref reaches
# only the baseline's own shrink check: the API is always compared with the release.
#
# Usage:  scripts/gates/gate-api-python.sh [--base-ref REF]          check the tree
#         scripts/gates/gate-api-python.sh record [--base-ref REF]   shrink the baseline
# A finding names a symbol, not a line, so an edit elsewhere never moves it. Its
# tool files (--tool-file) are python-tools.sh, the griffe pin in the SDK's gates
# dependency group and its packages in the lock, and the scripts that run griffe
# and read its output.

set -euo pipefail
cd "$(dirname "$0")/../.."
# python-tools.sh's ratchet step passes the hand-written Python files to its tool;
# this gate's tool takes none, so it checks the tools and runs ratchet.py itself.
scripts/gates/python-tools.sh check
exec python3 scripts/gates/ratchet.py --format griffe --gate "scripts/gates/${0##*/}" \
  --baseline scripts/gates/baselines/api-python.json "$@" \
  --tool-file scripts/gates/python-tools.sh \
  --tool-file sdk/python/pyproject.toml#dependency-groups.gates \
  --tool-file sdk/python/uv.lock#package.griffe --tool-file sdk/python/uv.lock#package.griffecli \
  --tool-file sdk/python/uv.lock#package.griffelib \
  --tool-file scripts/gates/api_diff.py --tool-file scripts/gates/api_formats.py \
  --tool-file scripts/gates/api_rules.py \
  -- python3 scripts/gates/api_diff.py python
