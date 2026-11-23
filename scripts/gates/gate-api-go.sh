#!/usr/bin/env bash
#
# Go SDK API gate: apidiff over every non-internal package under sdk/go, comparing
# the tree with the last release (the newest vX.Y.Z tag reachable from HEAD), against
# the shrink-only baseline scripts/gates/baselines/api-go.json. Each incompatible
# change to an exported symbol (a removal, a rename, a changed signature) is a
# finding, unless the release is a major version and sdk/go/CHANGELOG.md lists the
# symbol under Breaking (scripts/gates/api_rules.py). scripts/gates/api_diff.py runs
# apidiff; the pinned apidiff is checked by scripts/gates/go-tools.sh. --base-ref
# reaches only the baseline's own shrink check: the API is always compared with the
# release.
#
# Usage:  scripts/gates/gate-api-go.sh [--base-ref REF]          check the tree
#         scripts/gates/gate-api-go.sh record [--base-ref REF]   shrink the baseline
# A finding names a symbol, not a line, so an edit elsewhere never moves it. Its
# tool files are the apidiff pin, which go-tools.sh passes, and the scripts passed
# with --tool-file below, which run apidiff and read its output.

set -euo pipefail
cd "$(dirname "$0")/../.."
exec scripts/gates/go-tools.sh ratchet "scripts/gates/${0##*/}" apidiff scripts/gates/baselines/api-go.json \
  "$@" --tool-file scripts/gates/api_diff.py --tool-file scripts/gates/api_formats.py \
  --tool-file scripts/gates/api_rules.py \
  -- python3 scripts/gates/api_diff.py go
