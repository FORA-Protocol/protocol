#!/usr/bin/env bash
#
# TypeScript SDK API gate: API Extractor over every entry point of the export map of
# sdk/ts/package.json, comparing the tree with the last release (the newest vX.Y.Z tag
# reachable from HEAD), against the shrink-only baseline
# scripts/gates/baselines/api-ts.json. Each declaration of an entry point's report at
# the release that the tree's report no longer has (a removed, renamed or changed
# export or member) is a finding, with two exceptions (scripts/gates/api_rules.py):
# the release is a major version and sdk/ts/CHANGELOG.md lists the symbol under
# Breaking, or the change is a new value of a protocol or manifest version constant
# within its major. So
# is each committed report under sdk/ts/api that is missing, differs from the code or
# belongs to no entry point: `python3 scripts/gates/api_diff.py ts --update` rewrites
# them. scripts/gates/api_diff.py runs tsc and API Extractor; the pinned API Extractor
# is checked by scripts/gates/node-tools.sh. --base-ref reaches only the baseline's own
# shrink check: the API is always compared with the release.
#
# Usage:  scripts/gates/gate-api-ts.sh [--base-ref REF]          check the tree
#         scripts/gates/gate-api-ts.sh record [--base-ref REF]   shrink the baseline
# A finding names a symbol, not a line, so an edit elsewhere never moves it. Its
# tool files are the API Extractor and TypeScript pins, which node-tools.sh passes,
# and the scripts passed with --tool-file below, which run tsc and API Extractor
# and read their output.

set -euo pipefail
cd "$(dirname "$0")/../.."
exec scripts/gates/node-tools.sh ratchet "scripts/gates/${0##*/}" api-extractor scripts/gates/baselines/api-ts.json \
  "$@" --tool-file scripts/gates/api-extractor.mjs --tool-file scripts/gates/api_diff.py \
  --tool-file scripts/gates/api_formats.py --tool-file scripts/gates/api_rules.py \
  -- python3 scripts/gates/api_diff.py ts
