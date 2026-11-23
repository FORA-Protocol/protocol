#!/usr/bin/env bash
#
# TypeScript type gate: strict type checking of the hand-written TypeScript and
# JavaScript, one tsc run per project, against scripts/gates/baselines/ts-types.json:
#
#   sdk/ts/tsconfig.json          the SDK, its tests, examples and build script
#   sdk/ts/tsconfig.workers.json  the edge-safe modules, against the Workers types alone
#   gen/ts/tsconfig.tests.json    the hand-written tests of the generated types export
#   scripts/tsconfig.json         the repository's own scripts
#
# Every project runs with the tsc that sdk/ts/package-lock.json pins, which
# scripts/gates/node-tools.sh checks together with the packages tsc reads types from.
# scripts/gates/tsc-projects.sh runs the projects and tells a crashed tsc from one that
# reported diagnostics. The strictness settings are in tsconfig.strict.json.
#
# Usage:  scripts/gates/gate-ts-types.sh [--base-ref REF]          check the tree
#         scripts/gates/gate-ts-types.sh record [--base-ref REF]   shrink the baseline
# record carries the entry of a finding that moved; with --base-ref, also across a
# renamed or copied file, and across a change to a tsconfig it checks, or the TypeScript pin
# (sdk/ts/package.json, locked in sdk/ts/package-lock.json): the gate's tool files
# (--tool-file).

set -euo pipefail
cd "$(dirname "$0")/../.."
exec scripts/gates/node-tools.sh ratchet "scripts/gates/${0##*/}" tsc scripts/gates/baselines/ts-types.json \
  "$@" --tool-file scripts/gates/tsc-projects.sh --tool-file scripts/gates/node-tools.sh \
  --tool-file sdk/ts/package.json --tool-file sdk/ts/package-lock.json \
  --tool-file sdk/ts/tsconfig.json --tool-file sdk/ts/tsconfig.workers.json \
  --tool-file gen/ts/tsconfig.tests.json --tool-file scripts/tsconfig.json \
  -- scripts/gates/tsc-projects.sh sdk/ts/node_modules/.bin/tsc \
  sdk/ts/tsconfig.json sdk/ts/tsconfig.workers.json gen/ts/tsconfig.tests.json scripts/tsconfig.json
