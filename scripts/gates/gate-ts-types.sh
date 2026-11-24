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
# reported diagnostics. The strictness settings are in tsconfig.strict.json, which the
# projects extend; gen/ts/tsconfig.tests.json also extends gen/ts/tsconfig.json. Each
# project and each file it extends is a --tool-file below (test_gate_scripts.py holds
# that), and so are the type packages tsc reads the runtime's types from, by their pin
# in sdk/ts/package.json and their package in its lockfile (test_tool_parts.py holds
# that a tool a lockfile pins is named in the manifest beside it too).
#
# Usage:  scripts/gates/gate-ts-types.sh [--base-ref REF]          check the tree
#         scripts/gates/gate-ts-types.sh record [--base-ref REF]   shrink the baseline
# record carries the entry of a finding that moved; with --base-ref, also across a
# renamed or copied file, and across a change of the gate's tool alone: a file passed
# with --tool-file below, a pin that node-tools.sh passes, or the reader in formats.py.

set -euo pipefail
cd "$(dirname "$0")/../.."
exec scripts/gates/node-tools.sh ratchet "scripts/gates/${0##*/}" tsc scripts/gates/baselines/ts-types.json \
  "$@" --tool-file scripts/gates/tsc-projects.sh \
  --tool-file tsconfig.strict.json --tool-file gen/ts/tsconfig.json \
  --tool-file sdk/ts/tsconfig.json --tool-file sdk/ts/tsconfig.workers.json \
  --tool-file gen/ts/tsconfig.tests.json --tool-file scripts/tsconfig.json \
  --tool-file sdk/ts/package.json#devDependencies.@types/node \
  --tool-file sdk/ts/package-lock.json#packages.node_modules/@types/node \
  --tool-file sdk/ts/package.json#devDependencies.@cloudflare/workers-types \
  --tool-file sdk/ts/package-lock.json#packages.node_modules/@cloudflare/workers-types \
  -- scripts/gates/tsc-projects.sh sdk/ts/node_modules/.bin/tsc \
  sdk/ts/tsconfig.json sdk/ts/tsconfig.workers.json gen/ts/tsconfig.tests.json scripts/tsconfig.json
