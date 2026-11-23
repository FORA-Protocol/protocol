#!/usr/bin/env bash
#
# TypeScript format gate: `biome format` over the hand-written TypeScript and
# JavaScript that biome.jsonc includes, against scripts/gates/baselines/ts-format.json.
# A file the formatter would rewrite is a finding; `biome format --write` rewrites it.
# The pinned biome is checked by scripts/gates/node-tools.sh; the settings are in
# biome.jsonc.
#
# Usage:  scripts/gates/gate-ts-format.sh [--base-ref REF]   check the tree
#         scripts/gates/gate-ts-format.sh record             shrink the baseline

set -euo pipefail
cd "$(dirname "$0")/../.."
exec scripts/gates/node-tools.sh ratchet "scripts/gates/${0##*/}" biome scripts/gates/baselines/ts-format.json \
  "$@" -- sdk/ts/node_modules/.bin/biome format --reporter=json --max-diagnostics=none
