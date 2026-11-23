#!/usr/bin/env bash
#
# TypeScript lint gate: biome's linter and its organize-imports assist over the
# hand-written TypeScript and JavaScript that biome.jsonc includes, against
# scripts/gates/baselines/ts-lint.json. Every diagnostic, info-level ones included, is
# a finding. Formatting findings are left to gate-ts-format.sh. The pinned biome is
# checked by scripts/gates/node-tools.sh; the rule set is in biome.jsonc.
#
# Usage:  scripts/gates/gate-ts-lint.sh [--base-ref REF]   check the tree
#         scripts/gates/gate-ts-lint.sh record             shrink the baseline

set -euo pipefail
cd "$(dirname "$0")/../.."
exec scripts/gates/node-tools.sh ratchet "scripts/gates/${0##*/}" biome scripts/gates/baselines/ts-lint.json \
  "$@" -- sdk/ts/node_modules/.bin/biome check --formatter-enabled=false \
  --reporter=json --max-diagnostics=none --error-on-warnings
