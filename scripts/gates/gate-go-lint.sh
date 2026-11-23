#!/usr/bin/env bash
#
# Go lint gate: the linters in .golangci.yml over every hand-written Go package
# of the module and its tests, the corpus emitters included, against the
# shrink-only baseline scripts/gates/baselines/go-lint.json. Formatting findings
# are left to gate-go-format.sh.
#
# Usage:  scripts/gates/gate-go-lint.sh [--base-ref REF]   check the tree
#         scripts/gates/gate-go-lint.sh record             shrink the baseline

set -euo pipefail
cd "$(dirname "$0")/../.."
exec scripts/gates/go-tools.sh ratchet "scripts/gates/${0##*/}" golangci-lint scripts/gates/baselines/go-lint.json \
  "$@" -- golangci-lint run --output.json.path=stdout --show-stats=false ./...
