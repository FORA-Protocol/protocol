#!/usr/bin/env bash
#
# Go format gate: the formatters .golangci.yml enables, over every hand-written Go
# file of the module, against the shrink-only baseline
# scripts/gates/baselines/go-format.json. A file the formatters would rewrite is a
# finding; `golangci-lint fmt ./...` rewrites it.
#
# Usage:  scripts/gates/gate-go-format.sh [--base-ref REF]   check the tree
#         scripts/gates/gate-go-format.sh record             shrink the baseline

set -euo pipefail
cd "$(dirname "$0")/../.."
exec scripts/gates/go-tools.sh ratchet "scripts/gates/${0##*/}" golangci-lint-fmt scripts/gates/baselines/go-format.json \
  "$@" -- golangci-lint fmt --diff ./...
