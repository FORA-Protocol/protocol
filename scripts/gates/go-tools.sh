#!/usr/bin/env bash
#
# The Go gates' tool, pinned in one place, and the step both Go gates share.
# golangci-lint carries its own formatters, so this one pin covers the formatters
# .golangci.yml enables as well as its linters.
#
# Usage:
#   scripts/gates/go-tools.sh check
#       Exit 1 and print the install command unless the pinned golangci-lint
#       is on PATH.
#   scripts/gates/go-tools.sh install
#       Install the pinned golangci-lint (.github/workflows/gates.yml runs this).
#   scripts/gates/go-tools.sh ratchet GATE FORMAT BASELINE [record] [ARG...] -- CMD...
#       Run `check`, then CMD through ratchet.py for the gate script GATE, with
#       FORMAT and BASELINE. A first ARG of `record` shrinks the baseline; the
#       other ARGs, such as --base-ref REF, go to ratchet.py. gate-go-format.sh
#       and gate-go-lint.sh run this.

set -euo pipefail
cd "$(dirname "$0")/../.."
source scripts/gates/tool-helper.sh

GOLANGCI_LINT_VERSION=2.12.2
GOLANGCI_LINT_MODULE=github.com/golangci/golangci-lint/v2/cmd/golangci-lint

check() {
  local have
  have=$(golangci-lint version --short 2>/dev/null || echo 'not installed')
  if [ "$have" != "$GOLANGCI_LINT_VERSION" ]; then
    gate_refuse go-tools.sh "golangci-lint is ${have}, the Go gates pin ${GOLANGCI_LINT_VERSION}"
  fi
}

usage="usage: $0 check|install|ratchet GATE FORMAT BASELINE [record] [ARG...] -- CMD..."
case "${1:-}" in
  check)
    check
    ;;
  install)
    go install "${GOLANGCI_LINT_MODULE}@v${GOLANGCI_LINT_VERSION}"
    ;;
  ratchet)
    [ "$#" -ge 4 ] || { echo "$usage" >&2; exit 2; }
    check
    GOLANGCI_LINT_CACHE=$(golangci_lint_cache)
    export GOLANGCI_LINT_CACHE
    shift
    gate_ratchet "$@"
    ;;
  *)
    echo "$usage" >&2
    exit 2
    ;;
esac
