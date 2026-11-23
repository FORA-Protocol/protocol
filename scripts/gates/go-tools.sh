#!/usr/bin/env bash
#
# The Go gates' tools, pinned in one place, and the step the Go gates share.
# golangci-lint carries its own formatters, so its one pin covers the formatters
# .golangci.yml enables as well as its linters. apidiff, which the Go SDK's API gate
# (gate-api-go.sh) runs, is a command of golang.org/x/exp, a module with no
# releases, so it is pinned to a pseudo-version: one commit of that module.
#
# Usage:
#   scripts/gates/go-tools.sh check
#       Exit 1 and print the install command unless the pinned golangci-lint
#       and apidiff are on PATH. apidiff prints no version, so its version is read
#       from the module build information that `go version -m` prints.
#   scripts/gates/go-tools.sh install
#       Install the pinned golangci-lint and apidiff (.github/workflows/gates.yml
#       runs this).
#   scripts/gates/go-tools.sh ratchet GATE FORMAT BASELINE [record] [ARG...] -- CMD...
#       Run `check`, then CMD through ratchet.py for the gate script GATE, with
#       FORMAT and BASELINE, and the toolchain's TOOL_FILES. A first ARG of
#       `record` shrinks the baseline; the other ARGs, such as --base-ref REF and
#       the gate's own --tool-file FILE, go to ratchet.py.
#       gate-go-format.sh, gate-go-lint.sh and gate-api-go.sh run this.

set -euo pipefail
cd "$(dirname "$0")/../.."
source scripts/gates/tool-helper.sh

GOLANGCI_LINT_VERSION=2.12.2
GOLANGCI_LINT_MODULE=github.com/golangci/golangci-lint/v2/cmd/golangci-lint
# The tool files of the Go toolchain, which gate_ratchet passes for every Go gate:
# this script, which holds the pins.
TOOL_FILES=(
  --tool-file scripts/gates/go-tools.sh
)
APIDIFF_VERSION=v0.0.0-20261106192419-47ce03d25ef0
APIDIFF_MODULE=golang.org/x/exp/cmd/apidiff

check() {
  local have
  have=$(golangci-lint version --short 2>/dev/null || echo 'not installed')
  if [ "$have" != "$GOLANGCI_LINT_VERSION" ]; then
    gate_refuse go-tools.sh "golangci-lint is ${have}, the Go gates pin ${GOLANGCI_LINT_VERSION}"
  fi
  have=$(apidiff_version)
  if [ "$have" != "$APIDIFF_VERSION" ]; then
    gate_refuse go-tools.sh "apidiff is ${have}, the Go gates pin ${APIDIFF_VERSION}"
  fi
}

# apidiff_version: print the golang.org/x/exp version the apidiff on PATH was built
# from, `not installed`, or `of an unknown version` when `go version -m` names none.
apidiff_version() {
  local bin info version
  if ! bin=$(command -v apidiff); then
    echo 'not installed'
    return
  fi
  info=$(go version -m "$bin" 2>/dev/null) || info=''
  version=$(printf '%s\n' "$info" | awk '$1 == "mod" && $2 == "golang.org/x/exp" { print $3 }')
  echo "${version:-of an unknown version}"
}

usage="usage: $0 check|install|ratchet GATE FORMAT BASELINE [record] [ARG...] -- CMD..."
case "${1:-}" in
  check)
    check
    ;;
  install)
    go install "${GOLANGCI_LINT_MODULE}@v${GOLANGCI_LINT_VERSION}"
    go install "${APIDIFF_MODULE}@${APIDIFF_VERSION}"
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
