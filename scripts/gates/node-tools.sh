#!/usr/bin/env bash
#
# The npm-installed tools of the gates, and the step those gates share
# (gate-ts-format.sh, gate-ts-lint.sh, gate-ts-types.sh and gate-duplication.sh).
#
# Each tool is pinned by a lockfile: biome and tsc by sdk/ts/package-lock.json, jscpd
# by scripts/gates/package-lock.json. tsc also reads the types of what the checked
# code imports, from gen/ts, scripts/sdk-types and website (the documentation site's
# module that the two reference-page scripts import, and the @bufbuild/protobuf it
# imports). tsc-projects.sh fails on an import that does not resolve, so each of
# them has to be installed. The package directories below are
# the one list of what the gates install, and each one has to hold exactly what its
# lockfile pins.
#
# Usage:
#   scripts/gates/node-tools.sh check
#       Exit 1 and print the install command unless each package directory's
#       node_modules holds exactly what its lockfile pins.
#   scripts/gates/node-tools.sh install
#       Run `npm ci --ignore-scripts` in each package directory
#       (.github/workflows/gates.yml runs this). No third-party install script runs.
#   scripts/gates/node-tools.sh ratchet GATE FORMAT BASELINE [record] [ARG...] -- CMD...
#       Run `check`, then CMD through ratchet.py for the gate script GATE, with
#       FORMAT and BASELINE, and the toolchain's TOOL_FILES. A first ARG of
#       `record` shrinks the baseline; the other ARGs, such as --base-ref REF and
#       the gate's own --tool-file FILE, go to ratchet.py.

set -euo pipefail
cd "$(dirname "$0")/../.."
source scripts/gates/tool-helper.sh

DIRS=(sdk/ts gen/ts scripts/sdk-types website scripts/gates)
# The tool files of the npm toolchain, which gate_ratchet passes for every gate that
# runs through this script: this script; biome and tsc by their pins in the SDK's
# manifest and their packages in its lock, with what only they bring (biome's
# platform binaries); and jscpd's manifest and lock, which pin nothing else. The
# rest of the SDK's manifest and lock, such as its own version and its dependencies,
# is not the tool: an edit to it re-keys nothing.
TOOL_FILES=(
  --tool-file scripts/gates/node-tools.sh
  --tool-file sdk/ts/package.json#devDependencies.@biomejs/biome
  --tool-file sdk/ts/package.json#devDependencies.typescript
  --tool-file sdk/ts/package-lock.json#packages.node_modules/@biomejs/biome
  --tool-file sdk/ts/package-lock.json#packages.node_modules/typescript
  --tool-file scripts/gates/package.json
  --tool-file scripts/gates/package-lock.json
)

check() {
  if ! command -v npm >/dev/null 2>&1; then
    gate_refuse node-tools.sh "npm is not installed" "Node.js 22, https://nodejs.org/"
  fi
  python3 scripts/gates/npm_installed.py "${DIRS[@]}" >&2 ||
    gate_refuse node-tools.sh "the gates' npm packages do not match their lockfiles"
}

usage="usage: $0 check|install|ratchet GATE FORMAT BASELINE [record] [ARG...] -- CMD..."
case "${1:-}" in
  check)
    check
    ;;
  install)
    for dir in "${DIRS[@]}"; do
      (cd "$dir" && npm ci --no-audit --no-fund --ignore-scripts)
    done
    ;;
  ratchet)
    [ "$#" -ge 4 ] || { echo "$usage" >&2; exit 2; }
    check
    shift
    gate_ratchet "$@"
    ;;
  *)
    echo "$usage" >&2
    exit 2
    ;;
esac
