#!/usr/bin/env bash
#
# Scope gate: every hand-written file is read by every gate of its language, and
# no gate reads generated code. scripts/gates/scope.py defines the hand-written
# code, the one list of generated code and the gates of each language;
# scripts/gates/scope_coverage.py asks each gate's tool which files it reads and
# says, for each tool, how. The gate has no baseline: a file outside a gate, or a
# generated file inside one, fails the build.
#
# Usage:  scripts/gates/gate-scope.sh   (takes no arguments; --base-ref is accepted
#         and ignored, because run.sh passes its arguments to every gate)

set -euo pipefail
cd "$(dirname "$0")/../.."
scripts/gates/go-tools.sh check
scripts/gates/python-tools.sh check
scripts/gates/node-tools.sh check
exec python3 scripts/gates/scope_coverage.py
