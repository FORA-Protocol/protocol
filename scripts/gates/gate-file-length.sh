#!/usr/bin/env bash
#
# File-length gate: every hand-written Go, Python, TypeScript and JavaScript file,
# tests included, against its language's line limit, and against
# scripts/gates/baselines/file-length.json. A baselined file may shrink; the gate
# fails if it grows. scripts/gates/file_length.py holds the limits and lists the
# files over them.
#
# Usage:  scripts/gates/gate-file-length.sh [--base-ref REF]          check the tree
#         scripts/gates/gate-file-length.sh record [--base-ref REF]   shrink the baseline
# record carries the entry of a finding that moved; with --base-ref, also across a
# renamed or copied file, and across a change to file_length.py, the gate's
# tool file (--tool-file).

set -euo pipefail
cd "$(dirname "$0")/../.."
exec python3 scripts/gates/ratchet.py --format lines --gate "scripts/gates/${0##*/}" \
  --baseline scripts/gates/baselines/file-length.json "$@" \
  --tool-file scripts/gates/file_length.py -- \
  python3 scripts/gates/file_length.py
