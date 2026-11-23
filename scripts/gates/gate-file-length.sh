#!/usr/bin/env bash
#
# File-length gate: every hand-written Go, Python, TypeScript and JavaScript file,
# tests included, against its language's line limit, and against
# scripts/gates/baselines/file-length.json. A baselined file may shrink; the gate
# fails if it grows. scripts/gates/file_length.py holds the limits and lists the
# files over them.
#
# Usage:  scripts/gates/gate-file-length.sh [--base-ref REF]   check the tree
#         scripts/gates/gate-file-length.sh record             shrink the baseline

set -euo pipefail
cd "$(dirname "$0")/../.."
exec python3 scripts/gates/ratchet.py --format lines --gate "scripts/gates/${0##*/}" \
  --baseline scripts/gates/baselines/file-length.json "$@" -- \
  python3 scripts/gates/file_length.py
