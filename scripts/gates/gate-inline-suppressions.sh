#!/usr/bin/env bash
#
# Inline-suppression gate: every inline suppression in the hand-written code, in each
# form scripts/gates/inline_suppressions.py recognizes, against
# scripts/gates/baselines/inline-suppressions.json. AGENTS.md forbids adding one: an
# exclusion goes in the tool's config, with its reason.
#
# Usage:  scripts/gates/gate-inline-suppressions.sh [--base-ref REF]          check the tree
#         scripts/gates/gate-inline-suppressions.sh record [--base-ref REF]   shrink the baseline
# A suppression's entry moves with its line within its file, never to another file;
# with --base-ref, record carries it to its file's new name when git sees the file
# renamed, and across a change of the gate's tool alone: the scanner passed with
# --tool-file below, or the reader in formats.py.

set -euo pipefail
cd "$(dirname "$0")/../.."
exec python3 scripts/gates/ratchet.py --format suppressions --gate "scripts/gates/${0##*/}" \
  --baseline scripts/gates/baselines/inline-suppressions.json "$@" \
  --tool-file scripts/gates/inline_suppressions.py -- \
  python3 scripts/gates/inline_suppressions.py
