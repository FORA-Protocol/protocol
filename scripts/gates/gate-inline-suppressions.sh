#!/usr/bin/env bash
#
# Inline-suppression gate: every inline suppression in the hand-written code, in each
# form scripts/gates/inline_suppressions.py recognizes, against
# scripts/gates/baselines/inline-suppressions.json. AGENTS.md forbids adding one: an
# exclusion goes in the tool's config, with its reason.
#
# Usage:  scripts/gates/gate-inline-suppressions.sh [--base-ref REF]   check the tree
#         scripts/gates/gate-inline-suppressions.sh record             shrink the baseline

set -euo pipefail
cd "$(dirname "$0")/../.."
exec python3 scripts/gates/ratchet.py --format lines --gate "scripts/gates/${0##*/}" \
  --baseline scripts/gates/baselines/inline-suppressions.json "$@" -- \
  python3 scripts/gates/inline_suppressions.py
