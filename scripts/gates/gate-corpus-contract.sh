#!/usr/bin/env bash
#
# Corpus-contract gate: every conformance corpus against the rules of ADR-002
# (docs/architecture/adr-002-conformance-corpora.md) that a program can check, read
# through the registry sdk/parity/corpora.json, and against
# scripts/gates/baselines/corpus-contract.json. scripts/gates/corpus_contract.py lists
# the rules. The baseline holds the case lists not yet on the one outcome format, each
# at its number of rows without an outcome: it may shrink, and the gate fails if a
# case list gains such a row.
#
# Usage:  scripts/gates/gate-corpus-contract.sh [--base-ref REF]          check the tree
#         scripts/gates/gate-corpus-contract.sh record [--base-ref REF]   shrink the baseline
# The scanner's modules are the gate's tool files (--tool-file).

set -euo pipefail
cd "$(dirname "$0")/../.."
exec python3 scripts/gates/ratchet.py --format lines --gate "scripts/gates/${0##*/}" \
  --baseline scripts/gates/baselines/corpus-contract.json "$@" \
  --tool-file scripts/gates/corpus_contract.py --tool-file scripts/gates/corpora.py \
  --tool-file scripts/gates/corpus_replay.py --tool-file scripts/gates/corpus_vocabulary.py -- \
  python3 scripts/gates/corpus_contract.py
