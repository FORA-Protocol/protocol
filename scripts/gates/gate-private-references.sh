#!/usr/bin/env bash
#
# Private-reference gate: every tracked text file, the documentation site and the
# generated code included, against scripts/gates/baselines/private-references.json.
# This repository is public, so no tracked file may name a private tracker or its
# keys, a private repository, a developer's home directory, or a path into the
# services' repository. scripts/gates/private_references.py holds the kinds and
# ALLOWED, the one place a deliberate exception goes, each with its reason. The
# baseline is empty and stays empty.
#
# Usage:  scripts/gates/gate-private-references.sh [--base-ref REF]   check the tree
#         scripts/gates/gate-private-references.sh record             shrink the baseline

set -euo pipefail
cd "$(dirname "$0")/../.."
exec python3 scripts/gates/ratchet.py --format lines --gate "scripts/gates/${0##*/}" \
  --baseline scripts/gates/baselines/private-references.json "$@" \
  --tool-file scripts/gates/private_references.py -- \
  python3 scripts/gates/private_references.py
