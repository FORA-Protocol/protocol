#!/usr/bin/env bash
#
# Duplication gate: jscpd over the tracked hand-written files scripts/gates/scope.py
# lists, with the settings in .jscpd.json, against
# scripts/gates/baselines/duplication.json.
#
# A clone is identified by its two files and a hash of the duplicated text, not by its
# lines, so a clone that moves within its files keeps its baseline entry (see
# parse_jscpd in scripts/gates/formats.py). The pinned jscpd is checked by
# scripts/gates/node-tools.sh; scripts/gates/jscpd-report.sh passes it the files and
# refuses a run that wrote no report.
#
# Usage:  scripts/gates/gate-duplication.sh [--base-ref REF]   check the tree
#         scripts/gates/gate-duplication.sh record             shrink the baseline

set -euo pipefail
cd "$(dirname "$0")/../.."
exec scripts/gates/node-tools.sh ratchet "scripts/gates/${0##*/}" jscpd scripts/gates/baselines/duplication.json \
  "$@" -- scripts/gates/jscpd-report.sh scripts/gates/node_modules/.bin/jscpd
