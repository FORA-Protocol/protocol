#!/usr/bin/env bash
#
# Run TSC over each PROJECT with --noEmit and print every project's diagnostics on
# stdout, as one report for the tsc format of ratchet.py. gate-ts-types.sh runs it.
#
# tsc 6.0.3 with --noEmit exits 2 when it reports diagnostics. A non-zero exit counts
# as "tsc ran and reported diagnostics" only when that project's stdout holds at
# least one `error TS` line. Any other non-zero exit means the project was not
# checked: Node exits 1 on an uncaught exception and writes nothing to stdout. This
# script then stops at once with exit code 3, which ratchet.py's tsc format refuses,
# whatever code tsc exited with: a crash that exits 2 after an earlier project
# printed diagnostics must not read as a run that found something. Otherwise it
# exits with the highest code it saw, and the tsc format decides which it accepts.
#
# Usage:  scripts/gates/tsc-projects.sh TSC PROJECT...

set -uo pipefail
[ "$#" -ge 2 ] || { echo "usage: $0 TSC PROJECT..." >&2; exit 2; }
tsc=$1
shift

rc=0
for project in "$@"; do
  out=$("$tsc" -p "$project" --noEmit --pretty false)
  code=$?
  [ -z "$out" ] || printf '%s\n' "$out"
  [ "$code" -eq 0 ] && continue
  if ! grep -q 'error TS' <<<"$out"; then
    echo "tsc-projects.sh: tsc exited ${code} on ${project} and reported no diagnostic, so it did not check the project" >&2
    exit 3
  fi
  [ "$code" -le "$rc" ] || rc=$code
done
exit "$rc"
