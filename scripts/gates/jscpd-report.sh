#!/usr/bin/env bash
#
# Run JSCPD over the tracked hand-written files, with the settings in .jscpd.json, and
# print its JSON report on stdout, for the jscpd format of ratchet.py.
# gate-duplication.sh runs it, and scope_coverage.py runs it to see what the
# duplication gate reads.
#
# The files are the ones `scripts/gates/scope.py files` lists, in the languages
# .jscpd.json formats, passed to jscpd by name: an untracked file is never read, and
# generated code is left out by the one list scope.py holds.
#
# jscpd writes its report to a directory, not to stdout, and exits 1 both when it
# finds clones and when it crashes. The report tells the two apart: a run that read
# its files writes one, and a crash writes none. With no report this script exits 2,
# which the jscpd format refuses, so the silence is never read as zero clones.
# Otherwise it exits with jscpd's code.
#
# Usage:  scripts/gates/jscpd-report.sh JSCPD

set -uo pipefail
[ "$#" -eq 1 ] || { echo "usage: $0 JSCPD" >&2; exit 2; }
jscpd=$1

listed=$(python3 scripts/gates/scope.py files --language go --language python \
  --language typescript --language javascript --language shell) || exit 2
[ -n "$listed" ] || { echo "jscpd-report.sh: scope.py listed no file" >&2; exit 2; }
files=()
while IFS= read -r f; do files+=("$f"); done <<<"$listed"

out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
"$jscpd" --config .jscpd.json --reporters json --output "$out" --silent "${files[@]}" >&2
rc=$?
if [ ! -s "$out/jscpd-report.json" ]; then
  echo "jscpd-report.sh: jscpd exited ${rc} and wrote no report" >&2
  exit 2
fi
cat "$out/jscpd-report.json"
exit "$rc"
