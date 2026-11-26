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
# An import that does not resolve also stops the script with exit code 3: tsc
# reports it (TS2307, TS2792, or TS7016 for a module with no types) and then reads
# everything the module provides as `any`, so every check that depends on those
# types passes unseen. Such a run did not check the project as written, and it
# would give a different report wherever the package is installed. The packages the
# projects import are installed by scripts/gates/node-tools.sh.
#
# tsc reports an import with no types (TS7016) only under noImplicitAny, and reads
# an untyped parameter as `any` without it. So before it checks a project that
# checks JavaScript (allowJs or checkJs), this script reads the project's resolved
# settings (`tsc --showConfig`) and stops with exit code 3 unless noImplicitAny is
# true, set directly or through strict. A project's own default is not counted: the
# setting has to be written, so a compiler upgrade cannot change it.
#
# A file can be checked by two projects, as a root file of one and an import of
# another. A diagnostic that two projects report word for word, with its indented
# elaboration lines, is one finding, so it is printed once, where it first occurs.
#
# Usage:  scripts/gates/tsc-projects.sh TSC PROJECT...

set -uo pipefail
[ "$#" -ge 2 ] || { echo "usage: $0 TSC PROJECT..." >&2; exit 2; }
tsc=$1
shift

# Exit 0 when the --showConfig output on stdin holds noImplicitAny, or checks no
# JavaScript; any other exit, output that is not its JSON included, refuses.
holds_noimplicitany() {
  python3 -c '
import json, sys
options = json.load(sys.stdin)["compilerOptions"]
javascript = options.get("allowJs") or options.get("checkJs")
no_implicit_any = options.get("noImplicitAny", options.get("strict"))
sys.exit(1 if javascript and no_implicit_any is not True else 0)'
}

# Print each diagnostic in the tsc output on stdin that the file $1 does not hold,
# and add it there. A diagnostic is its `path(line,col): error` line and the
# indented lines that follow it.
print_new() {
  python3 -c '
import sys
with open(sys.argv[1], encoding="utf-8") as f:
    seen = set(f.read().split("\0"))
blocks = []
for line in sys.stdin.read().splitlines():
    if line.startswith(" ") and blocks:
        blocks[-1] += "\n" + line
    else:
        blocks.append(line)
with open(sys.argv[1], "a", encoding="utf-8") as f:
    for block in blocks:
        if block not in seen:
            seen.add(block)
            print(block)
            f.write(block + "\0")' "$1"
}

seen=$(mktemp) || exit 3
trap 'rm -f "$seen"' EXIT
rc=0
for project in "$@"; do
  if ! config=$("$tsc" -p "$project" --showConfig); then
    echo "tsc-projects.sh: tsc --showConfig failed on ${project}" >&2
    exit 3
  fi
  if ! holds_noimplicitany <<<"$config"; then
    echo "tsc-projects.sh: ${project} checks JavaScript (allowJs or checkJs) but does not set noImplicitAny, directly or through strict, so an untyped import would read as any" >&2
    exit 3
  fi
  out=$("$tsc" -p "$project" --noEmit --pretty false)
  code=$?
  if [ -n "$out" ] && ! print_new "$seen" <<<"$out"; then
    echo "tsc-projects.sh: could not print the diagnostics of ${project}" >&2
    exit 3
  fi
  if unresolved=$(grep -E ': error TS(2307|2792|7016): ' <<<"$out"); then
    printf '%s\n' "$unresolved" >&2
    echo "tsc-projects.sh: an import in ${project} does not resolve, so tsc read it as any; install the gates' npm packages (scripts/gates/node-tools.sh install)" >&2
    exit 3
  fi
  [ "$code" -eq 0 ] && continue
  if ! grep -q 'error TS' <<<"$out"; then
    echo "tsc-projects.sh: tsc exited ${code} on ${project} and reported no diagnostic, so it did not check the project" >&2
    exit 3
  fi
  [ "$code" -le "$rc" ] || rc=$code
done
exit "$rc"
