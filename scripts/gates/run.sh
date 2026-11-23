#!/usr/bin/env bash
#
# Run the gate tooling's own tests, then every quality gate, each through
# scripts/gates/ratchet.py and its shrink-only baseline.
#
# A gate is one executable file named scripts/gates/gate-<name>.sh. This script
# finds them; nothing lists them by hand. Each gate receives the arguments given
# here, so `--base-ref REF` reaches every ratchet check.
#
# A gate whose tool is missing fails and prints the install command; it is never
# skipped, because a skipped gate reports the same as a passing one. The SDK API
# gates (gate-api-*.sh) compare against the last release tag, so they fail, and
# say how to fetch the tags, in a clone without them.
#
# Usage:  scripts/gates/run.sh [--base-ref REF]
# Exit:   0 = every gate passes; 1 = at least one failed.

set -uo pipefail
cd "$(dirname "$0")/../.."

fail=0
printf '\n\033[1m==> gate tooling tests\033[0m\n'
# A passing run prints only the summary; a failing one prints everything, so the
# failing test's name and traceback are in the log.
if out=$(python3 -m unittest discover -s scripts/gates -p 'test_*.py' 2>&1); then
  printf '%s\n' "$out" | tail -n 3
else
  printf '%s\n' "$out"
  fail=1
fi

for gate in scripts/gates/gate-*.sh; do
  [ -e "$gate" ] || continue
  printf '\n\033[1m==> %s\033[0m\n' "$(basename "$gate" .sh)"
  "$gate" "$@" || fail=1
done

exit "$fail"
