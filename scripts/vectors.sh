#!/usr/bin/env bash
#
# Regenerate the committed conformance corpora from their Go emitters.
#
# An emitter only compares: when a committed corpus differs from what its emitter
# renders, the emitter writes the rendering beside the corpus as <corpus>.got and
# fails (sdk/go/internal/vectorio). This script runs the Go SDK's tests and moves every
# .got file over its corpus, round after round, because an emitter that checks several
# corpora stops at the first one that differs. It stops when a round leaves no .got
# file, and then runs the tests once more.
#
# The rounds are bounded by the number of corpus files the registry lists, plus one:
# a deterministic emitter needs at most one round per corpus it checks. A .got file
# still there after the last round comes from an emitter whose rendering changes from
# run to run; the script names it and fails, leaving it in place to compare.
#
# It also fails when a round's tests fail without leaving a .got file (the failure is
# not a stale corpus), and when the last run fails.
#
# Usage:  scripts/vectors.sh
# Exit:   0 = every corpus matches its emitter; 1 = otherwise.

set -euo pipefail
cd "$(dirname "$0")/.."

gots() { find sdk/go -name '*.got' -type f -print0; }

# corpus_files prints the number of corpus files the registry lists.
corpus_files() {
  python3 -c 'import json, sys
doc = json.load(open("sdk/parity/corpora.json"))
print(len({c["file"] for c in doc["corpora"].values()}))'
}

# move_gots moves every .got file over its corpus and prints how many it moved.
move_gots() {
  local moved=0 got
  while IFS= read -r -d '' got; do
    # Overwrite in place, so the committed file keeps its mode.
    cat "$got" >"${got%.got}"
    rm "$got"
    echo "vectors: updated ${got%.got}" >&2
    moved=$((moved + 1))
  done < <(gots)
  echo "$moved"
}

# A .got file from an earlier run is not this run's rendering.
gots | xargs -0 rm -f

max_rounds=$(($(corpus_files) + 1))
total=0
for ((round = 1; ; round++)); do
  status=0
  go test -count=1 ./sdk/go/... >/dev/null || status=$?
  if [ -z "$(find sdk/go -name '*.got' -type f -print -quit)" ]; then
    if [ "$status" -ne 0 ]; then
      echo "vectors: the Go tests failed without a stale corpus; fix that failure first" >&2
      go test -count=1 ./sdk/go/... >&2
      exit 1
    fi
    break
  fi
  if [ "$round" -ge "$max_rounds" ]; then
    echo "vectors: after $max_rounds rounds these emitters still render something new;" \
      "a non-deterministic emitter writes a different corpus each run:" >&2
    gots | xargs -0 -n1 echo "  " >&2
    exit 1
  fi
  total=$((total + $(move_gots)))
done

go test -count=1 ./sdk/go/... ./conformance/...
echo "vectors: $total corpus file(s) updated; every corpus matches its emitter"
