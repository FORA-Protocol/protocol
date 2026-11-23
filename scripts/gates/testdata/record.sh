#!/usr/bin/env bash
#
# Record the tool samples the gate tests read, with the repository's own configs
# and the pinned tools.
#
# The sources the samples are recorded from are in scripts/gates/testdata/planted/,
# each at its repository path with a .txt suffix added, so that no gate reads them.
# This script copies each one to its repository path, runs each tool over those
# copies with the options its gate passes, writes the samples into
# scripts/gates/testdata/, and deletes the copies.
# The repository's absolute path, which some tools print, is written as {root}.
#
# The API gates compare two versions of an SDK, so their samples are recorded in a
# throwaway clone of HEAD, with this checkout's gate scripts and installed tools: the
# sources in scripts/gates/testdata/api/old/ are committed there and tagged v999.0.0,
# a tag above any release, so api_diff.py compares against them; the sources in
# scripts/gates/testdata/api/new/ are committed over them, and api_diff.py prints
# what each SDK's tool reports. Each pair plants, in one SDK package, a removal, a
# rename, a changed signature, an addition and a deprecated alias.
#
# Usage:  scripts/gates/testdata/record.sh
#         (run it after a tool or a config changes, and commit the samples)

set -uo pipefail
cd "$(dirname "$0")/../../.."
root=$(pwd)
data=scripts/gates/testdata
planted=$data/planted

targets=()
while IFS= read -r -d '' source; do
  targets+=("${source#"$planted"/}")
done < <(find "$planted" -type f -name '*.txt' -print0 | sort -z)
for i in "${!targets[@]}"; do
  targets[i]=${targets[i]%.txt}
  if [ -e "${targets[i]}" ]; then
    echo "record.sh: ${targets[i]} exists; it would be overwritten and deleted" >&2
    exit 1
  fi
done

# Delete the copies, and each directory the copying created once it is empty.
api_dir=''
cleanup() {
  local target
  [ -z "$api_dir" ] || rm -rf "$api_dir"
  for target in "${targets[@]}"; do
    rm -f "$target"
    rmdir -p "$(dirname "$target")" 2>/dev/null
  done
}
trap cleanup EXIT
for target in "${targets[@]}"; do
  mkdir -p "$(dirname "$target")"
  cp "$planted/$target.txt" "$target"
done

# Run a tool, with its stdout written to the sample $1, the repository root
# written as {root}, and the values that change on every run (biome's timings,
# jscpd's detection date) written as 0, so that recording again with the same
# tools and configs reproduces the committed samples byte for byte. A tool exits
# non-zero when it reports a finding, so only an exit code above $2 fails the
# recording.
sample() {
  local out=$1 max=$2 code
  shift 2
  "$@" >"$data/$out.tmp"
  code=$?
  if [ "$code" -gt "$max" ]; then
    echo "record.sh: $* exited $code" >&2
    exit 1
  fi
  python3 - "$data/$out.tmp" "$root" <<'PY'
import re
import sys

path, root = sys.argv[1:]
text = open(path).read().replace(root, "{root}")
text = re.sub(r'"(duration|scannerDuration)":\d+', r'"\1":0', text)
text = re.sub(r'"detectionDate": "[^"]*"', '"detectionDate": "0"', text)
open(path, "w").write(text)
PY
  mv "$data/$out.tmp" "$data/$out"
}

scripts/gates/go-tools.sh check || exit 1
scripts/gates/node-tools.sh check || exit 1
source scripts/gates/tool-helper.sh
GOLANGCI_LINT_CACHE=$(golangci_lint_cache)
export GOLANGCI_LINT_CACHE
sample golangci-lint-run.json 1 golangci-lint run --allow-parallel-runners \
  --output.json.path=stdout --show-stats=false ./planted
sample golangci-lint-fmt.diff 1 golangci-lint fmt --diff ./planted

venv=sdk/python/.venv/bin
sample ruff-check.json 1 "$venv/ruff" check --no-fix --output-format json \
  scripts/zz_planted.py scripts/zz_broken.py
sample ruff-format.json 1 "$venv/ruff" format --check --output-format json scripts/zz_unformatted.py
sample mypy.jsonl 1 "$venv/mypy" --config-file mypy.ini --output json scripts/zz_planted.py

bin=sdk/ts/node_modules/.bin
sample biome-report.json 1 "$bin/biome" check --reporter=json --max-diagnostics=none \
  --error-on-warnings sdk/ts/tests/zz-sample.ts
sample tsc-report.txt 2 "$bin/tsc" -p sdk/ts/tsconfig.json --noEmit --pretty false
sample tsc-config-error.txt 1 "$bin/tsc" -p sdk/ts/no-such.json --noEmit --pretty false

report=$(mktemp -d)
scripts/gates/node_modules/.bin/jscpd --config .jscpd.json --reporters json --output "$report" --silent \
  planted/clones sdk/ts/tests/zz-clone-a.ts sdk/ts/tests/zz-clone-b.ts >&2
sample jscpd-report.json 0 cat "$report/jscpd-report.json"
rm -rf "$report"

api_dir=$(mktemp -d)
clone=$api_dir/repo
git clone -q --shared . "$clone"
cp scripts/gates/*.py "$clone/scripts/gates/"
# The installed tools, linked in and kept out of the clone's commits.
for linked in sdk/python/.venv sdk/ts/node_modules scripts/gates/node_modules; do
  ln -s "$root/$linked" "$clone/$linked"
  echo "/$linked" >>"$clone/.git/info/exclude"
done
# api_commit SIDE: copy testdata/api/SIDE into the clone at their repository paths,
# and commit them.
api_commit() {
  local source
  while IFS= read -r -d '' source; do
    source=${source#"$data/api/$1/"}
    mkdir -p "$clone/$(dirname "$source")"
    cp "$data/api/$1/$source" "$clone/${source%.txt}"
  done < <(find "$data/api/$1" -type f -name '*.txt' -print0)
  git -C "$clone" add -A
  git -C "$clone" -c user.name=record -c user.email=record@test.invalid commit -q -m "$1"
}
api_commit old
git -C "$clone" tag v999.0.0
api_commit new
sample apidiff.txt 0 python3 "$clone/scripts/gates/api_diff.py" go
