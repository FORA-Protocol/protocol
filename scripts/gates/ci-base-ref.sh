#!/usr/bin/env bash
#
# Print the commit a GitHub Actions run of the quality gates compares each baseline
# with (scripts/gates/run.sh --base-ref). .github/workflows/gates.yml runs it. Each
# base is fixed for its run, so a rerun of the job gives the same verdict:
#
# - a pull request: the base side (HEAD^1) of the merge commit GitHub checks out;
# - a push to main: BEFORE, the commit main pointed at before the push, so the check
#   covers every commit the push brought;
# - a release tag, when release.yml calls the workflow on the tag push: where the
#   tagged commit's history left origin/main (their merge base). For a commit on
#   main that is the commit itself, which passed main's check when it got there;
#   for a commit off main, every commit since it left main is compared.
#
# Anything else fails: a pull request checkout that is not a merge, a push whose
# BEFORE is missing, all zeros, or not an ancestor of HEAD (a force push), a commit
# with no parent, a tag run with no origin/main or no history shared with it, and an
# event or ref this script names no base for, so a new trigger gets its base on
# purpose.
#
# Reads GITHUB_EVENT_NAME and GITHUB_REF, which GitHub Actions sets, and BEFORE.
# Usage:  base=$(scripts/gates/ci-base-ref.sh)

set -euo pipefail
cd "$(dirname "$0")/../.." || exit 1

refuse() {
  echo "ci-base-ref.sh: $1" >&2
  exit 1
}

# first_parent WHY: print HEAD's first parent, or refuse with WHY.
first_parent() {
  git rev-parse --verify --quiet "HEAD^1" || refuse "$1"
}

event=${GITHUB_EVENT_NAME:-}
ref=${GITHUB_REF:-}
case "$event:$ref" in
  pull_request:*)
    git rev-parse --verify --quiet "HEAD^2" >/dev/null ||
      refuse "a pull request run checks out GitHub's merge commit, and HEAD is not a merge"
    first_parent "HEAD has no first parent"
    ;;
  push:refs/heads/main)
    before=${BEFORE:-}
    [ -n "${before//0/}" ] ||
      refuse "a push to main needs BEFORE, the commit main pointed at before the push"
    git merge-base --is-ancestor "$before" HEAD 2>/dev/null ||
      refuse "BEFORE $before is not an ancestor of HEAD here (a force push, or a shallow fetch)"
    git rev-parse --verify --quiet "$before^{commit}"
    ;;
  push:refs/tags/*)
    main=$(git rev-parse --verify --quiet "refs/remotes/origin/main^{commit}") ||
      refuse "a release tag is compared with origin/main, which is not fetched here"
    git merge-base HEAD "$main" ||
      refuse "the tagged commit shares no history with origin/main here (a shallow fetch)"
    ;;
  *)
    refuse "no base is named for the event '$event' on '$ref'"
    ;;
esac
