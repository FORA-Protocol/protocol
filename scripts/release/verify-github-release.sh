#!/usr/bin/env bash
# Read the GitHub Release back: it is marked as a prerelease exactly when the tag
# is one (scripts/release/version.py). build.sh sets the mark when it creates the
# release. The release workflow's verify job runs this after publication; it can
# be run by hand too. Needs gh (GH_TOKEN).
#   scripts/release/verify-github-release.sh v1.3.0-beta.1
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
want=$(python3 "$here/version.py" "$1" prerelease)
got=$(gh release view "$1" --json isPrerelease --jq .isPrerelease)
if [ "$got" != "$want" ]; then
  echo "::error::GitHub Release $1 has isPrerelease $got, the tag requires $want"; exit 1
fi
echo "GitHub Release $1: isPrerelease $got"
