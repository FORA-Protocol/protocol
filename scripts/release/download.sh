#!/usr/bin/env bash
# Download the release files for a tag and verify them against SHA256SUMS (FORA-291).
# Fails when SHA256SUMS is absent (the set is incomplete), when it does not list
# exactly the expected files, or when any digest differs. Publish jobs use only
# files that passed this check.
#   scripts/release/download.sh v1.2.3 out-dir            # build job: trust the release
#   scripts/release/download.sh v1.2.3 out-dir "$SUMS"    # publish jobs: pin to the build job
# With a third argument the downloaded SHA256SUMS must equal it. The release is a
# mutable store; the build job's output is not. An empty third argument fails: a
# job output whose step never set it is silently an empty string (fora-acw.3).
set -euo pipefail
tag=$1; out=$2; version=${tag#v}
here=$(cd "$(dirname "$0")" && pwd)
rm -rf "$out"; mkdir -p "$out"
gh release download "$tag" --pattern SHA256SUMS --dir "$out"
if [ $# -ge 3 ]; then
  if [ -z "$3" ]; then
    echo "::error::expected SHA256SUMS content is empty: the build job output is missing"; exit 1
  fi
  # $(...) strips trailing newlines on both sides; every other byte must match.
  if [ "$(cat "$out/SHA256SUMS")" != "$(printf '%s' "$3")" ]; then
    echo "::error::SHA256SUMS on release $tag differs from the one the build job verified"; exit 1
  fi
fi
if [ "$(awk '{print $2}' "$out/SHA256SUMS" | sort)" != "$("$here/files.sh" "$version" | sort)" ]; then
  echo "::error::SHA256SUMS on $tag does not list exactly the expected release files"; exit 1
fi
while read -r f; do gh release download "$tag" --pattern "$f" --dir "$out"; done < <("$here/files.sh" "$version")
(cd "$out" && sha256sum -c SHA256SUMS)
