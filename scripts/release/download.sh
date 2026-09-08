#!/usr/bin/env bash
# Download the release files for a tag and verify them against SHA256SUMS (FORA-291).
# Fails when SHA256SUMS is absent (the set is incomplete), when it does not list
# exactly the expected files, or when any digest differs. Publish jobs use only
# files that passed this check.
#   scripts/release/download.sh v1.2.3 out-dir
set -euo pipefail
tag=$1; out=$2; version=${tag#v}
here=$(cd "$(dirname "$0")" && pwd)
rm -rf "$out"; mkdir -p "$out"
gh release download "$tag" --pattern SHA256SUMS --dir "$out"
if [ "$(awk '{print $2}' "$out/SHA256SUMS" | sort)" != "$("$here/files.sh" "$version" | sort)" ]; then
  echo "::error::SHA256SUMS on $tag does not list exactly the expected release files"; exit 1
fi
while read -r f; do gh release download "$tag" --pattern "$f" --dir "$out"; done < <("$here/files.sh" "$version")
(cd "$out" && sha256sum -c SHA256SUMS)
