#!/usr/bin/env bash
# Build once, across reruns.
# The GitHub Release for the tag is the artifact store and SHA256SUMS is the
# completeness marker, uploaded last and listing exactly the expected files.
#   present: download and verify the existing assets, build nothing.
#   absent:  the assets are from an incomplete run and nothing has used them
#            (publish jobs require SHA256SUMS), so build, smoke-test, replace
#            them, then upload SHA256SUMS last. build-artifacts.sh writes the
#            SHA256SUMS before its smoke tests; this script only uploads it.
# A complete set is never overwritten. Needs gh (GH_TOKEN), uv, node, npm.
# Either way the verified SHA256SUMS content becomes the step output `sha256sums`
# when GITHUB_OUTPUT is set; the publish jobs pin their download to it.
# The token is used only to read and write the release. The build and the smoke
# tests (build-artifacts.sh) run with it removed from the environment.
#   scripts/release/build.sh v1.2.3 [out-dir]
set -euo pipefail
tag=$1; out=${2:-release-dist}; version=${tag#v}
here=$(cd "$(dirname "$0")" && pwd)

emit_sums() {
  [ -n "${GITHUB_OUTPUT:-}" ] || return 0
  { echo "sha256sums<<SHA256SUMS_EOF"; cat "$out/SHA256SUMS"; echo "SHA256SUMS_EOF"; } >> "$GITHUB_OUTPUT"
}

# Ask for the asset list explicitly. A 404 means no release yet (the marker is
# absent). Any other error is fatal: "could not ask GitHub" must never be read
# as "the marker is absent", or a transient failure would rebuild and overwrite
# a complete set.
release_exists=true
if names=$(gh api "repos/{owner}/{repo}/releases/tags/$tag" --jq '.assets[].name' 2>&1); then
  :
elif [[ "$names" == *"HTTP 404"* ]]; then
  names=""; release_exists=false
else
  echo "::error::cannot read release $tag: $names"; exit 1
fi
if grep -qx SHA256SUMS <<<"$names"; then
  echo "SHA256SUMS is on release $tag: verifying the existing assets, building nothing"
  "$here/download.sh" "$tag" "$out"
  emit_sums; exit 0
fi

echo "no SHA256SUMS on release $tag: building"
env -u GH_TOKEN -u GITHUB_TOKEN "$here/build-artifacts.sh" "$version" "$out"
out=$(cd "$out" && pwd)

# The lookup above already answered whether the release exists; a second
# "view || create" would read any failure of view as "absent".
$release_exists || gh release create "$tag" --verify-tag --title "$tag" --generate-notes
# The five release files by name, never the directory glob: SHA256SUMS is in the
# same directory and must be the last upload, after every file it lists.
files=(); while read -r f; do files+=("$out/$f"); done < <("$here/files.sh" "$version")
gh release upload "$tag" --clobber "${files[@]}"
gh release upload "$tag" "$out/SHA256SUMS"
emit_sums
echo "release $tag: assets and SHA256SUMS uploaded"
