#!/usr/bin/env bash
# Build once, across reruns (FORA-291).
# The GitHub Release for the tag is the artifact store and SHA256SUMS is the
# completeness marker, uploaded last and listing exactly the expected files.
#   present: download and verify the existing assets, build nothing.
#   absent:  the assets are from an incomplete run and nothing has used them
#            (publish jobs require SHA256SUMS), so build, smoke-test, replace
#            them, then upload SHA256SUMS last.
# A complete set is never overwritten. Needs gh (GH_TOKEN), uv, node, npm.
# Either way the verified SHA256SUMS content becomes the step output `sha256sums`
# when GITHUB_OUTPUT is set; the publish jobs pin their download to it.
#   scripts/release/build.sh v1.2.3 [out-dir]
set -euo pipefail
tag=$1; out=${2:-release-dist}; version=${tag#v}
here=$(cd "$(dirname "$0")" && pwd); root=$(cd "$here/../.." && pwd)

emit_sums() {
  [ -n "${GITHUB_OUTPUT:-}" ] || return 0
  { echo "sha256sums<<SHA256SUMS_EOF"; cat "$out/SHA256SUMS"; echo "SHA256SUMS_EOF"; } >> "$GITHUB_OUTPUT"
}

# Ask for the asset list explicitly. A 404 means no release yet (the marker is
# absent). Any other error is fatal: "could not ask GitHub" must never be read
# as "the marker is absent", or a transient failure would rebuild and overwrite
# a complete set.
if names=$(gh api "repos/{owner}/{repo}/releases/tags/$tag" --jq '.assets[].name' 2>&1); then
  :
elif [[ "$names" == *"HTTP 404"* ]]; then
  names=""
else
  echo "::error::cannot read release $tag: $names"; exit 1
fi
if grep -qx SHA256SUMS <<<"$names"; then
  echo "SHA256SUMS is on release $tag: verifying the existing assets, building nothing"
  "$here/download.sh" "$tag" "$out"
  emit_sums; exit 0
fi

echo "no SHA256SUMS on release $tag: building"
rm -rf "$out"; mkdir -p "$out"; out=$(cd "$out" && pwd)
uv build --out-dir "$out" "$root/gen/python"
uv build --out-dir "$out" "$root/sdk/python"
(cd "$root/sdk/ts" && npm ci --no-audit --no-fund && npm run build && npm pack ./dist --pack-destination "$out")

if [ "$(ls "$out" | sort)" != "$("$here/files.sh" "$version" | sort)" ]; then
  echo "::error::built files differ from the expected set:"; ls "$out"; exit 1
fi
staged=$(node -p "require('$root/sdk/ts/dist/package.json').version")
if [ "$staged" != "$version" ]; then
  echo "::error::staged npm manifest version $staged differs from tag $tag"; exit 1
fi

"$here/smoke-python.sh" "$out"/*.whl
"$here/smoke-python.sh" "$out"/*.tar.gz
"$here/smoke-npm.sh" "$out"/*.tgz

gh release view "$tag" >/dev/null 2>&1 || gh release create "$tag" --verify-tag --title "$tag" --generate-notes
gh release upload "$tag" --clobber "$out"/*
(cd "$out" && sha256sum $("$here/files.sh" "$version") > SHA256SUMS)
gh release upload "$tag" "$out/SHA256SUMS"
emit_sums
echo "release $tag: assets and SHA256SUMS uploaded"
