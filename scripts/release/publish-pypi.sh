#!/usr/bin/env bash
# Publish the Python release files to PyPI, per file (FORA-291).
# fora-protocol first, then fora-protocol-sdk. For each file: absent on PyPI ->
# upload it through trusted publishing; present -> compare PyPI's sha256 with
# the release file and fail on a mismatch. Rerunning the tag is the recovery.
#   scripts/release/publish-pypi.sh release-dist 1.2.3
set -euo pipefail
dist=$1; version=$2

publish_file() {
  local name=$1 file=$2 base remote mine
  base=$(basename "$file")
  remote=$(curl -sf "https://pypi.org/pypi/$name/$version/json" \
    | jq -r --arg f "$base" '.urls[] | select(.filename == $f) | .digests.sha256' || true)
  mine=$(sha256sum "$file" | cut -d' ' -f1)
  if [ -z "$remote" ]; then
    echo "$base: not on PyPI, uploading"
    uv publish --trusted-publishing always "$file"
  elif [ "$remote" = "$mine" ]; then
    echo "$base: already on PyPI with the same sha256"
  else
    echo "::error::$base is on PyPI with sha256 $remote but the release file has $mine"; exit 1
  fi
}

for f in "$dist/fora_protocol-$version.tar.gz" "$dist/fora_protocol-$version-py3-none-any.whl"; do
  publish_file fora-protocol "$f"
done
for f in "$dist/fora_protocol_sdk-$version.tar.gz" "$dist/fora_protocol_sdk-$version-py3-none-any.whl"; do
  publish_file fora-protocol-sdk "$f"
done
