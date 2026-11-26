#!/usr/bin/env bash
# Publish the Python release files to PyPI, per file.
# fora-protocol first, then fora-protocol-sdk. For each file: absent on PyPI ->
# upload it through trusted publishing; present -> compare PyPI's sha256 with
# the release file and fail on a mismatch. Rerunning the tag is the recovery.
# Takes the release tag as the workflow passes it (the v is optional); PyPI and the
# file names carry its PEP 440 spelling (scripts/release/version.py), so
# v1.3.0-beta.1 publishes 1.3.0b1.
#   scripts/release/publish-pypi.sh release-dist v1.2.3
#   scripts/release/publish-pypi.sh release-dist v1.3.0-beta.1
set -euo pipefail
dist=$1
here=$(cd "$(dirname "$0")" && pwd)
version=$(python3 "$here/version.py" "$2" python)

publish_file() {
  local name=$1 file=$2 base remote mine body status
  base=$(basename "$file")
  # Only HTTP 404 means "this version is not on PyPI". Any other failure (5xx,
  # rate limit, DNS) is not an answer: reading it as "absent" would skip the
  # digest comparison and try an upload that the registry then refuses.
  body=$(curl -s -w '\n%{http_code}' "https://pypi.org/pypi/$name/$version/json") \
    || { echo "::error::cannot reach PyPI for $name $version"; exit 1; }
  status=${body##*$'\n'}; body=${body%$'\n'*}
  case "$status" in
    200) remote=$(jq -r --arg f "$base" '.urls[] | select(.filename == $f) | .digests.sha256' <<<"$body") ;;
    404) remote="" ;;
    *) echo "::error::PyPI answered HTTP $status for $name $version"; exit 1 ;;
  esac
  mine=$(sha256sum "$file" | cut -d' ' -f1)
  if [ -z "$remote" ]; then
    echo "$base: not on PyPI, uploading"
    uv publish --trusted-publishing always "$file" || { echo "::error::uploading $base to PyPI failed"; exit 1; }
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
