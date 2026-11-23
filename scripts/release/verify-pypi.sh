#!/usr/bin/env bash
# Read the Python release back from PyPI, the way a consumer installs it.
# The release workflow's verify job runs this after publication; it can be run by
# hand too. Takes the tag and installs its PEP 440 spelling
# (scripts/release/version.py): v1.3.0-beta.1 is 1.3.0b1.
#   1. the SDK wheel installs and imports, with fora-protocol resolved from PyPI
#      through the SDK's exact pin, the resolution a consumer's install performs
#      and the one no pre-publish check can make (both files are handed to it);
#   2. both sdists download from PyPI and rebuild into working wheels.
# PyPI can lag a publish by a minute or two, so each step retries 6 times, 30
# seconds apart. uv takes a prerelease only for a package the install names, so
# fora-protocol is always named as a constraint, never as a request: the SDK's pin
# still has to pull it in. For a final release the pin already names that version,
# so the constraint changes nothing; one command serves both.
#   scripts/release/verify-pypi.sh v1.2.3
#   scripts/release/verify-pypi.sh v1.3.0-beta.1
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
v=$(python3 "$here/version.py" "$1" python)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT

for i in 1 2 3 4 5 6; do
  "$here/smoke-python.sh" --constraint "fora-protocol==$v" "fora-protocol-sdk==$v" && break
  [ "$i" = 6 ] && { echo "::error::fora-protocol-sdk $v does not install from PyPI after 3 minutes"; exit 1; }
  sleep 30
done

# The wheel install proves the release is on PyPI, but the per-version JSON page
# behind the CDN can still answer 404 for a short while after that, so the lookup
# retries too. jq -e fails when the page lists no sdist, so that is retried as well.
for n in fora-protocol fora-protocol-sdk; do
  for i in 1 2 3 4 5 6; do
    url=$(curl -sSf "https://pypi.org/pypi/$n/$v/json" | jq -er '.urls[] | select(.packagetype == "sdist") | .url') && break
    [ "$i" = 6 ] && { echo "::error::$n $v sdist not visible on PyPI after 3 minutes"; exit 1; }
    sleep 30
  done
  curl -sSfL -o "$work/$(basename "$url")" "$url"
done
"$here/smoke-python.sh" "$work"/*.tar.gz
echo "verify-pypi ok: $v"
