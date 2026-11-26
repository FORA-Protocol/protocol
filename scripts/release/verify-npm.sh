#!/usr/bin/env bash
# Read the npm release back from the registry: the version, its dist-tag, and
# the package as a consumer installs it.
# The release workflow's verify job runs this after publication; it can be run by
# hand too. Takes the tag; the npm version and the dist-tag come from
# scripts/release/version.py (v1.3.0-beta.1 is 1.3.0-beta.1 under `next`).
# The version reaches the registry right away, but the CDN in front of it keeps
# serving the old package metadata for several minutes, and there is no supported
# way to ask it for a fresh copy. So this waits, up to 15 tries 20 seconds apart,
# for the version to show up in the exact document `npm install` resolves against
# (same URL, same Accept header). npm sets the dist-tag in the same request that
# publishes the version, so the document that lists the version also carries its
# dist-tag, and the dist-tag is checked once, in that document:
#   - the release's dist-tag points at the version;
#   - for a prerelease, `latest` does not, so a plain install never gets it.
# A later release under the same dist-tag moves it, so after one this check fails
# for the earlier version. The smoke test then runs once, so a real smoke failure
# fails immediately instead of being retried for the whole window.
#   scripts/release/verify-npm.sh v1.2.3
#   scripts/release/verify-npm.sh v1.3.0-beta.1
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
v=$(python3 "$here/version.py" "$1" npm)
dist_tag=$(python3 "$here/version.py" "$1" dist-tag)
prerelease=$(python3 "$here/version.py" "$1" prerelease)

for i in $(seq 1 15); do
  doc=$(curl -sf -H 'Accept: application/vnd.npm.install-v1+json' https://registry.npmjs.org/@fora-protocol/sdk) \
    && jq -e --arg v "$v" '.versions[$v]' >/dev/null <<<"$doc" && break
  [ "$i" = 15 ] && { echo "::error::@fora-protocol/sdk@$v not visible on npm after 5 minutes"; exit 1; }
  sleep 20
done
tagged=$(jq -r --arg t "$dist_tag" '."dist-tags"[$t] // "nothing"' <<<"$doc")
if [ "$tagged" != "$v" ]; then
  echo "::error::the npm dist-tag $dist_tag points at $tagged, the release $1 requires $v"; exit 1
fi
if [ "$prerelease" = true ] && [ "$(jq -r '."dist-tags".latest // ""' <<<"$doc")" = "$v" ]; then
  echo "::error::the npm dist-tag latest points at the prerelease $v"; exit 1
fi
echo "@fora-protocol/sdk@$v is on npm under the dist-tag $dist_tag"
"$here/smoke-npm.sh" "@fora-protocol/sdk@$v"
