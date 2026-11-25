#!/usr/bin/env bash
# Publish the @fora-protocol/sdk release tarball to npm.
# Takes the release directory and the release tag, like publish-pypi.sh; the
# tarball is the one scripts/release/files.sh names for it.
# Absent on the registry -> publish it (trusted publishing + provenance; npm
# 11.5.1+). Present -> compare dist.integrity (the SHA-512 SRI string;
# dist.shasum is SHA-1 and is not used) with the release tarball and fail on a
# mismatch. Exactly the release bytes are published, never a rebuild.
# The publish command itself, with its dist-tag, is npm-publish-tarball.sh, which
# build-artifacts.sh also runs, as a dry run.
#   scripts/release/publish-npm.sh release-dist v1.2.3
#   scripts/release/publish-npm.sh release-dist v1.3.0-beta.1
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
version=$(python3 "$here/version.py" "$2" npm)
tarball=$1/$("$here/files.sh" "$version" | grep '\.tgz$')
# Checked here, not left to tar: tar's status for a missing file differs between
# GNU tar (2) and bsdtar (1), and the refusal is this script's.
if [ ! -f "$tarball" ] || [ ! -r "$tarball" ]; then
  echo "::error::no readable release tarball $tarball"; exit 1
fi
tarball=$(cd "$(dirname "$tarball")" && pwd)/$(basename "$tarball")

if ! staged=$(tar -xzOf "$tarball" package/package.json | jq -r .version); then
  echo "::error::cannot read package/package.json from $tarball"; exit 1
fi
if [ "$staged" != "$version" ]; then
  echo "::error::staged manifest version $staged differs from tag version $version"; exit 1
fi
mine="sha512-$(openssl dgst -sha512 -binary "$tarball" | base64 | tr -d "\n")"
# Empty when npm does not have the version; a lookup that is not an answer fails
# (scripts/release/npm-view.sh).
remote=$("$here/npm-view.sh" "@fora-protocol/sdk@$version" dist.integrity)
if [ -z "$remote" ]; then
  echo "@fora-protocol/sdk@$version: not on npm, publishing"
  "$here/npm-publish-tarball.sh" --publish "$tarball" "$version"
elif [ "$remote" = "$mine" ]; then
  echo "@fora-protocol/sdk@$version: already on npm with the same integrity"
else
  echo "::error::@fora-protocol/sdk@$version is on npm with integrity $remote but the release tarball has $mine"; exit 1
fi
