#!/usr/bin/env bash
# Publish the @fora-protocol/sdk release tarball to npm (FORA-291).
# Absent on the registry -> publish it (trusted publishing + provenance; npm
# 11.5.1+). Present -> compare dist.integrity (the SHA-512 SRI string;
# dist.shasum is SHA-1 and is not used) with the release tarball and fail on a
# mismatch. Exactly the release bytes are published, never a rebuild.
#   scripts/release/publish-npm.sh release-dist/fora-protocol-sdk-1.2.3.tgz 1.2.3
set -euo pipefail
tarball=$1; version=$2

staged=$(tar -xzOf "$tarball" package/package.json | jq -r .version)
if [ "$staged" != "$version" ]; then
  echo "::error::staged manifest version $staged differs from tag version $version"; exit 1
fi
mine="sha512-$(openssl dgst -sha512 -binary "$tarball" | base64 | tr -d "\n")"
remote=$(npm view "@fora-protocol/sdk@$version" dist.integrity 2>/dev/null || true)
if [ -z "$remote" ]; then
  echo "@fora-protocol/sdk@$version: not on npm, publishing"
  npm publish "$tarball" --access public --provenance
elif [ "$remote" = "$mine" ]; then
  echo "@fora-protocol/sdk@$version: already on npm with the same integrity"
else
  echo "::error::@fora-protocol/sdk@$version is on npm with integrity $remote but the release tarball has $mine"; exit 1
fi
