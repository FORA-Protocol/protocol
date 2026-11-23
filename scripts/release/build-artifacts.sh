#!/usr/bin/env bash
# Build the release artifact set for a version into out-dir and smoke-test it.
# No registry token: the npm installs here resolve dependencies from the registry
# (with lifecycle scripts ignored), and nothing that comes from there may see a
# token. SHA256SUMS is written BEFORE the smoke tests and checked again after
# them, so a dependency that swaps a release file during the smoke run fails the
# build instead of getting checksummed and published. This detects a changed
# file; it is not isolation (the smoke tests run as the same user). build.sh
# runs this with the token removed; pull-request CI (sdk-types-ci.yml) runs it
# too, so the staged NodeNext compile, the file set, the staged manifest version
# and the consumer smoke tests fail on the pull request instead of on the
# protected tag. The version is the release version (the tag without the v);
# scripts/release/version.py maps it to each ecosystem's spelling and refuses an
# unsupported one before anything is built. Needs uv, node, npm.
#   scripts/release/build-artifacts.sh 1.2.3 out-dir
#   scripts/release/build-artifacts.sh 1.3.0-beta.1 out-dir
set -euo pipefail
out=$2
here=$(cd "$(dirname "$0")" && pwd); root=$(cd "$here/../.." && pwd)
version=$(python3 "$here/version.py" "$1" npm)
if [ -n "${GH_TOKEN:-}" ] || [ -n "${GITHUB_TOKEN:-}" ]; then
  echo "::error::build-artifacts.sh must run without a registry token in its environment"; exit 1
fi

rm -rf "$out"; mkdir -p "$out"; out=$(cd "$out" && pwd)
uv build --out-dir "$out" "$root/gen/python"
uv build --out-dir "$out" "$root/sdk/python"
(cd "$root/sdk/ts" && npm ci --ignore-scripts --no-audit --no-fund && npm run build && npm pack ./dist --pack-destination "$out")

if [ "$(ls "$out" | sort)" != "$("$here/files.sh" "$version" | sort)" ]; then
  echo "::error::built files differ from the expected set:"; ls "$out"; exit 1
fi
staged=$(node -p "require('$root/sdk/ts/dist/package.json').version")
if [ "$staged" != "$version" ]; then
  echo "::error::staged npm manifest version $staged differs from version $version"; exit 1
fi
# The real publish command, as a dry run: the same script publish-npm.sh runs on the tag.
"$here/npm-publish-tarball.sh" --dry-run "$out/$("$here/files.sh" "$version" | grep '\.tgz$')" "$version"
(cd "$out" && sha256sum $("$here/files.sh" "$version") > SHA256SUMS)

"$here/smoke-python.sh" "$out"/*.whl
"$here/smoke-python.sh" "$out"/*.tar.gz
"$here/smoke-npm.sh" "$out"/*.tgz
(cd "$out" && sha256sum -c SHA256SUMS)
echo "artifact set $version built, smoke-tested and checksummed in $out"
