#!/usr/bin/env bash
# Build the release artifact set for a version into out-dir and smoke-test it.
# No registry token: the npm installs here resolve dependencies from the registry
# (with lifecycle scripts ignored), and nothing that comes from there may see a
# token or touch the artifact set before the checksums exist. build.sh runs this
# with the token removed; pull-request CI (sdk-types-ci.yml) runs it too, so the
# staged NodeNext compile, the file set, the staged manifest version and the
# consumer smoke tests fail on the pull request instead of on the protected tag.
# Needs uv, node, npm.
#   scripts/release/build-artifacts.sh 1.2.3 out-dir
set -euo pipefail
version=$1; out=$2
here=$(cd "$(dirname "$0")" && pwd); root=$(cd "$here/../.." && pwd)
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

"$here/smoke-python.sh" "$out"/*.whl
"$here/smoke-python.sh" "$out"/*.tar.gz
"$here/smoke-npm.sh" "$out"/*.tgz
echo "artifact set $version built and smoke-tested in $out"
