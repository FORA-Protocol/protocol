#!/usr/bin/env bash
# A dry-run release of a tag from the committed tree, with nothing published.
# Exports HEAD to a scratch directory and writes the tag's version into it the way
# a release-preparation change does (RELEASING.md): the npm spelling into the root
# package.json and, through npm version, into gen/ts and sdk/ts; the PEP 440
# spelling into both pyproject.toml files and the fora-protocol== pin
# (scripts/release/version.py). It then runs, inside that copy, the version gate
# and build-artifacts.sh, which builds the npm and PyPI files, checks their names
# against files.sh, runs the npm publish command with --dry-run under the tag's
# dist-tag, and smoke-tests the local files. The Go module is the tagged tree
# itself, so there is nothing to build for it.
# Pull-request CI (sdk-types-ci.yml) runs it for v1.3.0-beta.1, so the prerelease
# path of the build runs before any prerelease is prepared. Only committed
# changes are in the copy. Needs git, uv, node, npm.
#   scripts/release/dry-run-release.sh v1.3.0-beta.1 out-dir
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd); root=$(cd "$here/../.." && pwd)
npm=$(python3 "$here/version.py" "$1" npm)
py=$(python3 "$here/version.py" "$1" python)
mkdir -p "$2"; out=$(cd "$2" && pwd)
copy=$(mktemp -d); trap 'rm -rf "$copy"' EXIT
git -C "$root" archive HEAD | tar -x -C "$copy"
cd "$copy"

npm pkg set "version=$npm"
(cd gen/ts && npm version "$npm" --no-git-tag-version --allow-same-version >/dev/null)
(cd sdk/ts && npm version "$npm" --no-git-tag-version --allow-same-version >/dev/null)
python3 - "$py" <<'PY'
import pathlib, re, sys
py = sys.argv[1]
for p in ("gen/python/pyproject.toml", "sdk/python/pyproject.toml"):
    f = pathlib.Path(p)
    s, n = re.subn(r'(?m)^version = "[^"]*"$', f'version = "{py}"', f.read_text())
    if n != 1:
        sys.exit(f"{p}: expected one project version line, found {n}")
    if p.startswith("sdk/"):
        s, n = re.subn(r'"fora-protocol==[^"]*"', f'"fora-protocol=={py}"', s)
        if n != 1:
            sys.exit(f"{p}: expected one fora-protocol== pin, found {n}")
    f.write_text(s)
PY
python3 scripts/release/check-versions.py "$npm"
scripts/release/build-artifacts.sh "$npm" "$out"
echo "dry-run release $1: npm $npm, PyPI $py, built in $out, nothing published"
