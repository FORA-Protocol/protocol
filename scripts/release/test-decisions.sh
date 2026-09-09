#!/usr/bin/env bash
# The release scripts' decisions, against stub registries.
# Drives publish-pypi.sh, publish-npm.sh and build.sh unchanged. curl, uv, npm and
# gh are stubs on PATH: each registry is a directory the stubs read and write,
# and every stub call is appended to $LOG. build.sh is copied next to a stub
# build-artifacts.sh, so nothing is really built. Each case asserts the exit
# status and the recorded commands. The tag run only ever takes the happy path,
# so this is where the refusals and the rerun path are exercised.
# Needs jq, openssl, tar, sha256sum.
#   scripts/release/test-decisions.sh
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
export LOG="$work/log" PYPI="$work/pypi" NPM="$work/npm" RELEASE="$work/release"
export STUB_PYPI_STATUS="" STUB_NPM_FAIL="" STUB_GH_FAIL="" STUB_GH_UPLOAD_FAIL=""
v=1.2.3; tag=v$v

# ---- stubs ----------------------------------------------------------------
mkdir -p "$work/bin"
cat > "$work/bin/curl" <<'STUB'
#!/usr/bin/env bash
# curl -s -w '\n%{http_code}' https://pypi.org/pypi/<name>/<version>/json
set -euo pipefail; shopt -s nullglob; echo "curl $*" >> "$LOG"
name=$(basename "$(dirname "$(dirname "${*: -1}")")")
if [ -n "$STUB_PYPI_STATUS" ]; then printf '\n%s' "$STUB_PYPI_STATUS"; exit 0; fi
if [ ! -d "$PYPI/$name" ]; then printf '\n404'; exit 0; fi
for f in "$PYPI/$name"/*; do
  printf '{"filename":"%s","digests":{"sha256":"%s"}}\n' "$(basename "$f")" "$(sha256sum "$f" | cut -d' ' -f1)"
done | jq -s '{urls: .}'
printf '\n200'
STUB
cat > "$work/bin/uv" <<'STUB'
#!/usr/bin/env bash
# uv publish --trusted-publishing always <file>
set -euo pipefail; echo "uv $*" >> "$LOG"
[ "$1" = publish ] || exit 0
f=${*: -1}; n=$(basename "$f"); n=${n%%-*}; n=${n//_/-}
mkdir -p "$PYPI/$n"; cp "$f" "$PYPI/$n/"
STUB
cat > "$work/bin/npm" <<'STUB'
#!/usr/bin/env bash
# npm view @fora-protocol/sdk@<version> dist.integrity | npm publish <tarball> ...
set -euo pipefail; echo "npm $*" >> "$LOG"
case "$1" in
  view)
    if [ -n "$STUB_NPM_FAIL" ]; then echo "npm ERR! code E503" >&2; exit 1; fi
    f="$NPM/fora-protocol-sdk-${2##*@}.tgz"
    if [ ! -e "$f" ]; then echo "npm ERR! code E404" >&2; exit 1; fi
    echo "sha512-$(openssl dgst -sha512 -binary "$f" | base64 | tr -d '\n')" ;;
  publish) [[ "$2" = /* ]] || { echo "npm ERR! publish requires an absolute tarball path" >&2; exit 2; }
    mkdir -p "$NPM"; cp "$2" "$NPM/" ;;
esac
STUB
cat > "$work/bin/gh" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail; echo "gh $*" >> "$LOG"
case "$1 $2" in
  "api "*)
    if [ -n "$STUB_GH_FAIL" ]; then echo "HTTP 503: unavailable" >&2; exit 1; fi
    if [ ! -d "$RELEASE" ]; then echo "HTTP 404: Not Found" >&2; exit 1; fi
    ls "$RELEASE" ;;
  "release create") mkdir -p "$RELEASE" ;;
  "release download") # gh release download <tag> --pattern <name> --dir <dir>
    shift 3; while [ $# -gt 0 ]; do case "$1" in --pattern) p=$2 ;; --dir) d=$2 ;; esac; shift 2; done
    cp "$RELEASE/$p" "$d/" ;;
  "release upload") # gh release upload <tag> [--clobber] <file>...
    shift 3
    for f in "$@"; do
      [ "$f" = --clobber ] && continue
      if [ -n "$STUB_GH_UPLOAD_FAIL" ]; then echo "upload failed" >&2; exit 1; fi
      cp "$f" "$RELEASE/"
    done ;;
esac
STUB
# build.sh resolves its siblings from its own directory: a copy of it next to a
# stub build-artifacts.sh runs the real decisions over a fake build.
mkdir -p "$work/rel"; cp "$here/build.sh" "$here/files.sh" "$here/download.sh" "$work/rel/"
cat > "$work/rel/build-artifacts.sh" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail; echo "build-artifacts $*" >> "$LOG"
version=$1; out=$2; rm -rf "$out"; mkdir -p "$out"; here=$(dirname "$0")
for f in $("$here/files.sh" "$version"); do echo "built $f" > "$out/$f"; done
(cd "$out" && sha256sum $("$here/files.sh" "$version") > SHA256SUMS)
STUB
chmod +x "$work/bin"/* "$work/rel"/*
export PATH="$work/bin:$PATH"

# ---- fixtures: a release file set, with a real tarball for publish-npm.sh -----
dist="$work/dist"; mkdir -p "$dist" "$work/pkg/package"
for f in $("$here/files.sh" "$v"); do echo "release $f" > "$dist/$f"; done
echo "{\"name\":\"@fora-protocol/sdk\",\"version\":\"$v\"}" > "$work/pkg/package/package.json"
tar -czf "$dist/fora-protocol-sdk-$v.tgz" -C "$work/pkg" package

# ---- assertions -----------------------------------------------------------
run() { # run <case> <expected exit status> <command>...
  : > "$LOG"; local name=$1 want=$2; shift 2; local got=0
  "$@" > "$work/out" 2>&1 || got=$?
  if [ "$got" != "$want" ]; then echo "FAIL $name: exit $got, expected $want"; cat "$work/out" "$LOG"; exit 1; fi
  echo "ok: $name (exit $got)"
}
called()     { grep -q -- "$1" "$LOG" || { echo "FAIL: expected a call matching: $1"; cat "$LOG"; exit 1; }; }
not_called() { ! grep -q -- "$1" "$LOG" || { echo "FAIL: unexpected call matching: $1"; cat "$LOG"; exit 1; }; }

# publish-pypi.sh
run "pypi: absent -> upload" 0 "$here/publish-pypi.sh" "$dist" "$v"
[ "$(grep -c '^uv publish --trusted-publishing always ' "$LOG")" = 4 ] || { echo "FAIL: expected 4 uploads"; cat "$LOG"; exit 1; }
run "pypi: same digest -> success, no upload" 0 "$here/publish-pypi.sh" "$dist" "$v"
not_called "uv publish"
echo tampered >> "$PYPI/fora-protocol-sdk/fora_protocol_sdk-$v-py3-none-any.whl"
run "pypi: different digest -> failure, no upload" 1 "$here/publish-pypi.sh" "$dist" "$v"
not_called "uv publish"
STUB_PYPI_STATUS=503 run "pypi: lookup failed -> failure, no upload" 1 "$here/publish-pypi.sh" "$dist" "$v"
not_called "uv publish"

# publish-npm.sh
tgz="$dist/fora-protocol-sdk-$v.tgz"
run "npm: absent -> publish" 0 "$here/publish-npm.sh" "$tgz" "$v"
called "npm publish $tgz"
run "npm: same integrity -> success, no publish" 0 "$here/publish-npm.sh" "$tgz" "$v"
not_called "npm publish"
echo tampered >> "$NPM/fora-protocol-sdk-$v.tgz"
run "npm: different integrity -> failure, no publish" 1 "$here/publish-npm.sh" "$tgz" "$v"
not_called "npm publish"
STUB_NPM_FAIL=1 run "npm: lookup failed -> failure, no publish" 1 "$here/publish-npm.sh" "$tgz" "$v"
not_called "npm publish"

# build.sh
out="$work/out-dir"
run "build: no release -> build, upload files, then SHA256SUMS last" 0 "$work/rel/build.sh" "$tag" "$out"
called "build-artifacts $v"
[ "$(tail -1 "$LOG")" = "gh release upload $tag $out/SHA256SUMS" ] || { echo "FAIL: SHA256SUMS was not the last upload"; cat "$LOG"; exit 1; }
tail -2 "$LOG" | head -1 | grep -q "^gh release upload $tag --clobber $out/fora_protocol-$v.tar.gz .* $out/fora-protocol-sdk-$v.tgz$" \
  || { echo "FAIL: the release files were not uploaded by name before SHA256SUMS"; cat "$LOG"; exit 1; }
tail -2 "$LOG" | head -1 | grep -qv SHA256SUMS || { echo "FAIL: SHA256SUMS uploaded with the release files"; cat "$LOG"; exit 1; }
run "build: SHA256SUMS on the release -> download and verify, no build, no upload" 0 "$work/rel/build.sh" "$tag" "$out"
called "gh release download $tag --pattern SHA256SUMS"
not_called "build-artifacts"; not_called "release upload"
echo tampered >> "$RELEASE/fora_protocol-$v.tar.gz"
run "build: asset differs from SHA256SUMS -> failure, nothing replaced" 1 "$work/rel/build.sh" "$tag" "$out"
not_called "build-artifacts"; not_called "release upload"
grep -q tampered "$RELEASE/fora_protocol-$v.tar.gz" || { echo "FAIL: the release asset was replaced"; exit 1; }
STUB_GH_FAIL=1 run "build: release lookup failed -> failure, no build, no upload" 1 "$work/rel/build.sh" "$tag" "$out"
not_called "build-artifacts"; not_called "release upload"; not_called "release download"
rm -rf "$RELEASE"
STUB_GH_UPLOAD_FAIL=1 run "build: file upload failed -> no SHA256SUMS upload" 1 "$work/rel/build.sh" "$tag" "$out"
called "build-artifacts $v"
not_called "release upload $tag $out/SHA256SUMS"
[ ! -e "$RELEASE/SHA256SUMS" ] || { echo "FAIL: SHA256SUMS reached the release"; exit 1; }
echo "test-decisions ok"
