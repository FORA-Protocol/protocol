#!/usr/bin/env bash
# The release scripts' decisions, against stub registries.
# Drives version.py, check-versions.py, publish-pypi.sh, publish-npm.sh,
# npm-publish-tarball.sh and build.sh unchanged. curl, uv, npm and gh are stubs
# on PATH: each registry is a directory the stubs read and write, and every stub
# call is appended to $LOG.
# The npm stub refuses a prerelease published without --tag, as npm 11 does, and
# applies that rule to a dry run too, so a dry run cannot pass a command the real
# publish would have refused.
# build.sh is copied next to a stub build-artifacts.sh, so nothing is really
# built; check-versions.py is copied into fixture trees of manifests. Each case
# asserts the exit status and the recorded commands. The tag run only ever takes
# the happy path, so this is where the refusals and the rerun path are
# exercised, for a final release and for a prerelease.
# Needs python3 (3.11+), jq, openssl, tar, sha256sum.
#   scripts/release/test-decisions.sh
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
export LOG="$work/log" PYPI="$work/pypi" NPM="$work/npm" RELEASE="$work/release"
export STUB_PYPI_STATUS="" STUB_NPM_FAIL="" STUB_GH_FAIL="" STUB_GH_UPLOAD_FAIL=""
v=1.2.3; tag=v$v
# A prerelease: npm and Go spell it $b, Python (PEP 440) spells it $bpy.
b=1.3.0-beta.1; btag=v$b; bpy=1.3.0b1

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
  publish) # npm publish [--dry-run] <tarball> ...: a dry run writes nothing
    dry=false; t=""; for a in "${@:2}"; do case "$a" in --dry-run) dry=true ;; *.tgz) t=$a ;; esac; done
    [[ "$t" = /* ]] || { echo "npm ERR! publish requires an absolute tarball path" >&2; exit 2; }
    case "$(tar -xzOf "$t" package/package.json | jq -r .version)" in *-*)
      [[ " $* " == *" --tag "* ]] || { echo "npm error You must specify a tag using --tag when publishing a prerelease version." >&2; exit 1; } ;;
    esac
    $dry || { mkdir -p "$NPM"; cp "$t" "$NPM/"; } ;;
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
mkdir -p "$work/rel"; cp "$here/build.sh" "$here/files.sh" "$here/download.sh" "$here/version.py" "$work/rel/"
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
make_dist() { # make_dist <dir> <version>: the release files, with a real npm tarball
  local d=$1 ver=$2 f; mkdir -p "$d" "$work/pkg-$ver/package"
  for f in $("$here/files.sh" "$ver"); do echo "release $f" > "$d/$f"; done
  echo "{\"name\":\"@fora-protocol/sdk\",\"version\":\"$ver\"}" > "$work/pkg-$ver/package/package.json"
  tar -czf "$d/fora-protocol-sdk-$ver.tgz" -C "$work/pkg-$ver" package
}
dist="$work/dist"; make_dist "$dist" "$v"
bdist="$work/bdist"; make_dist "$bdist" "$b"

# ---- assertions -----------------------------------------------------------
run() { # run <case> <expected exit status> <command>...
  : > "$LOG"; local name=$1 want=$2; shift 2; local got=0
  "$@" > "$work/out" 2>&1 || got=$?
  if [ "$got" != "$want" ]; then echo "FAIL $name: exit $got, expected $want"; cat "$work/out" "$LOG"; exit 1; fi
  echo "ok: $name (exit $got)"
}
called()     { grep -q -- "$1" "$LOG" || { echo "FAIL: expected a call matching: $1"; cat "$LOG"; exit 1; }; }
not_called() { ! grep -q -- "$1" "$LOG" || { echo "FAIL: unexpected call matching: $1"; cat "$LOG"; exit 1; }; }
said()       { grep -q -- "$1" "$work/out" || { echo "FAIL: expected output matching: $1"; cat "$work/out"; exit 1; }; }
one_error()  { [ "$(grep -c '::error::' "$work/out")" = 1 ] || { echo "FAIL: expected exactly one error"; cat "$work/out"; exit 1; }; }
spells() { # spells <tag> <npm> <python> <dist-tag> <prerelease>: version.py prints each field
  local t=$1 field want got; shift
  for field in npm python dist-tag prerelease; do
    want=$1; shift; got=$(python3 "$here/version.py" "$t" "$field")
    [ "$got" = "$want" ] || { echo "FAIL: version.py $t $field printed $got, expected $want"; exit 1; }
    echo "ok: version.py $t $field -> $want"
  done
}
usage_error() { # usage_error <case> <version.py argument>...: exit 2, a usage line, nothing on stdout
  local name=$1 got=0; shift
  python3 "$here/version.py" "$@" > "$work/stdout" 2> "$work/stderr" || got=$?
  [ "$got" = 2 ] || { echo "FAIL $name: exit $got, expected 2"; cat "$work/stdout" "$work/stderr"; exit 1; }
  [ ! -s "$work/stdout" ] || { echo "FAIL $name: printed to stdout:"; cat "$work/stdout"; exit 1; }
  grep -q '^usage: ' "$work/stderr" || { echo "FAIL $name: no usage line"; cat "$work/stderr"; exit 1; }
  echo "ok: $name (exit 2, usage, empty stdout)"
}
uploaded_in_order() { # uploaded_in_order <tag> <python version> <npm version>: the last two calls in $LOG
  local t=$1 py=$2 npm=$3 files sums
  files=$(tail -2 "$LOG" | head -1); sums=$(tail -1 "$LOG")
  [ "$sums" = "gh release upload $t $out/SHA256SUMS" ] || { echo "FAIL: SHA256SUMS was not the last upload"; cat "$LOG"; exit 1; }
  grep -q "^gh release upload $t --clobber $out/fora_protocol-$py.tar.gz .* $out/fora-protocol-sdk-$npm.tgz$" <<<"$files" \
    || { echo "FAIL: the release files were not uploaded by name before SHA256SUMS"; cat "$LOG"; exit 1; }
  ! grep -q SHA256SUMS <<<"$files" || { echo "FAIL: SHA256SUMS uploaded with the release files"; cat "$LOG"; exit 1; }
}

# version.py: the tag in each ecosystem's spelling
spells "$tag" "$v" "$v" latest false
spells "$v" "$v" "$v" latest false
spells "$btag" "$b" "$bpy" next true
spells v2.0.0-rc.12 2.0.0-rc.12 2.0.0rc12 next true
usage_error "version: unknown field -> usage" "$btag" pypi
usage_error "version: field missing -> usage" "$btag"
usage_error "version: extra argument -> usage" "$btag" npm extra
for t in v1.3.0-alpha.1 v1.3.0b1 1.3.0b1 v1.3.0-beta v1.3.0-beta1 v1.3.0-beta.01 v1.3 v01.3.0 \
         v1.3.0-beta.1+build.5 v1.3.0-BETA.1 V1.3.0 "v1.3.0 " ""; do
  run "version: unsupported tag '$t' -> refused" 1 python3 "$here/version.py" "$t" npm
  said "unsupported release version"
done

# check-versions.py, against fixture trees of the six versions it reads
tree() { # tree <dir> <gen/python> <sdk/python> <gen/ts> <sdk/ts> <package.json> <pin>
  local d=$1; mkdir -p "$d/scripts/release" "$d/gen/python" "$d/sdk/python" "$d/gen/ts" "$d/sdk/ts"
  cp "$here/check-versions.py" "$here/version.py" "$d/scripts/release/"
  printf '[project]\nversion = "%s"\n' "$2" > "$d/gen/python/pyproject.toml"
  printf '[project]\nversion = "%s"\ndependencies = ["fora-protocol==%s", "pydantic>=2.9"]\n' "$3" "$7" > "$d/sdk/python/pyproject.toml"
  printf '{"version": "%s"}\n' "$4" > "$d/gen/ts/package.json"
  printf '{"version": "%s"}\n' "$5" > "$d/sdk/ts/package.json"
  printf '{"version": "%s"}\n' "$6" > "$d/package.json"
}
gate() { python3 "$1/scripts/release/check-versions.py" "$2"; }
manifests=("gen/python/pyproject.toml" "sdk/python/pyproject.toml" "gen/ts/package.json"
           "sdk/ts/package.json" "package.json" "sdk/python/pyproject.toml fora-protocol pin")
tree "$work/t-final" "$v" "$v" "$v" "$v" "$v" "$v"
run "versions: consistent final tree -> pass" 0 gate "$work/t-final" "$v"
tree "$work/t-beta" "$bpy" "$bpy" "$b" "$b" "$b" "$bpy"
run "versions: consistent beta tree -> pass" 0 gate "$work/t-beta" "$b"
run "versions: final tree, beta tag -> failure" 1 gate "$work/t-final" "$b"
run "versions: beta tree, final tag -> failure" 1 gate "$work/t-beta" "$v"
run "versions: unsupported tag -> failure" 1 gate "$work/t-beta" "$bpy"
said "unsupported release version"
# One manifest off at a time. In the beta tree the wrong value is the other
# ecosystem's spelling of the same version, the mistake a bump most likely makes.
for i in 0 1 2 3 4 5; do
  fin=("$v" "$v" "$v" "$v" "$v" "$v"); fin[i]=1.2.4
  tree "$work/t-final-$i" "${fin[@]}"
  run "versions: final tree, ${manifests[i]} differs -> failure" 1 gate "$work/t-final-$i" "$v"
  said "::error::${manifests[i]} has version 1.2.4, release $v requires $v"; one_error
  bet=("$bpy" "$bpy" "$b" "$b" "$b" "$bpy")
  case $i in 0|1|5) bet[i]=$b; want=$bpy ;; *) bet[i]=$bpy; want=$b ;; esac
  tree "$work/t-beta-$i" "${bet[@]}"
  run "versions: beta tree, ${manifests[i]} misspelled -> failure" 1 gate "$work/t-beta-$i" "$b"
  said "::error::${manifests[i]} has version ${bet[i]}, release $b requires $want"; one_error
done

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
run "pypi: prerelease absent -> upload under the PEP 440 spelling" 0 "$here/publish-pypi.sh" "$bdist" "$b"
called "curl .*https://pypi.org/pypi/fora-protocol/$bpy/json"
called "curl .*https://pypi.org/pypi/fora-protocol-sdk/$bpy/json"
for f in "fora_protocol-$bpy.tar.gz" "fora_protocol-$bpy-py3-none-any.whl" \
         "fora_protocol_sdk-$bpy.tar.gz" "fora_protocol_sdk-$bpy-py3-none-any.whl"; do
  called "uv publish --trusted-publishing always $bdist/$f$"
done
[ "$(grep -c '^uv publish ' "$LOG")" = 4 ] || { echo "FAIL: expected 4 uploads"; cat "$LOG"; exit 1; }
run "pypi: prerelease same digest -> success, no upload" 0 "$here/publish-pypi.sh" "$bdist" "$b"
not_called "uv publish"
run "pypi: unsupported version -> failure, no lookup" 1 "$here/publish-pypi.sh" "$bdist" "$bpy"
not_called "curl"; not_called "uv publish"

# publish-npm.sh
tgz="$dist/fora-protocol-sdk-$v.tgz"
run "npm: absent -> publish under the dist-tag latest" 0 "$here/publish-npm.sh" "$tgz" "$v"
called "npm publish $tgz --access public --provenance --tag latest$"
run "npm: same integrity -> success, no publish" 0 "$here/publish-npm.sh" "$tgz" "$v"
not_called "npm publish"
echo tampered >> "$NPM/fora-protocol-sdk-$v.tgz"
run "npm: different integrity -> failure, no publish" 1 "$here/publish-npm.sh" "$tgz" "$v"
not_called "npm publish"
STUB_NPM_FAIL=1 run "npm: lookup failed -> failure, no publish" 1 "$here/publish-npm.sh" "$tgz" "$v"
not_called "npm publish"
btgz="$bdist/fora-protocol-sdk-$b.tgz"
run "npm: prerelease absent -> publish under the dist-tag next" 0 "$here/publish-npm.sh" "$btgz" "$b"
called "npm view @fora-protocol/sdk@$b dist.integrity"
called "npm publish $btgz --access public --provenance --tag next$"
run "npm: prerelease same integrity -> success, no publish" 0 "$here/publish-npm.sh" "$btgz" "$b"
not_called "npm publish"
run "npm: tarball version differs from the release -> failure, no publish" 1 "$here/publish-npm.sh" "$btgz" 1.3.0-beta.2
not_called "npm publish"
run "npm: unsupported version -> failure, npm not asked" 1 "$here/publish-npm.sh" "$btgz" "$bpy"
not_called "npm "

# npm-publish-tarball.sh: the one publish command, for the dry run and for real
pub="$here/npm-publish-tarball.sh"; r=2.0.0-rc.12; rdist="$work/rdist"; make_dist "$rdist" "$r"
rtgz="$rdist/fora-protocol-sdk-$r.tgz"
run "npm publish command: --dry-run prerelease -> the real flags under next, nothing published" 0 "$pub" --dry-run "$rtgz" "$r"
called "npm publish --dry-run $rtgz --access public --provenance --tag next$"
[ ! -e "$NPM/fora-protocol-sdk-$r.tgz" ] || { echo "FAIL: the dry run published"; exit 1; }
run "npm publish command: --dry-run final -> the real flags under latest" 0 "$pub" --dry-run "$tgz" "$v"
called "npm publish --dry-run $tgz --access public --provenance --tag latest$"
for args in "$rtgz $r" "--publsh $rtgz $r" "--dry-run $rtgz" "--publish $rtgz $r extra"; do
  # shellcheck disable=SC2086 # the cases are word lists
  run "npm publish command: '$args' -> usage, npm not called" 2 "$pub" $args
  not_called "npm "
done
run "npm publish command: unsupported version -> failure, npm not called" 1 "$pub" --publish "$rtgz" 2.0.0rc12
not_called "npm "

# build.sh
out="$work/out-dir"
run "build: no release -> build, upload files, then SHA256SUMS last" 0 "$work/rel/build.sh" "$tag" "$out"
called "build-artifacts $v"
called "gh release create $tag --verify-tag --title $tag --generate-notes$"
uploaded_in_order "$tag" "$v" "$v"
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
rm -rf "$RELEASE"
run "build: prerelease tag -> release marked prerelease, each file in its spelling" 0 "$work/rel/build.sh" "$btag" "$out"
called "build-artifacts $b $out"
called "gh release create $btag --verify-tag --title $btag --generate-notes --prerelease$"
uploaded_in_order "$btag" "$bpy" "$b"
run "build: prerelease SHA256SUMS on the release -> download and verify, no build" 0 "$work/rel/build.sh" "$btag" "$out"
called "gh release download $btag --pattern fora_protocol_sdk-$bpy-py3-none-any.whl"
not_called "build-artifacts"; not_called "release upload"; not_called "release create"
run "build: unsupported tag -> failure, GitHub not asked" 1 "$work/rel/build.sh" v1.3.0-alpha.1 "$out"
not_called "gh "; not_called "build-artifacts"
echo "test-decisions ok"
