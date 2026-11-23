#!/usr/bin/env bash
# The release scripts' decisions, against stub registries.
# Drives version.py, check-versions.py, the publish scripts, build.sh,
# smoke-python.sh and the verify scripts unchanged. curl, uv, npm, gh and sleep
# are stubs on PATH: each registry is a directory the stubs read and write, and
# every stub call is appended to $LOG.
# The npm stub refuses a prerelease published without --tag, as npm 11 does, and
# applies that rule to a dry run too, so a dry run cannot pass a command the real
# publish would have refused. The uv stub refuses a prerelease pin the install
# does not name, as uv does.
# build.sh is copied next to a stub build-artifacts.sh, so nothing is really
# built; check-versions.py is copied into fixture trees of manifests. The verify
# scripts (verify-pypi.sh, verify-npm.sh, verify-github-release.sh) read back
# what the publish cases left on the stub registries; smoke-python.sh runs
# against the uv stub, and verify-npm.sh is copied next to a stub smoke-npm.sh.
# Each case asserts the exit status and the recorded commands. The tag run only
# ever takes the happy path, and its verify job is the first time the verify
# scripts meet the real registries, so this is where the refusals, the rerun path
# and the readbacks are exercised, for a final release and for a prerelease.
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
# PyPI JSON: curl -s -w '\n%{http_code}' <url> (the status on the last line)
#            curl -sSf <url> (an error status fails with 22, as -f does)
# download:  curl -sSfL -o <file> https://files.example/<name>/<file>
# npm:       curl -sf -H <accept> https://registry.npmjs.org/@fora-protocol/sdk
set -euo pipefail; shopt -s nullglob; echo "curl $*" >> "$LOG"
url=${*: -1}; status=false; o=""; args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do case "${args[i]}" in -w) status=true ;; -o) o=${args[i+1]} ;; esac; done
answer() { # answer <http status> [body]
  if $status; then printf '%s\n%s' "${2:-}" "$1"; elif [ "$1" = 200 ]; then printf '%s\n' "$2"; else exit 22; fi
}
case "$url" in
  https://files.example/*) f="$PYPI/${url#https://files.example/}"; [ -e "$f" ] || exit 22; cp "$f" "$o" ;;
  https://registry.npmjs.org/*) # the packument: dist-tags and the versions on the registry
    [ -d "$NPM" ] || exit 22
    vs=$(for f in "$NPM"/fora-protocol-sdk-*.tgz; do f=${f##*/fora-protocol-sdk-}; echo "${f%.tgz}"; done | jq -R . | jq -s 'map({key: ., value: {}}) | from_entries')
    answer 200 "$(jq -n --argjson vs "$vs" --argjson t "$(cat "$NPM/dist-tags.json" 2>/dev/null || echo '{}')" \
      '{name: "@fora-protocol/sdk", "dist-tags": $t, versions: $vs}')" ;;
  https://pypi.org/pypi/*) # https://pypi.org/pypi/<name>/<version>/json: that version's files, else 404
    [ -z "$STUB_PYPI_STATUS" ] || answer "$STUB_PYPI_STATUS"
    p=${url#https://pypi.org/pypi/}; name=${p%%/*}; ver=${p#*/}; ver=${ver%/json}
    body=$(for f in "$PYPI/$name"/*; do case "${f##*/}" in
        *-"$ver".tar.gz) t=sdist ;; *-"$ver"-py3-none-any.whl) t=bdist_wheel ;; *) continue ;; esac
      printf '{"filename":"%s","packagetype":"%s","url":"https://files.example/%s/%s","digests":{"sha256":"%s"}}\n' \
        "${f##*/}" "$t" "$name" "${f##*/}" "$(sha256sum "$f" | cut -d' ' -f1)"
    done | jq -s '{urls: .}')
    if [ "$(jq '.urls | length' <<<"$body")" = 0 ]; then answer 404; else answer 200 "$body"; fi ;;
  *) echo "curl stub: unexpected URL $url" >&2; exit 2 ;;
esac
STUB
cat > "$work/bin/uv" <<'STUB'
#!/usr/bin/env bash
# uv publish --trusted-publishing always <file>: the file lands on the stub PyPI
# uv venv <dir>: an interpreter that reads its script from stdin and succeeds
# uv build ...: builds nothing
# uv pip install [-q] [--python <venv>] [-c <file>] <requirement>...: logs each
#   constraint as "uv constraint <spec>". Refuses a name==version the stub PyPI
#   does not hold, and a fora-protocol-sdk prerelease whose exact fora-protocol
#   pin the install does not name, as uv does: it accepts a prerelease only for a
#   package the install names, as a requirement or a constraint.
set -euo pipefail; echo "uv $*" >> "$LOG"
case "$1" in
  publish) f=${*: -1}; n=$(basename "$f"); n=${n%%-*}; n=${n//_/-}
    mkdir -p "$PYPI/$n"; cp "$f" "$PYPI/$n/" ;;
  venv) d=${*: -1}; mkdir -p "$d/bin"; printf '#!/bin/sh\ncat >/dev/null\n' > "$d/bin/python"; chmod +x "$d/bin/python" ;;
  pip) shift 2; named=(); reqs=()
    while [ $# -gt 0 ]; do
      case "$1" in
        -q) ;;
        --python) shift ;;
        -c) shift; while read -r c; do echo "uv constraint $c" >> "$LOG"; named+=("$c"); done < "$1" ;;
        *) reqs+=("$1"); named+=("$1") ;;
      esac; shift
    done
    for r in ${reqs[@]+"${reqs[@]}"}; do
      case "$r" in *==*) ;; *) continue ;; esac
      n=${r%%==*}; ver=${r#*==}
      [ -e "$PYPI/$n/${n//-/_}-$ver-py3-none-any.whl" ] || { echo "error: there is no version of $r" >&2; exit 1; }
      case "$n $ver" in "fora-protocol-sdk "*[a-z]*)
        [[ " ${named[*]} " == *" fora-protocol==$ver "* ]] \
          || { echo "error: fora-protocol==$ver is a prerelease and the install does not name fora-protocol" >&2; exit 1; } ;;
      esac
    done ;;
esac
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
  publish) # npm publish [--dry-run] <tarball> ... [--tag <dist-tag>]: a dry run writes nothing
    dry=false; t=""; dt=latest; prev=""
    for a in "${@:2}"; do case "$a" in --dry-run) dry=true ;; *.tgz) t=$a ;; esac; [ "$prev" != --tag ] || dt=$a; prev=$a; done
    [[ "$t" = /* ]] || { echo "npm ERR! publish requires an absolute tarball path" >&2; exit 2; }
    ver=$(tar -xzOf "$t" package/package.json | jq -r .version)
    case "$ver" in *-*)
      [[ " $* " == *" --tag "* ]] || { echo "npm error You must specify a tag using --tag when publishing a prerelease version." >&2; exit 1; } ;;
    esac
    $dry && exit 0
    mkdir -p "$NPM"; cp "$t" "$NPM/"
    tags="$NPM/dist-tags.json"; [ -e "$tags" ] || echo '{}' > "$tags"
    jq --arg t "$dt" --arg v "$ver" '.[$t] = $v' "$tags" > "$tags.new"; mv "$tags.new" "$tags" ;;
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
  "release create") # the prerelease mark is kept next to the asset directory
    mkdir -p "$RELEASE"
    if [[ " $* " == *" --prerelease "* ]]; then echo true; else echo false; fi > "$RELEASE.prerelease" ;;
  "release view") # gh release view <tag> --json isPrerelease --jq .isPrerelease
    if [ -n "$STUB_GH_FAIL" ]; then echo "HTTP 503: unavailable" >&2; exit 1; fi
    if [ ! -e "$RELEASE.prerelease" ]; then echo "release not found" >&2; exit 1; fi
    cat "$RELEASE.prerelease" ;;
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
# The verify scripts wait between tries; the stub returns at once, so a case can
# run out every retry.
cat > "$work/bin/sleep" <<'STUB'
#!/usr/bin/env bash
echo "sleep $*" >> "$LOG"
STUB
# build.sh and verify-npm.sh resolve their siblings from their own directory: a
# copy of build.sh next to a stub build-artifacts.sh runs the real decisions over
# a fake build, and a copy of verify-npm.sh next to a stub smoke-npm.sh reads the
# stub registry without installing anything.
mkdir -p "$work/rel"
cp "$here/build.sh" "$here/files.sh" "$here/download.sh" "$here/version.py" "$here/verify-npm.sh" "$work/rel/"
cat > "$work/rel/build-artifacts.sh" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail; echo "build-artifacts $*" >> "$LOG"
version=$1; out=$2; rm -rf "$out"; mkdir -p "$out"; here=$(dirname "$0")
for f in $("$here/files.sh" "$version"); do echo "built $f" > "$out/$f"; done
(cd "$out" && sha256sum $("$here/files.sh" "$version") > SHA256SUMS)
STUB
cat > "$work/rel/smoke-npm.sh" <<'STUB'
#!/usr/bin/env bash
echo "smoke-npm $*" >> "$LOG"
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

# smoke-python.sh and verify-pypi.sh, against what the cases above left on PyPI
installs_with_constraint() { # installs_with_constraint <version>: the SDK requested, fora-protocol a constraint only
  called "^uv pip install -q --python .venv -c [^ ]*/constraints.txt fora-protocol-sdk==$1$"
  called "^uv constraint fora-protocol==$1$"
  [ "$(grep -c '^uv constraint ' "$LOG")" = 1 ] || { echo "FAIL: expected exactly one constraint"; cat "$LOG"; exit 1; }
  not_called "^uv pip install .* fora-protocol==$1"
}
smoke="$here/smoke-python.sh"
run "smoke-python: --constraint -> a constraints file, not a requirement" 0 "$smoke" --constraint "fora-protocol==$bpy" "fora-protocol-sdk==$bpy"
installs_with_constraint "$bpy"
run "smoke-python: prerelease pin not named -> refused, as uv does" 1 "$smoke" "fora-protocol-sdk==$bpy"
said "the install does not name fora-protocol"
run "smoke-python: --constraint without a spec -> usage, no install" 2 "$smoke" --constraint
said "::error::--constraint needs a requirement spec"; not_called "uv pip install"
run "verify-pypi: final -> wheel through the pin, sdists rebuilt" 0 "$here/verify-pypi.sh" "$tag"
installs_with_constraint "$v"
for n in fora_protocol fora_protocol_sdk; do
  called "^curl -sSfL -o [^ ]*/$n-$v.tar.gz https://files.example/${n//_/-}/$n-$v.tar.gz$"
  called "^uv build -q --wheel --out-dir [^ ]* [^ ]*/$n-$v.tar.gz$"
done
not_called "^sleep"
run "verify-pypi: prerelease -> the PEP 440 spelling, fora-protocol a constraint" 0 "$here/verify-pypi.sh" "$btag"
installs_with_constraint "$bpy"
called "^curl -sSf https://pypi.org/pypi/fora-protocol-sdk/$bpy/json$"
called "^curl -sSfL -o [^ ]*/fora_protocol_sdk-$bpy.tar.gz "
run "verify-pypi: version never installs -> failure after 6 tries, no sdist lookup" 1 "$here/verify-pypi.sh" v1.3.0-beta.2
said "::error::fora-protocol-sdk 1.3.0b2 does not install from PyPI after 3 minutes"; one_error
[ "$(grep -c '^uv pip install ' "$LOG")" = 6 ] && [ "$(grep -c '^sleep 30$' "$LOG")" = 5 ] \
  || { echo "FAIL: expected 6 install tries 30 seconds apart"; cat "$LOG"; exit 1; }
not_called "^curl"
STUB_PYPI_STATUS=404 run "verify-pypi: sdist page never appears -> failure after 6 tries, nothing downloaded" 1 "$here/verify-pypi.sh" "$tag"
said "::error::fora-protocol $v sdist not visible on PyPI after 3 minutes"; one_error
[ "$(grep -c '^sleep 30$' "$LOG")" = 5 ] || { echo "FAIL: expected 6 lookups 30 seconds apart"; cat "$LOG"; exit 1; }
not_called "^curl -sSfL -o"
run "verify-pypi: unsupported tag -> failure, nothing installed" 1 "$here/verify-pypi.sh" v1.3.0-alpha.1
not_called "^uv "; not_called "^curl"

# publish-npm.sh
tgz="$dist/fora-protocol-sdk-$v.tgz"
run "npm: absent -> publish under the dist-tag latest" 0 "$here/publish-npm.sh" "$dist" "$v"
called "npm publish $tgz --access public --provenance --tag latest$"
run "npm: same integrity -> success, no publish" 0 "$here/publish-npm.sh" "$dist" "$v"
not_called "npm publish"
echo tampered >> "$NPM/fora-protocol-sdk-$v.tgz"
run "npm: different integrity -> failure, no publish" 1 "$here/publish-npm.sh" "$dist" "$v"
not_called "npm publish"
STUB_NPM_FAIL=1 run "npm: lookup failed -> failure, no publish" 1 "$here/publish-npm.sh" "$dist" "$v"
not_called "npm publish"
btgz="$bdist/fora-protocol-sdk-$b.tgz"
run "npm: prerelease absent -> publish under the dist-tag next" 0 "$here/publish-npm.sh" "$bdist" "$b"
called "npm view @fora-protocol/sdk@$b dist.integrity"
called "npm publish $btgz --access public --provenance --tag next$"
run "npm: prerelease same integrity -> success, no publish" 0 "$here/publish-npm.sh" "$bdist" "$b"
not_called "npm publish"
mkdir -p "$work/wrong" "$work/empty"; cp "$btgz" "$work/wrong/fora-protocol-sdk-1.3.0-beta.2.tgz"
run "npm: tarball version differs from the release -> failure, no publish" 1 "$here/publish-npm.sh" "$work/wrong" 1.3.0-beta.2
not_called "npm publish"
run "npm: no tarball for the version -> failure, npm not asked" 1 "$here/publish-npm.sh" "$work/empty" "$v"
not_called "npm "
run "npm: unsupported version -> failure, npm not asked" 1 "$here/publish-npm.sh" "$bdist" "$bpy"
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

# verify-npm.sh, against what the publish cases left on npm: 1.2.3 under latest,
# 1.3.0-beta.1 under next. Each refusal case then sets the dist-tags itself.
vnpm="$work/rel/verify-npm.sh"; tags="$NPM/dist-tags.json"
run "verify-npm: final under latest -> smoke test" 0 "$vnpm" "$tag"
called "^curl -sf -H Accept: application/vnd.npm.install-v1+json https://registry.npmjs.org/@fora-protocol/sdk$"
called "^smoke-npm @fora-protocol/sdk@$v$"; not_called "^sleep"
run "verify-npm: prerelease under next, latest elsewhere -> smoke test" 0 "$vnpm" "$btag"
called "^smoke-npm @fora-protocol/sdk@$b$"
echo "{\"latest\": \"$b\", \"next\": \"$b\"}" > "$tags"
run "verify-npm: prerelease also under latest -> failure, no smoke test" 1 "$vnpm" "$btag"
said "::error::the npm dist-tag latest points at the prerelease $b"; one_error; not_called "smoke-npm"
echo "{\"latest\": \"$b\", \"next\": \"1.3.0-beta.0\"}" > "$tags"
run "verify-npm: prerelease not under next -> failure, no smoke test" 1 "$vnpm" "$btag"
said "::error::the npm dist-tag next points at 1.3.0-beta.0, the release $btag requires $b"; one_error; not_called "smoke-npm"
run "verify-npm: final not under latest -> failure, no smoke test" 1 "$vnpm" "$tag"
said "::error::the npm dist-tag latest points at $b, the release $tag requires $v"; one_error; not_called "smoke-npm"
echo '{}' > "$tags"
run "verify-npm: no dist-tag -> failure, no smoke test" 1 "$vnpm" "$tag"
said "::error::the npm dist-tag latest points at nothing"; not_called "smoke-npm"
echo "{\"latest\": \"$v\", \"next\": \"$b\"}" > "$tags"
run "verify-npm: version never appears -> failure after 15 tries, no smoke test" 1 "$vnpm" v1.2.4
said "::error::@fora-protocol/sdk@1.2.4 not visible on npm after 5 minutes"; one_error
[ "$(grep -c '^curl ' "$LOG")" = 15 ] && [ "$(grep -c '^sleep 20$' "$LOG")" = 14 ] \
  || { echo "FAIL: expected 15 lookups 20 seconds apart"; cat "$LOG"; exit 1; }
not_called "smoke-npm"
run "verify-npm: unsupported tag -> failure, npm not asked" 1 "$vnpm" v1.3.0-alpha.1
not_called "^curl"; not_called "smoke-npm"

# build.sh
out="$work/out-dir"
run "build: no release -> build, upload files, then SHA256SUMS last" 0 "$work/rel/build.sh" "$tag" "$out"
called "build-artifacts $v"
called "gh release create $tag --verify-tag --title $tag --generate-notes$"
uploaded_in_order "$tag" "$v" "$v"
vgh="$here/verify-github-release.sh"
run "verify-github-release: final, not marked prerelease -> pass" 0 "$vgh" "$tag"
called "^gh release view $tag --json isPrerelease --jq .isPrerelease$"
run "verify-github-release: prerelease tag, release not marked -> failure" 1 "$vgh" "$btag"
said "::error::GitHub Release $btag has isPrerelease false, the tag requires true"; one_error
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
run "verify-github-release: prerelease, marked prerelease -> pass" 0 "$vgh" "$btag"
run "verify-github-release: final tag, release marked prerelease -> failure" 1 "$vgh" "$tag"
said "::error::GitHub Release $tag has isPrerelease true, the tag requires false"; one_error
STUB_GH_FAIL=1 run "verify-github-release: GitHub lookup failed -> failure" 1 "$vgh" "$btag"
run "verify-github-release: unsupported tag -> failure, GitHub not asked" 1 "$vgh" v1.3.0-alpha.1
not_called "gh "
run "build: prerelease SHA256SUMS on the release -> download and verify, no build" 0 "$work/rel/build.sh" "$btag" "$out"
called "gh release download $btag --pattern fora_protocol_sdk-$bpy-py3-none-any.whl"
not_called "build-artifacts"; not_called "release upload"; not_called "release create"
run "build: unsupported tag -> failure, GitHub not asked" 1 "$work/rel/build.sh" v1.3.0-alpha.1 "$out"
not_called "gh "; not_called "build-artifacts"
echo "test-decisions ok"
