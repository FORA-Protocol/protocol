#!/usr/bin/env bash
# What npm says about a package, for a release decision: npm view <spec> <field>,
# printed as npm prints it. Only "not found" is an answer of nothing. npm fails with
# E404 for a package the registry does not have, for a version it does not have, and
# for a range no published version satisfies, and this script then prints nothing
# and exits 0. Any other failure (5xx, network) is not an answer, and reading it as
# "nothing" would let a decision go ahead on no information: it exits 1, with
# npm's error. Stdout is the answer, so errors go to stderr. A usage error exits 2.
# It asks with --prefer-online, so package data npm cached a few minutes ago cannot
# hide a version published since: a release decision reads the registry as it is.
#   scripts/release/npm-view.sh @fora-protocol/sdk@1.2.3 dist.integrity
#   scripts/release/npm-view.sh '@fora-protocol/sdk@>1.2.3' version
set -euo pipefail
[ $# = 2 ] || { echo "usage: $0 <spec> <field>" >&2; exit 2; }
err=$(mktemp); trap 'rm -f "$err"' EXIT
if npm view "$1" "$2" --prefer-online 2>"$err"; then exit 0; fi
if grep -q E404 "$err"; then exit 0; fi
{ echo "::error::cannot ask npm for $1:"; cat "$err"; } >&2
exit 1
