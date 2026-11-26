#!/usr/bin/env bash
# The output directory of a release script: <dir> when it is new or empty, created
# when absent, printed as an absolute path. Anything else is refused, never emptied:
# a file, a link to nothing, a directory with an entry in it, or one that cannot be
# listed. No release script deletes anything of the caller's, so a mistyped
# argument such as `.` or /tmp costs a refusal, not the directory.
# A link to a directory is read through (find -H): without that, find reports no
# entries for the link itself, and a full directory would read as empty.
# Stdout is the path, so a refusal goes to stderr. A refusal exits 1, usage 2.
#   out=$(scripts/release/out-dir.sh release-dist)
set -euo pipefail
[ $# = 1 ] || { echo "usage: $0 <dir>" >&2; exit 2; }
d=$1
case "$d" in -*) d=./$d ;; esac # find and mkdir would read a leading - as an option
refuse() {
  echo "::error::$d $1: a release script writes only into a new or empty directory, and deletes nothing" >&2
  exit 1
}
if [ -e "$d" ] || [ -L "$d" ]; then
  [ -d "$d" ] || refuse "is not a directory"
  if ! first=$(find -H "$d" -mindepth 1 -maxdepth 1 -print -quit) || [ -n "$first" ]; then
    refuse "is not empty, or cannot be listed"
  fi
fi
mkdir -p -- "$d"
cd -- "$d" >/dev/null && pwd
