#!/usr/bin/env bash
# The one npm publish command of a release, for the dry run and the real publish.
# build-artifacts.sh runs it with --dry-run on every pull request, so the flags
# the tag's real publish (publish-npm.sh, --publish) passes are the flags the
# dry run has already had accepted. The mode is a required argument: no call
# publishes by default, and nothing in the environment selects the mode.
# The dist-tag is always explicit (scripts/release/version.py): a final release
# is published as `latest`, a prerelease as `next`, so `latest` never moves to a
# prerelease. npm 11 refuses to publish a prerelease without --tag.
#   scripts/release/npm-publish-tarball.sh --dry-run out/fora-protocol-sdk-1.3.0-beta.1.tgz 1.3.0-beta.1
#   scripts/release/npm-publish-tarball.sh --publish release-dist/fora-protocol-sdk-1.2.3.tgz 1.2.3
set -euo pipefail
case "${1:-}" in
  --dry-run) dry_run=(--dry-run) ;;
  --publish) dry_run=() ;;
  *) echo "usage: $0 --dry-run|--publish <tarball> <version>" >&2; exit 2 ;;
esac
[ $# = 3 ] || { echo "usage: $0 --dry-run|--publish <tarball> <version>" >&2; exit 2; }
here=$(cd "$(dirname "$0")" && pwd)
dist_tag=$(python3 "$here/version.py" "$3" dist-tag)
npm publish ${dry_run[@]+"${dry_run[@]}"} "$2" --access public --provenance --tag "$dist_tag"
