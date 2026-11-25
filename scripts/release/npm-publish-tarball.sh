#!/usr/bin/env bash
# The one npm publish command of a release, for the dry run and the real publish:
# build-artifacts.sh runs it with --dry-run, in pull-request CI (sdk-types-ci.yml,
# on the paths that workflow watches) and in the tag's build job; publish-npm.sh
# runs it with --publish. Both modes pass the same flags. The mode is a required
# argument: no call publishes by default, and nothing in the environment selects it.
# The dist-tag is always explicit (scripts/release/version.py): a final release
# is published as `latest`, a prerelease as `next`, so `latest` never moves to a
# prerelease.
# The dry run runs under the job's bundled npm, not the npm 11 the publish job
# installs (release.yml), so it does not show that npm 11 accepts the command: npm
# 11 refuses a prerelease published without --tag, for one, and older npm does
# not. The npm stub in scripts/release/test-decisions.sh refuses as npm 11 does.
# A refusal exits 1, whatever status npm itself returned; a usage error exits 2.
#   scripts/release/npm-publish-tarball.sh --dry-run out/fora-protocol-sdk-1.3.0-beta.1.tgz 1.3.0-beta.1
#   scripts/release/npm-publish-tarball.sh --publish release-dist/fora-protocol-sdk-1.2.3.tgz 1.2.3
set -euo pipefail
case "${1:-}" in
  --dry-run) dry_run=(--dry-run) ;;
  --publish) dry_run=() ;;
  *) echo "usage: $0 --dry-run|--publish <tarball> <version>" >&2; exit 2 ;;
esac
[ $# = 3 ] || { echo "usage: $0 --dry-run|--publish <tarball> <version>" >&2; exit 2; }
if [ ! -f "$2" ] || [ ! -r "$2" ]; then
  echo "::error::no readable tarball $2"; exit 1
fi
here=$(cd "$(dirname "$0")" && pwd)
dist_tag=$(python3 "$here/version.py" "$3" dist-tag)
if ! npm publish ${dry_run[@]+"${dry_run[@]}"} "$2" --access public --provenance --tag "$dist_tag"; then
  echo "::error::npm publish${dry_run[@]+ ${dry_run[*]}} $2 under the dist-tag $dist_tag failed"; exit 1
fi
