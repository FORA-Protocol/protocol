#!/usr/bin/env bash
#
# Astro type gate: the documentation site's Astro components, type-checked by the
# checker `astro check` runs (@astrojs/language-server), against
# scripts/gates/baselines/astro-types.json. tsc does not read .astro files, so this
# gate is their type gate; gate-ts-types.sh checks the site's TypeScript and
# JavaScript. website/scripts/astro-check.mjs runs the checker over the site's own
# project (website/tsconfig.json), with the strictness settings of
# tsconfig.strict.json, and refuses a run in which an import does not resolve. The
# checker and its TypeScript are pinned by website/package-lock.json, which
# scripts/gates/node-tools.sh checks.
#
# Usage:  scripts/gates/gate-astro-types.sh [--base-ref REF]          check the tree
#         scripts/gates/gate-astro-types.sh record [--base-ref REF]   shrink the baseline
# record carries the entry of a finding that moved; with --base-ref, also across a
# renamed or copied file, and across a change of the gate's tool alone: a file passed
# with --tool-file below (the runner, the site's project and what it extends, and
# the pins of the checker, its TypeScript and Astro), a pin that node-tools.sh
# passes, or the reader in formats.py.

set -euo pipefail
cd "$(dirname "$0")/../.."
exec scripts/gates/node-tools.sh ratchet "scripts/gates/${0##*/}" astro-check \
  scripts/gates/baselines/astro-types.json \
  "$@" --tool-file website/scripts/astro-check.mjs \
  --tool-file website/tsconfig.json --tool-file tsconfig.strict.json \
  --tool-file website/package.json#devDependencies.@astrojs/language-server \
  --tool-file website/package.json#devDependencies.typescript \
  --tool-file website/package-lock.json#packages.node_modules/@astrojs/language-server \
  --tool-file website/package-lock.json#packages.node_modules/typescript \
  --tool-file website/package-lock.json#packages.node_modules/astro \
  --tool-file website/package.json#dependencies.astro \
  -- node website/scripts/astro-check.mjs
