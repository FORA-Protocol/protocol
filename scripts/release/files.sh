#!/usr/bin/env bash
# The release artifact set for a version, one file name per line (FORA-291).
# Derived from the manifests: wheel + sdist for fora-protocol (gen/python) and
# fora-protocol-sdk (sdk/python), and the @fora-protocol/sdk tarball.
#   scripts/release/files.sh 1.2.3
set -euo pipefail
v=$1
printf '%s\n' \
  "fora_protocol-$v.tar.gz" \
  "fora_protocol-$v-py3-none-any.whl" \
  "fora_protocol_sdk-$v.tar.gz" \
  "fora_protocol_sdk-$v-py3-none-any.whl" \
  "fora-protocol-sdk-$v.tgz"
