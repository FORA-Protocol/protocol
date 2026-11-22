#!/usr/bin/env bash
# The release artifact set for a version, one file name per line.
# Derived from the manifests: wheel + sdist for fora-protocol (gen/python) and
# fora-protocol-sdk (sdk/python), and the @fora-protocol/sdk tarball. The Python
# file names carry the PEP 440 spelling of the version, the tarball the npm one
# (scripts/release/version.py): 1.3.0-beta.1 names fora_protocol-1.3.0b1.tar.gz
# and fora-protocol-sdk-1.3.0-beta.1.tgz.
#   scripts/release/files.sh 1.2.3
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
py=$(python3 "$here/version.py" "$1" python)
npm=$(python3 "$here/version.py" "$1" npm)
printf '%s\n' \
  "fora_protocol-$py.tar.gz" \
  "fora_protocol-$py-py3-none-any.whl" \
  "fora_protocol_sdk-$py.tar.gz" \
  "fora_protocol_sdk-$py-py3-none-any.whl" \
  "fora-protocol-sdk-$npm.tgz"
