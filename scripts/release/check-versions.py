#!/usr/bin/env python3
"""Release version gate.

The version in every released manifest must be the release version in that
ecosystem's spelling (scripts/release/version.py): the npm spelling in the
package.json files, the PEP 440 spelling in the pyproject.toml files. The
fora-protocol pin in sdk/python must equal it too (the two Python distributions
always move together). website/package.json is not part of the release. A
version the release tooling does not support fails the gate.

Takes the release tag as the release workflow passes it, or the version
without its v as pull-request CI passes the sdk/ts version; version.py reads
either.

    scripts/release/check-versions.py v1.2.3
    scripts/release/check-versions.py 1.3.0-beta.1
"""

import json
import pathlib
import sys
import tomllib

from version import parse

root = pathlib.Path(__file__).resolve().parents[2]
try:
    want = parse(sys.argv[1])
except ValueError as e:
    print(f"::error::{e}")
    sys.exit(1)


def toml_version(p: str) -> str:
    return tomllib.loads((root / p).read_text())["project"]["version"]


def json_version(p: str) -> str:
    return json.loads((root / p).read_text())["version"]


# manifest -> (found, expected)
found = {
    "gen/python/pyproject.toml": (toml_version("gen/python/pyproject.toml"), want.python),
    "sdk/python/pyproject.toml": (toml_version("sdk/python/pyproject.toml"), want.python),
    "gen/ts/package.json": (json_version("gen/ts/package.json"), want.npm),
    "sdk/ts/package.json": (json_version("sdk/ts/package.json"), want.npm),
    "package.json": (json_version("package.json"), want.npm),
}
pin = "fora-protocol=="
deps = tomllib.loads((root / "sdk/python/pyproject.toml").read_text())["project"]["dependencies"]
found["sdk/python/pyproject.toml fora-protocol pin"] = (
    next((d[len(pin) :] for d in deps if d.startswith(pin)), "<missing>"),
    want.python,
)

bad = {name: pair for name, pair in found.items() if pair[0] != pair[1]}
for name, (have, need) in bad.items():
    print(f"::error::{name} has version {have}, release {want.npm} requires {need}")
sys.exit(1 if bad else 0)
