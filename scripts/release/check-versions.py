#!/usr/bin/env python3
"""Release version gate (FORA-291).

The tag version must equal the version in every released manifest, and the
fora-protocol pin in sdk/python must equal it too (the two Python distributions
always move together). website/package.json is not part of the release.

    scripts/release/check-versions.py 1.2.3
"""
import json
import pathlib
import sys
import tomllib

root = pathlib.Path(__file__).resolve().parents[2]
want = sys.argv[1]


def toml_version(p: str) -> str:
    return tomllib.loads((root / p).read_text())["project"]["version"]


def json_version(p: str) -> str:
    return json.loads((root / p).read_text())["version"]


found = {
    "gen/python/pyproject.toml": toml_version("gen/python/pyproject.toml"),
    "sdk/python/pyproject.toml": toml_version("sdk/python/pyproject.toml"),
    "gen/ts/package.json": json_version("gen/ts/package.json"),
    "sdk/ts/package.json": json_version("sdk/ts/package.json"),
    "package.json": json_version("package.json"),
}
pin = "fora-protocol=="
deps = tomllib.loads((root / "sdk/python/pyproject.toml").read_text())["project"]["dependencies"]
found["sdk/python/pyproject.toml fora-protocol pin"] = next(
    (d[len(pin):] for d in deps if d.startswith(pin)), "<missing>"
)

bad = {k: v for k, v in found.items() if v != want}
for k, v in bad.items():
    print(f"::error::{k} has version {v}, tag is {want}")
sys.exit(1 if bad else 0)
