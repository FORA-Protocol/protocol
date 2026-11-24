"""Tests over the repository's own gate scripts, manifests and lockfiles.

A gate names a tool that a lockfile pins by its package in the lockfile and by the key
of the manifest beside it that requires it. These tests read the real files, through
the declarations the gates make (toolfiles.declare, as ratchet.py reads them).

Run: python3 -m unittest discover -s scripts/gates -p 'test_*.py'
"""

from __future__ import annotations

import json
import re
import tomllib
import unittest
from pathlib import PurePosixPath

from lockfiles import is_lockfile, tool_name
from ratchet_harness import GATES
from toolfiles import declare, path_of

ROOT = GATES.parent.parent
# The manifest beside each lockfile, which requires what the lockfile locks.
MANIFESTS = {"package-lock.json": "package.json", "uv.lock": "pyproject.toml"}
# The fields of a package.json that install a package. A peer range is the package's
# published interface, not a pin of the project's own.
NPM_INSTALLS = ("dependencies", "devDependencies", "optionalDependencies")
# The name at the start of a Python requirement, such as `ruff` in `ruff==0.17.4`.
REQUIREMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


def read(rel: str) -> str | None:
    path = ROOT / rel
    return path.read_text(encoding="utf-8") if path.exists() else None


def tool_files(gate: str) -> frozenset[str]:
    """Return the tool files the gate script `gate` and the helper it runs declare."""
    text = read(gate)
    assert text is not None, gate
    return declare(text, gate, read).tool_files


def gates() -> list[str]:
    return sorted(f"scripts/gates/{p.name}" for p in GATES.glob("gate-*.sh"))


def normalized(name: str) -> str:
    """Return a Python package name as uv.lock spells it (PEP 503)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def npm_requires(manifest: str, name: str) -> list[str]:
    """Return the key paths of the package.json `manifest` that install `name`."""
    data = json.loads(manifest)
    return [f"{field}.{name}" for field in NPM_INSTALLS if name in data.get(field, {})]


def python_requires(manifest: str, name: str) -> list[str]:
    """Return the key paths of the lists in the pyproject.toml `manifest` requiring `name`."""
    data = tomllib.loads(manifest)
    project = data.get("project", {})
    lists = {"project.dependencies": project.get("dependencies", [])}
    for group, items in project.get("optional-dependencies", {}).items():
        lists[f"project.optional-dependencies.{group}"] = items
    for group, items in data.get("dependency-groups", {}).items():
        lists[f"dependency-groups.{group}"] = items
    return [
        key
        for key, items in lists.items()
        if any(
            isinstance(item, str) and (m := REQUIREMENT.match(item)) and normalized(m[0]) == name
            for item in items
        )
    ]


def requirements(lock: str, tool: str) -> tuple[str, list[str]]:
    """Return the manifest beside `lock`, and the key paths in it that require `tool`."""
    manifest = str(PurePosixPath(lock).with_name(MANIFESTS[PurePosixPath(lock).name]))
    text = read(manifest)
    if text is None:
        return manifest, []
    if lock.endswith("package-lock.json"):
        return manifest, npm_requires(text, tool.removeprefix("node_modules/"))
    return manifest, python_requires(text, tool)


def covered(key: str, parts: set[str]) -> bool:
    """Say whether the key path `key` is one of `parts`, inside one, or in a whole file (``)."""
    return any(not part or key == part or key.startswith(f"{part}.") for part in parts)


class LockfileToolTest(unittest.TestCase):
    def test_a_tool_a_lockfile_pins_is_named_in_the_manifest_beside_it_too(self) -> None:
        # Its upgrade edits both; a requirement of it that no part names would count as an
        # edit beyond the tool, and so would block the upgrade's re-key.
        checked = 0
        for gate in gates():
            declared = tool_files(gate)
            for spec in sorted(declared):
                path, _, part = spec.partition("#")
                if not part or not is_lockfile(path):
                    continue
                manifest, keys = requirements(path, tool_name(path, part))
                named = {s.partition("#")[2] for s in declared if path_of(s) == manifest}
                for key in keys:
                    checked += 1
                    with self.subTest(gate=gate, tool=spec, requirement=f"{manifest}#{key}"):
                        self.assertTrue(covered(key, named), sorted(named))
        self.assertGreater(checked, 0, "no gate names a tool by its part of a lockfile")


if __name__ == "__main__":
    unittest.main()
