"""Tests over the repository's own gate scripts, manifests and lockfiles.

A gate names a tool that a lockfile pins by its package in the lockfile and by the key
of the manifest beside it that requires it. These tests read the real files, through
the declarations the gates make (toolfiles.declare, as ratchet.py reads them), and sort
upgrades made in memory as `ratchet.py --base-ref` would (toolfiles.tool_edits): an
upgrade of a tool alone is a change to the tool, and one that also moves what the code
depends on is not. The packages each upgrade moves are read from the lockfile, so the
tests follow the lockfiles as they change.

Run: python3 -m unittest discover -s scripts/gates -p 'test_*.py'
"""

from __future__ import annotations

import json
import re
import tomllib
import unittest
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any

from lockfiles import is_lockfile, tool_name
from ratchet_harness import GATES, replace_once
from toolfiles import declare, path_of, tool_edits

if TYPE_CHECKING:
    from collections.abc import Callable

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


NPM_LOCK = "sdk/ts/package-lock.json"
NPM_MANIFEST = "sdk/ts/package.json"
UV_LOCK = "sdk/python/uv.lock"
PYPROJECT = "sdk/python/pyproject.toml"
TS_GATES = ("gate-ts-format.sh", "gate-ts-lint.sh", "gate-ts-types.sh")
PYTHON_GATES = ("gate-python-format.sh", "gate-python-lint.sh", "gate-python-types.sh")
BEYOND = " beyond the tool's part"
NEW = "9.9.9"


def loaded(rel: str) -> Any:
    text = read(rel)
    assert text is not None, rel
    return json.loads(text) if rel.endswith(".json") else tomllib.loads(text)


class Change:
    """A change to the repository's files, held in memory over the files as they are."""

    def __init__(self) -> None:
        self.files: dict[str, str] = {}

    def read(self, rel: str) -> str | None:
        return self.files[rel] if rel in self.files else read(rel)

    def json(self, rel: str, edit: Callable[[Any], object]) -> None:
        data = json.loads(self.read(rel) or "")
        edit(data)
        self.files[rel] = json.dumps(data, indent=2)

    def text(self, rel: str, old: str, new: str) -> None:
        self.files[rel] = replace_once(self.read(rel) or "", old, new)

    def sorted_by(self, gate: str) -> tuple[list[str], list[str]]:
        """Return how the gate sorts this change: the tool files it edits, and its other edits."""
        declared = tool_files(f"scripts/gates/{gate}")
        return tool_edits(declared, frozenset(self.files), read, self.read)


def npm_dependents(packages: dict[str, Any], name: str) -> set[str]:
    """Return the install paths of the packages that list `name` among what they need."""
    fields = ("dependencies", "optionalDependencies", "peerDependencies")
    return {path for path, e in packages.items() if any(name in e.get(f, {}) for f in fields)}


def npm_upgrade(change: Change, name: str, *, pin: bool = True) -> list[str]:
    """Upgrade the SDK's `name` as npm does: its package, each package it lists, and with
    `pin` its pin in package.json and in the lockfile's record. Return what it lists."""
    packages = loaded(NPM_LOCK)["packages"]
    entry = packages[f"node_modules/{name}"]
    moved = [*entry.get("dependencies", {}), *entry.get("optionalDependencies", {}), name]
    change.json(NPM_LOCK, lambda d: npm_move(d["packages"], moved))
    if pin:
        change.json(NPM_MANIFEST, lambda d: d["devDependencies"].update({name: NEW}))
        change.json(NPM_LOCK, lambda d: d["packages"][""]["devDependencies"].update({name: NEW}))
    return moved[:-1]


def npm_move(packages: dict[str, Any], names: list[str]) -> None:
    """Move each of the packages `names` to version NEW in a lockfile's `packages` map."""
    for name in names:
        packages[f"node_modules/{name}"]["version"] = NEW


def uv_packages() -> dict[str, Any]:
    return {p["name"]: p for p in loaded(UV_LOCK)["package"]}


def uv_needs(name: str) -> list[str]:
    return [d["name"] for d in uv_packages()[name].get("dependencies", [])]


def uv_dependents(name: str) -> set[str]:
    return {
        n
        for n, p in uv_packages().items()
        if name in [d["name"] for d in p.get("dependencies", [])]
    }


def mypy_and_its_needs() -> set[str]:
    """Return mypy and the packages it needs: a package only they need is mypy's own."""
    return {"mypy", *uv_needs("mypy")}


def uv_move(change: Change, name: str) -> None:
    """Move the package `name` in the SDK's uv.lock to version NEW."""
    old = uv_packages()[name]["version"]
    change.text(
        UV_LOCK, f'name = "{name}"\nversion = "{old}"', f'name = "{name}"\nversion = "{NEW}"'
    )


def uv_upgrade(change: Change, name: str) -> None:
    """Upgrade the gates group's `name` as uv does: its package, its pin in pyproject.toml
    and the lockfile's record of that pin."""
    old = uv_packages()[name]["version"]
    uv_move(change, name)
    record = '{{ name = "{}", specifier = "=={}" }}'
    change.text(UV_LOCK, record.format(name, old), record.format(name, NEW))
    change.text(PYPROJECT, f'"{name}=={old}"', f'"{name}=={NEW}"')


class ToolUpgradeTest(unittest.TestCase):
    """Upgrades of the real tools, sorted by the real gates' declarations."""

    def assert_tool_change(self, change: Change, gates: tuple[str, ...], *specs: str) -> None:
        for gate in gates:
            edited, others = change.sorted_by(gate)
            with self.subTest(gate=gate):
                self.assertEqual(set(specs) - set(edited), set())
                self.assertEqual(others, [])

    def assert_beyond(self, change: Change, gates: tuple[str, ...], *paths: str) -> None:
        for gate in gates:
            with self.subTest(gate=gate):
                self.assertEqual(change.sorted_by(gate)[1], sorted(p + BEYOND for p in paths))

    def test_a_biome_upgrade_is_a_change_to_the_tool_of_every_npm_gate(self) -> None:
        change = Change()
        binaries = npm_upgrade(change, "@biomejs/biome")
        self.assertTrue(binaries, "biome lists no platform binary")
        biome = ("devDependencies.@biomejs/biome", "packages.node_modules/@biomejs/biome")
        specs = (f"{NPM_MANIFEST}#{biome[0]}", f"{NPM_LOCK}#{biome[1]}")
        self.assert_tool_change(change, TS_GATES, *specs)

    def test_a_typescript_upgrade_within_its_range_is_a_change_to_the_tool(self) -> None:
        change = Change()
        npm_upgrade(change, "typescript", pin=False)
        self.assert_tool_change(change, TS_GATES, f"{NPM_LOCK}#packages.node_modules/typescript")

    def test_a_type_package_upgrade_is_a_change_to_the_type_gates_tool_alone(self) -> None:
        for package in ("@types/node", "@cloudflare/workers-types"):
            change = Change()
            for listed in npm_upgrade(change, package):
                packages = loaded(NPM_LOCK)["packages"]
                self.assertEqual(npm_dependents(packages, listed), {f"node_modules/{package}"})
            with self.subTest(package=package):
                self.assert_tool_change(change, ("gate-ts-types.sh",))
                self.assert_beyond(change, ("gate-ts-lint.sh",), NPM_LOCK, NPM_MANIFEST)

    def test_an_npm_upgrade_with_a_dependency_or_the_version_of_the_sdk_is_not(self) -> None:
        dependency = min(loaded(NPM_LOCK)["packages"][""]["dependencies"])
        cases: dict[str, Callable[[Change], None]] = {
            f"the SDK's dependency {dependency}": lambda c: c.json(
                NPM_LOCK, lambda d: npm_move(d["packages"], [dependency])
            ),
            "the SDK's version": lambda c: c.json(NPM_MANIFEST, lambda d: d.update(version=NEW)),
        }
        beyond = {"the SDK's version": NPM_MANIFEST}
        for case, edit in cases.items():
            change = Change()
            npm_upgrade(change, "@biomejs/biome")
            edit(change)
            with self.subTest(case=case):
                self.assert_beyond(change, TS_GATES, beyond.get(case, NPM_LOCK))

    def test_a_ruff_upgrade_is_a_change_to_the_tool_of_every_python_gate(self) -> None:
        change = Change()
        uv_upgrade(change, "ruff")
        specs = (f"{PYPROJECT}#dependency-groups.gates", f"{UV_LOCK}#package.ruff")
        self.assert_tool_change(change, PYTHON_GATES, *specs)

    def test_a_mypy_upgrade_with_the_packages_only_it_needs_is_a_change_to_the_tool(
        self,
    ) -> None:
        own = [d for d in uv_needs("mypy") if uv_dependents(d) <= mypy_and_its_needs()]
        if not own:
            self.skipTest("mypy needs no package that only it needs")
        change = Change()
        uv_upgrade(change, "mypy")
        for package in own:
            uv_move(change, package)
        self.assert_tool_change(change, PYTHON_GATES, f"{UV_LOCK}#package.mypy")

    def test_a_mypy_upgrade_with_a_package_the_code_needs_too_is_not(self) -> None:
        shared = [d for d in uv_needs("mypy") if uv_dependents(d) - mypy_and_its_needs()]
        if not shared:
            self.skipTest("mypy shares no package with the code")
        change = Change()
        uv_upgrade(change, "mypy")
        uv_move(change, shared[0])
        self.assert_beyond(change, PYTHON_GATES, UV_LOCK)

    def test_a_dependency_of_the_sdk_beside_a_helper_edit_is_not_a_tool_change(self) -> None:
        # The helper is a whole tool file: an edit to it is a change to the tool. The
        # dependency's new version is the code's, so nothing is re-keyed.
        projects = {"fora-protocol", "fora-protocol-sdk"}
        dependency = next(d for d in uv_needs("fora-protocol-sdk") if d not in projects)
        change = Change()
        uv_move(change, dependency)
        helper = "scripts/gates/python-tools.sh"
        change.files[helper] = (read(helper) or "") + "# a comment\n"
        for gate in PYTHON_GATES:
            edited, others = change.sorted_by(gate)
            with self.subTest(gate=gate):
                self.assertIn(helper, edited)
                self.assertEqual(others, [UV_LOCK + BEYOND])


if __name__ == "__main__":
    unittest.main()
