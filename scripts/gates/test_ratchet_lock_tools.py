"""Tests for re-keying a baseline when the gate's tool is a package of a lockfile.

The gate names its tool, lint, by its pin in a manifest and its package in the lockfile
beside it (`FILE#PART`). A new version of the tool changes its package, the packages only
it brings (a platform binary, a dependency of its own) and the entries that record its
pin, and each of those is a change to the tool. The lockfiles are ratchet_harness's small
npm and uv lockfiles of a project that requires `app` and the tool `lint`.

Run: python3 -m unittest discover -s scripts/gates -p 'test_*.py'
"""

from __future__ import annotations

import json
import unittest

from ratchet_harness import (
    GATE_SCRIPT,
    ToolChangeCase,
    names_tools,
    npm_entry,
    npm_lock,
    npm_text,
    uv_lock,
)

NPM_MANIFEST = "tools/package.json"
NPM_LOCK = "tools/package-lock.json"
NPM_PARTS = (f"{NPM_MANIFEST}#devDependencies.lint", f"{NPM_LOCK}#packages.node_modules/lint")
UV_MANIFEST = "tools/pyproject.toml"
UV_LOCK = "tools/uv.lock"
UV_PARTS = (f"{UV_MANIFEST}#dependency-groups.gates", f"{UV_LOCK}#package.lint")


def npm_files(
    packages: dict[str, dict[str, object]] | None = None, lint: str = "2.0.0"
) -> dict[str, str]:
    """Return proj's package.json, with lint's pin at `lint`, and its lockfile."""
    manifest = {
        "name": "proj",
        "imports": {"#x": "./x.js"},
        "dependencies": {"app": "^1"},
        "devDependencies": {"lint": lint},
    }
    locked = npm_lock(lint) if packages is None else packages
    return {NPM_MANIFEST: json.dumps(manifest, indent=2), NPM_LOCK: npm_text(locked)}


def uv_files(lint: str = "2.0.0", proj: str = "1.0.0", **versions: str) -> dict[str, str]:
    """Return proj's pyproject.toml, with lint's pin at `lint`, and its uv.lock."""
    manifest = (
        f'[project]\nname = "proj"\nversion = "{proj}"\ndependencies = ["app>=1"]\n\n'
        f'[dependency-groups]\ngates = ["lint=={lint}"]\n'
    )
    return {UV_MANIFEST: manifest, UV_LOCK: uv_lock(lint=lint, proj=proj, **versions)}


class LockToolCase(ToolChangeCase):
    """On main, the gate names its tool files (`tool_files`), which `files()` holds."""

    def files(self) -> dict[str, str]:
        raise NotImplementedError

    def setUp(self) -> None:
        super().setUp()
        self.files_on_main(self.files())

    def change(self, files: dict[str, str]) -> None:
        for path, text in files.items():
            self.repo.write(path, text)

    def assert_rekeys(self, *edited: str) -> None:
        """Assert that `record --base-ref` re-keys the reworded findings, naming `edited`."""
        proc = self.base("record", self.reworded())
        self.assert_passes(proc)
        self.assertIn("this change edits nothing else", proc.stderr)
        for spec in edited:
            self.assertIn(spec, proc.stderr)

    def assert_refused(self, spec: str) -> None:
        """Assert that ratchet.py refuses `spec`, a lockfile part that names no package."""
        proc = self.repo.run("check", [], "--gate", GATE_SCRIPT, "--tool-file", spec)
        self.assert_fails(proc, f"--tool-file {spec} cannot be read: names no package", code=2)


class NpmLockToolTest(LockToolCase):
    gate_text = names_tools(*NPM_PARTS)
    tool_files = NPM_PARTS

    def files(self) -> dict[str, str]:
        return npm_files()

    def test_a_new_version_of_the_tool_rekeys_the_baseline(self) -> None:
        # The pin, the package, both platform binaries and the lockfile's record of the pin.
        self.change(npm_files(npm_lock("3.0.0"), lint="3.0.0"))
        self.assert_rekeys(*NPM_PARTS)

    def test_a_platform_binary_of_the_tool_is_the_tool(self) -> None:
        self.change(npm_files(npm_lock(**{"~lint-x64": npm_entry("2.0.1")})))
        self.assert_rekeys(NPM_PARTS[1])

    def test_a_part_of_the_lockfile_that_names_no_package_is_refused(self) -> None:
        self.assert_refused(f"{NPM_LOCK}#lockfileVersion")


class UvLockToolTest(LockToolCase):
    gate_text = names_tools(*UV_PARTS)
    tool_files = UV_PARTS

    def files(self) -> dict[str, str]:
        return uv_files()

    def test_a_new_version_of_the_tool_rekeys_the_baseline(self) -> None:
        # The pin, the package and the lockfile's record of the pin.
        self.change(uv_files(lint="3.0.0"))
        self.assert_rekeys(*UV_PARTS)

    def test_a_dependency_only_the_tool_brings_is_the_tool(self) -> None:
        self.change(uv_files(lint_util="1.1.0"))
        self.assert_rekeys(UV_PARTS[1])

    def test_a_part_of_the_lockfile_that_names_no_package_is_refused(self) -> None:
        self.assert_refused(f"{UV_LOCK}#version")


if __name__ == "__main__":
    unittest.main()
