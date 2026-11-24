"""Tests for lockfiles.py: which part of a lockfile a tool is, and what is left.

A tool's part of a lockfile is its package, the packages only the tools bring, and the
entries that record the project's requirement of it. Everything else is the code's,
including a package the code needs too. The lockfiles are ratchet_harness's small npm
and uv lockfiles of a project that requires `app` and the tool `lint`.

Run: python3 -m unittest discover -s scripts/gates -p 'test_*.py'
"""

from __future__ import annotations

import json
import unittest

from lockfiles import split, tool_name
from ratchet_harness import npm_entry, npm_lock, npm_text, replace_once, uv_entry, uv_lock

NPM = "sdk/package-lock.json"
UV = "sdk/uv.lock"
LINT = "packages.node_modules/lint"
BINARIES = {"node_modules/lint-x64", "node_modules/lint-arm64"}


def at(value: object, *keys: str) -> object:
    """Return value[keys[0]][keys[1]]…, each step into a table."""
    for key in keys:
        assert isinstance(value, dict), value
        value = value[key]
    return value


def own(found: dict[str, object | None], part: str) -> set[str]:
    """Return the packages in the footprint of `part`."""
    packages = at(found[part], "packages")
    assert isinstance(packages, dict)
    return set(packages)


def npm_split(
    packages: dict[str, dict[str, object]], *tools: str
) -> tuple[dict[str, object | None], object]:
    """Return the footprint of each tool (by package name) and the rest of the lockfile."""
    return split(NPM, npm_text(packages), [f"packages.node_modules/{t}" for t in tools])


def with_project(packages: dict[str, dict[str, object]], **fields: object) -> None:
    """Set `fields` of the project's entry in `packages`."""
    packages[""] = {**packages[""], **fields}


def uv_split(text: str) -> tuple[dict[str, object | None], object]:
    return split(UV, text, ["package.lint"])


class NpmFootprintTest(unittest.TestCase):
    def test_a_tool_brings_its_platform_binaries_and_not_what_the_code_needs(self) -> None:
        found, _ = npm_split(npm_lock(), "lint")
        self.assertEqual(own(found, LINT), {"node_modules/lint", *BINARIES})

    def test_the_projects_record_of_the_pin_is_the_tools_and_its_peer_range_is_not(
        self,
    ) -> None:
        packages = npm_lock()
        with_project(packages, peerDependencies={"lint": "^2"})
        found, rest = npm_split(packages, "lint")
        self.assertEqual(at(found[LINT], "pins"), [["", "devDependencies", "2.0.0"]])
        self.assertEqual(at(rest, "packages", "", "devDependencies"), {})
        self.assertEqual(at(rest, "packages", "", "peerDependencies"), {"lint": "^2"})
        self.assertEqual(at(rest, "packages", "", "dependencies"), {"app": "^1"})

    def test_the_rest_changes_with_the_code_and_not_with_the_tool(self) -> None:
        _, before = npm_split(npm_lock(), "lint")
        upgrade = npm_lock("3.0.0")
        del upgrade["node_modules/lint-arm64"]
        self.assertEqual(npm_split(upgrade, "lint")[1], before)
        for path in ("~shared", "~app"):
            bumped = npm_lock(**{path: npm_entry("9.9.9")})
            with self.subTest(bumped=path):
                self.assertNotEqual(npm_split(bumped, "lint")[1], before)

    def test_a_package_nested_under_the_tool_is_the_tools_and_the_hoisted_one_is_not(
        self,
    ) -> None:
        packages = npm_lock(
            **{"~lint": npm_entry("2.0.0", dependencies={"semver": "^7"})},
            **{"~lint/~semver": npm_entry("7.0.0"), "~semver": npm_entry("6.0.0")},
            **{"~app": npm_entry(dependencies={"semver": "^6"})},
        )
        found, _ = npm_split(packages, "lint")
        self.assertIn("node_modules/lint/node_modules/semver", own(found, LINT))
        self.assertNotIn("node_modules/semver", own(found, LINT))

    def test_the_walk_from_the_code_stops_at_a_tool(self) -> None:
        # app reaches the tool `types` through an optional peer; what only `types` brings
        # is still the tool's.
        app = npm_entry(peerDependencies={"types": "*"}, dependencies={"shared": "^1"})
        types = npm_entry(dependencies={"types-util": "^1"})
        packages = npm_lock(**{"~app": app, "~types": types, "~types-util": npm_entry()})
        found, _ = npm_split(packages, "lint", "types")
        types_own = {"node_modules/types", "node_modules/types-util"}
        self.assertEqual(own(found, "packages.node_modules/types"), types_own)

    def test_what_a_dependencys_peer_or_a_workspace_member_needs_is_the_codes(self) -> None:
        cases: dict[str, dict[str, dict[str, object]]] = {
            "a peer": {"~app": npm_entry(peerDependencies={"util": "*"})},
            "a member": {"packages/ws": {"name": "ws", "dependencies": {"util": "^1"}}},
        }
        lint = npm_entry("2.0.0", dependencies={"util": "^1"})
        for case, extra in cases.items():
            packages = npm_lock(**extra, **{"~lint": lint, "~util": npm_entry()})
            with self.subTest(case=case):
                self.assertEqual(own(npm_split(packages, "lint")[0], LINT), {"node_modules/lint"})

    def test_a_package_only_the_tools_need_is_each_tools(self) -> None:
        common = npm_entry(dependencies={"common": "^1"})
        packages = npm_lock(**{"~lint": common, "~fmt": common, "~common": npm_entry()})
        with_project(packages, devDependencies={"lint": "2.0.0", "fmt": "^1"})
        found, _ = npm_split(packages, "lint", "fmt")
        for tool in ("lint", "fmt"):
            with self.subTest(tool=tool):
                self.assertIn("node_modules/common", own(found, f"packages.node_modules/{tool}"))
        # When fmt is not one of the gate's tools, it is the code's, and so is what it needs.
        found, _ = npm_split(packages, "lint")
        self.assertNotIn("node_modules/common", own(found, LINT))

    def test_a_dotted_name_is_one_package_and_a_missing_one_holds_nothing(self) -> None:
        packages = npm_lock(**{"~lodash.merge": npm_entry()})
        with_project(packages, devDependencies={"lodash.merge": "^1"})
        found, _ = npm_split(packages, "lodash.merge", "absent")
        dotted = own(found, "packages.node_modules/lodash.merge")
        self.assertEqual(dotted, {"node_modules/lodash.merge"})
        self.assertIsNone(found["packages.node_modules/absent"])


class RefusalTest(unittest.TestCase):
    def test_a_part_that_names_no_package_is_refused(self) -> None:
        refused = {
            NPM: ("lockfileVersion", "packages.", "packages.sdk/ws", f"{LINT}/node_modules/b"),
            UV: ("version", "package.", "package.zope.interface", "manifest.members"),
        }
        for path, parts in refused.items():
            for part in parts:
                with (
                    self.subTest(path=path, part=part),
                    self.assertRaisesRegex(ValueError, "names no package"),
                ):
                    tool_name(path, part)

    def test_a_lockfile_with_no_packages_or_no_syntax_is_refused(self) -> None:
        cases = {
            NPM: (json.dumps({"lockfileVersion": 1, "dependencies": {}}), "no `packages` map"),
            UV: ("version = 1\n", r"no \[\[package\]\] entries"),
        }
        for path, (text, why) in cases.items():
            part = LINT if path == NPM else "package.lint"
            with self.subTest(path=path):
                self.assertRaisesRegex(ValueError, why, split, path, text, [part])
                self.assertRaises(ValueError, split, path, "{not a lockfile", [part])


class UvFootprintTest(unittest.TestCase):
    def test_a_tool_brings_its_own_dependencies_and_its_pins(self) -> None:
        found, rest = uv_split(uv_lock())
        self.assertEqual(own(found, "package.lint"), {"lint", "lint-util"})
        self.assertEqual(
            at(found["package.lint"], "pins"),
            [
                ["proj.dev-dependencies.gates", {"name": "lint"}],
                ["proj.metadata.requires-dev.gates", {"name": "lint", "specifier": "==2.0.0"}],
            ],
        )
        entries = at(rest, "package")
        assert isinstance(entries, list)
        self.assertEqual([at(e, "name") for e in entries], ["proj", "app", "shared"])

    def test_the_rest_changes_with_the_code_and_not_with_the_tool(self) -> None:
        _, before = uv_split(uv_lock())
        self.assertEqual(uv_split(uv_lock(lint="3.0.0", lint_util="1.1.0"))[1], before)
        for package in ("shared", "app", "proj"):
            with self.subTest(bumped=package):
                self.assertNotEqual(uv_split(uv_lock(**{package: "9.9.9"}))[1], before)

    def test_what_any_extra_group_platform_or_manifest_requires_is_the_codes(self) -> None:
        # Each case makes lint-util, which lint needs, a requirement of the code's too. The
        # first three change app's entry or proj's gates group, which the lockfile holds once.
        app_needs = 'dependencies = [{ name = "shared" }]\n'
        extra = '[package.optional-dependencies]\nfast = [{ name = "speedup" }]\n'
        marker = '{ name = "lint-util", marker = "sys_platform == \'win32\'" }'
        gates = 'gates = [{ name = "lint" }]\n'
        member = 'name = "lint-util"'
        cases = {
            "an extra": replace_once(
                uv_lock(uv_entry("speedup", "1.0.0", member)), app_needs, app_needs + extra
            ),
            "a marker": replace_once(
                uv_lock(), app_needs, f'dependencies = [{{ name = "shared" }}, {marker}]\n'
            ),
            "a group": replace_once(uv_lock(), gates, f"{gates}docs = [{{ {member} }}]\n"),
            "the manifest": uv_lock(tail=f"\n[manifest]\nrequirements = [{{ {member} }}]\n"),
            "a virtual member": uv_lock(uv_entry("ws", "0.1.0", member, source='virtual = "ws"')),
            "a directory member": uv_lock(
                uv_entry("ws", "0.1.0", member, source='directory = "ws"')
            ),
        }
        for case, text in cases.items():
            with self.subTest(case=case):
                self.assertEqual(own(uv_split(text)[0], "package.lint"), {"lint"})

    def test_every_version_of_a_name_is_one_package(self) -> None:
        found, _ = uv_split(uv_lock(uv_entry("lint-util", "2.0.0")))
        versions = at(found["package.lint"], "packages", "lint-util")
        assert isinstance(versions, list)
        self.assertEqual(len(versions), 2)


if __name__ == "__main__":
    unittest.main()
