"""Tests that the type gate passes, as tool files, every tsconfig that decides what tsc reports.

They read the repository's own gate-ts-types.sh and the tsconfig files it runs.

Run: python3 -m unittest discover -s scripts/gates -p 'test_*.py'
"""

from __future__ import annotations

import os
import re
import unittest

from ratchet_harness import GATES
from toolfiles import declared, tool_args

# A tsconfig's `extends`: one path, or a list of them.
EXTENDS = re.compile(r'"extends"\s*:\s*(\[[^\]]*\]|"[^"]*")')


class TypeGateToolFilesTest(unittest.TestCase):
    """gate-ts-types.sh passes, as tool files, every tsconfig that decides what tsc reports."""

    def setUp(self) -> None:
        self.root = GATES.parent.parent
        self.text = (GATES / "gate-ts-types.sh").read_text()
        self.tools = declared(self.text).tool_files

    def projects(self) -> list[str]:
        """The projects the gate runs tsc-projects.sh over: its arguments after TSC."""
        return tool_args(self.text, "scripts/gates/tsc-projects.sh")[1:]

    def extended(self, project: str) -> list[str]:
        """The files `project` extends, from the repository root.

        A package's config (`astro/tsconfigs/strict`) is named by the pin of the
        package in the lockfile beside the project, the tool file that decides it.
        """
        text = "".join(
            line
            for line in (self.root / project).read_text().splitlines(keepends=True)
            if not line.lstrip().startswith("//")
        )
        found = EXTENDS.search(text)
        targets = re.findall(r'"([^"]*)"', found[1]) if found else []
        base = (self.root / project).parent
        out = []
        for t in targets:
            if t.startswith("."):
                out.append(os.path.relpath((base / t).resolve(), self.root.resolve()))
            else:
                lock = os.path.relpath(base / "package-lock.json", self.root)
                out.append(f"{lock}#packages.node_modules/{t.split('/', 1)[0]}")
        return out

    def test_each_project_is_a_tool_file(self) -> None:
        projects = self.projects()
        self.assertEqual(len(projects), 5, projects)
        self.assertEqual(set(projects) - self.tools, set())

    def test_each_file_a_project_extends_is_a_tool_file(self) -> None:
        pending, seen = list(self.projects()), set()
        while pending:
            project = pending.pop()
            for target in self.extended(project):
                with self.subTest(project=project, extends=target):
                    self.assertIn(target, self.tools)
                if target not in seen:
                    seen.add(target)
                    if "#" not in target:
                        pending.append(target)
        self.assertIn("tsconfig.strict.json", seen)


if __name__ == "__main__":
    unittest.main()
