"""Shared fixtures for the API gates' tests: a throwaway repository with a release.

An API gate's findings pass through api_rules.py, which reads the last release tag,
the SDK's release manifest and its changelog. An ApiTestCase's repository holds
each of them, as the real repository does, with the version, tag and changelog a
test chooses.
"""

from __future__ import annotations

import json
import re

from api_rules import SDKS
from ratchet_harness import RepoTestCase


def changelog(*sections: tuple[str, str, list[str]]) -> str:
    """Return a changelog with one `## heading` per section, each with a `### sub` list."""
    text = "# Changelog\n\n"
    for heading, sub, symbols in sections:
        items = "".join(f"- `{s}`: changed.\n" for s in symbols)
        text += f"## {heading}\n\n### {sub}\n\n{items}\n"
    return text


class ApiTestCase(RepoTestCase):
    """A RepoTestCase whose repository has a go.mod, release manifests, changelogs and a tag."""

    def setUp(self) -> None:
        super().setUp()
        self.repo.write("go.mod", "module github.com/FORA-Protocol/protocol\n\ngo 1.26\n")

    def release(
        self, version: str, tag: str | None, text: str = "## Unreleased\n", sdk: str = ""
    ) -> None:
        """Commit each SDK's manifest at `version` and its changelog; tag `tag` first.

        The changelog of `sdk`, or of every SDK when `sdk` is empty, is `text`; any
        other changelog has an empty Unreleased section.
        """
        if tag is not None:
            self.repo.commit("the last release")
            self.repo.git("tag", tag)
        for name, s in SDKS.items():
            if s.manifest.endswith(".toml"):
                self.repo.write(s.manifest, f'[project]\nversion = "{version}"\n')
            else:
                self.repo.write(s.manifest, json.dumps({"version": version}) + "\n")
            self.repo.write(s.changelog, text if sdk in ("", name) else "## Unreleased\n")
        self.repo.commit("the change")

    def check(self, fmt: str, sample: str, *, tool_exit: int = 0) -> None:
        """Run ratchet's check with an empty baseline over the tool output `sample`."""
        self.repo.write_entries([])
        self.proc = self.repo.run_output("check", fmt, sample, tool_exit=tool_exit)

    def assert_reported(self, *symbols: str) -> None:
        """Assert the check failed on exactly the findings of `symbols`, one each.

        A finding's message starts with its symbol, followed by `:`, or by `(` and the
        parameter it is about.
        """
        out = self.proc.stdout
        self.assert_fails(self.proc, "findings not in the baseline")
        reported = [line for line in out.splitlines() if line.startswith("  ")]
        self.assertEqual(len(reported), len(symbols), out)
        for symbol in symbols:
            self.assertRegex(out, rf"\] {re.escape(symbol)}[:(]")
