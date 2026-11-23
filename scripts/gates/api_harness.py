"""Shared fixtures for the API gates' tests: a throwaway repository with a release.

An API gate's findings pass through api_rules.py, which reads the last release tag,
the SDK's release manifest and its changelog. An ApiTestCase's repository holds
each of them, as the real repository does, with the version, tag and changelog a
test chooses.
"""

from __future__ import annotations

import json

from ratchet_harness import RepoTestCase

# The release manifests api_rules.py reads, by SDK, and the changelogs.
MANIFESTS = {"go": "package.json"}
CHANGELOGS = {"go": "sdk/go/CHANGELOG.md"}


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

    def release(self, version: str, tag: str | None, text: str = "## Unreleased\n") -> None:
        """Commit every manifest at `version` and every changelog as `text`; tag `tag` before."""
        if tag is not None:
            self.repo.commit("the last release")
            self.repo.git("tag", tag)
        for sdk, manifest in MANIFESTS.items():
            if manifest.endswith(".toml"):
                self.repo.write(manifest, f'[project]\nversion = "{version}"\n')
            else:
                self.repo.write(manifest, json.dumps({"version": version}) + "\n")
            self.repo.write(CHANGELOGS[sdk], text)
        self.repo.commit("the change")

    def check(self, fmt: str, sample: str, *, tool_exit: int = 0) -> None:
        """Run ratchet's check with an empty baseline over the tool output `sample`."""
        self.repo.write_entries([])
        self.proc = self.repo.run_output("check", fmt, sample, tool_exit=tool_exit)

    def assert_reported(self, *symbols: str) -> None:
        """Assert the check failed on exactly the findings of `symbols`."""
        out = self.proc.stdout
        self.assert_fails(self.proc, "findings not in the baseline")
        reported = [line for line in out.splitlines() if line.startswith("  ")]
        self.assertEqual(len(reported), len(symbols), out)
        for symbol in symbols:
            self.assertIn(f"{symbol}:", out)
