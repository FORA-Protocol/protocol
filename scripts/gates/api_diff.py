#!/usr/bin/env python3
"""Print the incompatible changes to one SDK's public API since the last release.

The last release is the newest vX.Y.Z tag reachable from HEAD (api_rules.py). This
script builds what the SDK's tool needs from that tag, runs the tool over the tag
and the tree, and prints the tool's own output, which api_formats.py reads. It is
the command each API gate (scripts/gates/gate-api-*.sh) runs through ratchet.py.
It names the tag it compares against on stderr, and exits non-zero, printing why,
when the tag cannot be found or a tool fails.

  go: apidiff, over every non-internal package under sdk/go. The tagged tree is
      extracted with `git archive`, apidiff writes its export data there, and
      `apidiff -m -incompatible` compares it with the tree.

Usage:  api_diff.py go
"""

from __future__ import annotations

import sys
import tarfile
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import scope
from api_formats import go_module
from api_rules import ReleaseError, last_release
from scope import REPO_ROOT

if TYPE_CHECKING:
    import subprocess

# What `git archive` leaves out of the tagged tree: the documentation site, which no
# SDK build reads.
ARCHIVE_EXCLUDE = ":(exclude)website"


class ToolError(Exception):
    """A tool the comparison runs failed; the message says which and how."""


def run(argv: list[str], cwd: Path = REPO_ROOT) -> subprocess.CompletedProcess[str]:
    """Run `argv` in `cwd`, and raise ToolError when it fails."""
    proc = scope.run(argv, cwd)
    if proc.returncode != 0:
        raise ToolError(
            f"{' '.join(argv[:3])} exited {proc.returncode}:\n{proc.stdout}{proc.stderr}"
        )
    return proc


def extract(tag: str, into: Path) -> None:
    """Write the tree of `tag`, without the documentation site, into `into`."""
    tar = into.with_suffix(".tar")
    run(["git", "archive", "--format=tar", "-o", str(tar), tag, "--", ".", ARCHIVE_EXCLUDE])
    try:
        with tarfile.open(tar) as archive:
            archive.extractall(into, filter="data")
    except tarfile.TarError as exc:
        raise ToolError(f"cannot extract the tree of {tag}: {exc}") from exc


def quiet(stderr: str) -> str:
    """Return apidiff's stderr without the line it prints for each internal package it skips."""
    return "".join(
        line
        for line in stderr.splitlines(keepends=True)
        if not line.startswith("Ignoring internal package")
    )


def go(tag: str) -> str:
    packages = f"{go_module()}/sdk/go"
    with tempfile.TemporaryDirectory() as tmp:
        old, export = Path(tmp) / "tree", Path(tmp) / "old.zip"
        extract(tag, old)
        written = run(["apidiff", "-m", "-w", str(export), packages], old)
        sys.stderr.write(quiet(written.stderr))
        compared = run(["apidiff", "-m", "-incompatible", str(export), packages])
    sys.stderr.write(quiet(compared.stderr))
    return compared.stdout


SDKS = {"go": go}


def main(argv: list[str]) -> int:
    if len(argv) != 1 or argv[0] not in SDKS:
        sys.stderr.write(f"usage: api_diff.py {'|'.join(SDKS)}\n")
        return 2
    try:
        tag = last_release()
        sys.stderr.write(f"api_diff: comparing the {argv[0]} SDK's public API against {tag}\n")
        sys.stdout.write(SDKS[argv[0]](tag))
    except (ReleaseError, ToolError) as exc:
        sys.stderr.write(f"api_diff: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
