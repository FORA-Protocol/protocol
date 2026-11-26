"""The git history ratchet.py's --base-ref check compares with.

The check reads, through these functions, where HEAD's history left the ref
(`merge_base`), what git sees renamed, copied and changed since that commit
(`changes_since`), the paths of the files at it (`paths_at`), and a file as it was
there (`git_show`). Each runs git through scope.run. A git failure that leaves
nothing to compare goes to the `fail` the caller passes, which exits; a file that
does not exist at the commit is None. The module needs only the Python standard
library.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, NoReturn

from carry import Changes
from scope import run

if TYPE_CHECKING:
    import subprocess
    from collections.abc import Callable


def git(*args: str) -> subprocess.CompletedProcess[str]:
    return run(["git", *args])


def git_show(commit: str, rel: str) -> str | None:
    """Return the file `rel` as of `commit`, or None if it does not exist there."""
    proc = git("show", f"{commit}:{rel}")
    return proc.stdout if proc.returncode == 0 else None


def paths_at(commit: str, fail: Callable[[str], NoReturn]) -> frozenset[str]:
    """Return the paths of the files in `commit`."""
    proc = git("ls-tree", "-r", "-z", "--name-only", commit)
    if proc.returncode != 0:
        fail(f"git ls-tree of {commit[:12]} failed: {proc.stderr.strip()}")
    return frozenset(p for p in proc.stdout.split("\0") if p)


def changes_since(commit: str, fail: Callable[[str], NoReturn]) -> Changes:
    """Return what git sees renamed, copied and changed between `commit` and the tree now.

    The tree includes uncommitted edits to tracked files; a new file counts once
    it is staged.
    """
    proc = git("diff", "--name-status", "-z", "-M", "-C", "--no-color", "--no-ext-diff", commit)
    if proc.returncode != 0:
        fail(f"git diff against {commit[:12]} failed: {proc.stderr.strip()}")
    fields = proc.stdout.split("\0")
    renames: dict[str, str] = {}
    copies: list[tuple[str, str]] = []
    changed: set[str] = set()
    i = 0
    while i + 1 < len(fields):
        status, path = fields[i], fields[i + 1]
        if status[:1] not in ("R", "C"):
            changed.add(path)
            i += 2
            continue
        new = fields[i + 2]
        if status[0] == "R":
            renames[path] = new
            changed.add(path)
        else:
            copies.append((path, new))
        changed.add(new)
        i += 3
    return Changes(renames, tuple(copies), frozenset(changed))


def merge_base(ref: str, fail: Callable[[str], NoReturn]) -> str:
    """Return the commit where HEAD's history left `ref`'s: their merge base.

    Comparing there, rather than with the tip of `ref`, holds a change to what it
    added: a branch behind `ref` is not failed for an entry that `ref` dropped
    after the branch left it. The commit is named on stderr.
    """
    commit = git("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}").stdout.strip()
    if not commit:
        fail(f"--base-ref {ref} does not name a commit here (fetch it, or check its spelling)")
    base = git("merge-base", commit, "HEAD").stdout.strip()
    if not base:
        fail(f"--base-ref {ref} has no history in common with HEAD here (fetch the full history)")
    sys.stderr.write(f"ratchet: comparing with {ref} at its merge base with HEAD, {base[:12]}\n")
    return base
