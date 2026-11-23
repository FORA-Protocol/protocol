"""The trees scope.py excludes from the gates, compared between two commits.

ratchet.py's --base-ref check reads scope.py's EXCLUDED as it was at the merge
base, and compares it with the one in the tree now:

- A tree EXCLUDED holds now and did not hold at the merge base fails the check:
  the list only shrinks, so a tree cannot be excluded and then brought back with
  new findings.
- A tree that EXCLUDED held at the merge base and no longer holds was read by no
  gate there, so its findings arrive as inherited debt when it comes inside the
  gates. The check accepts a baseline entry added under such a tree, and only
  there; `record --base-ref` keeps such an entry.

EXCLUDED is read from scope.py's source as a literal, in either form, plain
(`EXCLUDED = {...}`) or annotated (`EXCLUDED: dict[str, str] = {...}`); a
scope.py with no EXCLUDED excludes nothing. The module runs no program and needs
only the Python standard library.
"""

from __future__ import annotations

import ast
import sys
from collections import Counter
from typing import TYPE_CHECKING

from baseline import State, restrict, section
from scope import EXCLUDED

if TYPE_CHECKING:
    from formats import Finding


def declared(text: str) -> tuple[str, ...]:
    """Return the trees the scope.py source `text` declares in EXCLUDED.

    A ValueError says EXCLUDED is not a literal.
    """
    for node in ast.parse(text).body:
        targets: list[ast.expr]
        if isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        elif isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        else:
            continue
        if any(isinstance(t, ast.Name) and t.id == "EXCLUDED" for t in targets):
            try:
                return tuple(ast.literal_eval(value)) if value is not None else ()
            except (ValueError, TypeError) as exc:
                raise ValueError("EXCLUDED is not a literal dict") from exc
    return ()


def since(text: str | None, ref: str) -> tuple[list[str], tuple[str, ...]]:
    """Compare EXCLUDED now with the one in `text`, scope.py's source at `ref` (None: absent).

    Return the problems (a tree EXCLUDED holds now and did not there) and the trees
    it held there and no longer holds. A ValueError says EXCLUDED there is not a
    literal.
    """
    before, now = declared(text) if text is not None else (), tuple(EXCLUDED)
    problems = section(
        f"EXCLUDED trees added since {ref} (an exclusion only shrinks):",
        (f"  {tree}" for tree in sorted(set(now) - set(before))),
    )
    return problems, tuple(tree for tree in before if tree not in now)


def inherited(found: Counter[Finding], trees: tuple[str, ...], ref: str) -> Counter[Finding]:
    """Return the part of `found` whose path lies under one of `trees`, and say so on stderr."""
    out = Counter({f: n for f, n in found.items() if f.path.startswith(trees)})
    if out:
        sys.stderr.write(
            f"ratchet: {sum(out.values())} findings in {', '.join(trees)}, which the gates "
            f"did not read at {ref}, are inherited\n"
        )
    return out


def with_inherited(allowed: State, current: State, trees: tuple[str, ...]) -> State:
    """Return `allowed` extended by `current`'s findings under one of `trees`."""
    out = State(
        Counter(allowed.counts), {f: list(s) for f, s in allowed.sizes.items()}, set(allowed.lower)
    )
    under = restrict(current, lambda f: f.path.startswith(trees))
    for f, n in under.counts.items():
        if n <= out.counts[f]:
            continue
        out.counts[f] = n
        out.sizes.pop(f, None)
        if f in under.sizes:
            out.sizes[f] = list(under.sizes[f])
        if f in current.lower:
            out.lower.add(f)
    return out
