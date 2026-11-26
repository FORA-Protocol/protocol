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
from typing import TYPE_CHECKING, NoReturn

from baseline import State, restrict
from scope import EXCLUDED

if TYPE_CHECKING:
    from collections.abc import Callable

# The module that declares EXCLUDED, read at the ref.
SCOPE = "scripts/gates/scope.py"


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


def left_since(
    read: Callable[[str], str | None], ref: str, fail: Callable[[str], NoReturn]
) -> tuple[str, ...]:
    """Return the trees EXCLUDED held at `ref` and no longer holds: those brought inside.

    `read` returns a file's text at `ref`, or None when it is absent there. `fail`
    is called when EXCLUDED there is not a literal, and when EXCLUDED now holds a
    tree it did not hold there.
    """
    text = read(SCOPE)
    try:
        before = declared(text) if text is not None else ()
    except ValueError as exc:
        fail(f"{SCOPE} at {ref}: {exc}")
    now = tuple(EXCLUDED)
    added = "\n".join(f"  {tree}" for tree in sorted(set(now) - set(before)))
    if added:
        fail(f"EXCLUDED trees added since {ref} (an exclusion only shrinks):\n{added}")
    return tuple(tree for tree in before if tree not in now)


def with_inherited(allowed: State, now: State, trees: tuple[str, ...], ref: str) -> State:
    """Return `allowed` extended by `now`'s findings under one of `trees`, saying so on stderr."""
    out = State(
        Counter(allowed.counts), {f: list(s) for f, s in allowed.sizes.items()}, set(allowed.lower)
    )
    under = restrict(now, lambda f: f.path.startswith(trees))
    added = 0
    for f, n in under.counts.items():
        if n <= out.counts[f]:
            continue
        added += n - out.counts[f]
        out.counts[f] = n
        out.sizes.pop(f, None)
        if f in under.sizes:
            out.sizes[f] = list(under.sizes[f])
        if f in now.lower:
            out.lower.add(f)
    if added:
        sys.stderr.write(
            f"ratchet: {added} findings in {', '.join(trees)}, which the gates did not read "
            f"at {ref}, are inherited\n"
        )
    return out
