"""Carrying a baseline entry to the identity its finding has after its code moved.

A finding's identity names its file (formats.Finding), so a finding whose code
moved to another file reads as a new finding, and its old entry as one that no
longer occurs. `carry` restates what a reference baseline allows in the
identities another state has now, by these rules, none of which lets the count of
findings grow:

- An identity that occurs in both keeps the reference's allowance for it, as
  before: as many findings as both hold, each paired with the reference's sizes
  worst to worst.
- A move: a finding the reference does not hold at its identity takes the place
  of one the reference holds to spare (one that no longer occurs where it was)
  with the same move key (Format.move_key), at any path. The default key is the
  rule, the message and the text of the line, so the finding moved with its line;
  a finding with no line has no key and moves only with its file. The spare
  entries of a key are paired with the findings that need one, worst size to
  worst size, so a moved finding may not be worse than the entry it takes.

The result is a State over the reference's entries as they read now; `exceeds`
and `record` (baseline.py) compare against it as against any baseline. Nothing
here runs a program or reads a file.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING

from baseline import State, describe

if TYPE_CHECKING:
    from collections.abc import Callable, Hashable

    from formats import Finding

    MoveKey = Callable[[Finding], Hashable | None]
    # (badness, finding) pairs: a size as State holds it, and the finding it is of.
    Held = list[tuple[float, Finding]]


@dataclass(frozen=True)
class Carried:
    """One entry carried from the identity it had to the one its finding has now."""

    old: Finding
    new: Finding

    def __str__(self) -> str:
        return f"{describe(self.new, 1)} (from {self.old.path})"


def _worst_first(items: Held) -> Held:
    return sorted(items, key=lambda item: (-item[0], item[1]))


def _allow(state: State, f: Finding, sizes: list[float], lower: bool) -> None:
    """Add to `state` an allowance of `f` for len(`sizes`) findings at those sizes.

    `math.inf` is a finding that allows any size. An identity holds a size for
    each of its findings or for none, so once one of them allows any size, all do.
    """
    if not sizes:
        return
    known = state.sizes.get(f, [] if state.counts[f] == 0 else None)
    state.counts[f] += len(sizes)
    if lower:
        state.lower.add(f)
    if known is None or any(math.isinf(s) for s in sizes):
        state.sizes.pop(f, None)
    else:
        state.sizes[f] = sorted([*known, *sizes], reverse=True)


def carry(ref: State, now: State, move_key: MoveKey) -> tuple[State, list[Carried]]:
    """Return what `ref` allows, restated in `now`'s identities, and the entries carried."""
    allowed = State(lower=set(ref.lower))
    spare: dict[Hashable, Held] = defaultdict(list)
    for f, n in ref.counts.items():
        kept = min(n, now.counts.get(f, 0))
        sizes = ref.sizes_of(f)
        _allow(allowed, f, sizes[:kept], f in ref.lower)
        key = move_key(f)
        if key is None:
            # It cannot move, so it stays where it was, allowing what it did.
            _allow(allowed, f, sizes[kept:], f in ref.lower)
        else:
            spare[key] += [(s, f) for s in sizes[kept:]]
    need: dict[Hashable, Held] = defaultdict(list)
    for f, n in now.counts.items():
        key = move_key(f)
        kept = min(n, ref.counts.get(f, 0))
        if key is not None and n > kept:
            need[key] += [(s, f) for s in now.sizes_of(f)[kept:]]
    carried = []
    for key, wanted in sorted(need.items(), key=lambda item: repr(item[0])):
        offered = _worst_first(spare.get(key, []))
        for (_, f), (size, origin) in zip(_worst_first(wanted), offered, strict=False):
            _allow(allowed, f, [size], origin in ref.lower)
            carried.append(Carried(origin, f))
    return allowed, carried
