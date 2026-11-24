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
  with the same move key, at any path. A format's Policy (POLICIES) names its
  key; the default key is the rule, the message and the text of the line, so the
  finding moved with its line; a finding with no line has no key. The spare
  entries of a key are paired with the findings that need one, worst size to
  worst size, so a moved finding may not be worse than the entry it takes.
- A rename or a copy, which only the --base-ref commands know of (Changes, from
  git): an entry with no key follows its file when git sees the file renamed, and
  a file git sees as a copy takes the entry of its source when the source no
  longer has that finding, unless the format's Policy refuses copies. A file
  renamed and rewritten until git no longer sees the rename keeps nothing, which
  is the safe direction.
- A tool change, which the --base-ref commands also report (Changes.tool_changed),
  only for a change that edits nothing but the gate's tool files and baselines,
  and of a file named in part nothing beyond the tool's part (ratchet.py,
  toolfiles.py): in each file, the findings the tool reports now take the entries
  of that file, whatever their rule, message or line, as long as the file has no
  more findings than before, and each at the size the tool now measures. No code
  changed, and nothing the code depends on, so what changed is how the tool reads
  it; a change that also edits code, or the code's dependencies beside a tool's
  part of a lockfile, re-keys nothing, so a change of tool cannot carry a finding
  that code brought, in the file it edits or in another.

The result is a State over the reference's entries as they read now; `exceeds`
and `record` (baseline.py) compare against it as against any baseline. Nothing
here runs a program or reads a file.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

from baseline import State, describe, partition

if TYPE_CHECKING:
    from collections.abc import Callable, Hashable, Mapping

    from formats import Finding

    MoveKey = Callable[[Finding], Hashable | None]
    # (badness, finding) pairs: a size as State holds it, and the finding it is of.
    Held = list[tuple[float, Finding]]
    # The sizes of the findings of each identity that the other side does not match.
    Unmatched = dict[Finding, list[float]]


def default_move_key(f: Finding) -> tuple[str, str, str] | None:
    """Return what a finding keeps when its code moves to another file, or None.

    A finding that points at a line moves with that line's text, its rule and its
    message. A finding about a whole file has no line to move with, so it moves
    only with its file.
    """
    return (f.rule, f.message, f.source) if f.source else None


@dataclass(frozen=True)
class Policy:
    """How the entries of one format's findings follow their code to another file.

    `move_key` names what a finding keeps when its line moves to another file;
    a finding it gives no key moves only with its file. `copies` says whether a
    file git sees as a copy takes its source's entry.
    """

    move_key: MoveKey = default_move_key
    copies: bool = True


def no_move_key(_: Finding) -> None:
    """Give no finding a move key: its entry moves only with its renamed file."""


# The Policy of each format that does not carry by the default, by its --format name.
POLICIES: dict[str, Policy] = {
    # An inline suppression silences a tool over the code around it. Its entry
    # never moves to another file, by a move or a copy, where it would silence
    # code it was never written for; it follows its file when git sees the file
    # renamed.
    "suppressions": Policy(move_key=no_move_key, copies=False),
}


def policy_of(fmt: str) -> Policy:
    """Return how the entries of the format `fmt` are carried."""
    return POLICIES.get(fmt, Policy())


@dataclass(frozen=True)
class Carried:
    """One entry carried from the identity it had to the one its finding has now."""

    old: Finding
    new: Finding

    def __str__(self) -> str:
        if self.old.path != self.new.path:
            return f"{describe(self.new, 1)} (from {self.old.path})"
        return f"{describe(self.new, 1)} (was [{self.old.rule}] {self.old.message})"


@dataclass(frozen=True)
class Changes:
    """What git reports changed between the reference's commit and the tree now.

    `renames` maps each renamed path to its new one, `copies` lists each copy as
    (source, copy), and `changed` holds every path that was added, removed,
    modified, renamed or copied. `tool_changed` says that the gate's tool changed,
    in a change that edits nothing else (ratchet.py), and `at_base` lists the paths
    of the reference's commit, which only a tool change needs.
    """

    renames: Mapping[str, str] = field(default_factory=dict)
    copies: tuple[tuple[str, str], ...] = ()
    changed: frozenset[str] = frozenset()
    tool_changed: bool = False
    at_base: frozenset[str] = frozenset()

    def rekeys(self, path: str) -> bool:
        """Say whether a tool change re-keys the findings of `path`: it is unchanged."""
        return self.tool_changed and path in self.at_base and path not in self.changed


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


def _rekeyed(ref: State, now: State, allowed: State) -> list[Carried]:
    """Allow `now`'s findings of each file the entries `ref` held there, at their sizes now.

    Both hold only files a tool change re-keys. A file gets no more findings than
    `ref` held there. When it would, the findings `ref` held, and then those on a
    line `ref` had a finding on, are allowed first, so the one refused is the one
    the new tool found anew.
    """
    carried = []
    for path in sorted({f.path for f in now.counts}):
        before = sorted(f for f in ref.counts if f.path == path)
        room = sum(ref.counts[f] for f in before)
        lines = {f.source for f in before}
        here = sorted(
            (f for f in now.counts if f.path == path),
            key=lambda f: (f not in ref.counts, f.source not in lines, f),
        )
        gone = [f for f in before if f not in now.counts]
        for f in here:
            take = min(now.counts[f], room)
            room -= take
            _allow(allowed, f, now.sizes_of(f)[:take], f in now.lower)
            if take and gone and f not in ref.counts:
                was = next((g for g in gone if g.source == f.source), gone[0])
                gone.remove(was)
                carried.append(Carried(was, f))
    return carried


def _renamed(
    ref: State, renames: Mapping[str, str], move_key: MoveKey
) -> tuple[State, dict[Finding, Finding]]:
    """Return `ref` with each entry that has no move key at the new path of its file.

    Also return, for each identity a rename produced, the one it had.
    """
    out = State()
    origins: dict[Finding, Finding] = {}
    for f, n in ref.counts.items():
        g = f
        if move_key(f) is None and f.path in renames:
            g = replace(f, path=renames[f.path])
            origins[g] = f
        _allow(out, g, ref.sizes_of(f)[:n], f in ref.lower)
    return out, origins


def _match(ref: State, now: State, allowed: State) -> tuple[Unmatched, Unmatched]:
    """Allow each identity both hold as before; return what each side has left over.

    The reference's leftover entries are spare, and the findings now that it does
    not hold at their identity need one.
    """
    spare, need = {}, {}
    for f, n in ref.counts.items():
        kept = min(n, now.counts.get(f, 0))
        sizes = ref.sizes_of(f)
        _allow(allowed, f, sizes[:kept], f in ref.lower)
        if n > kept:
            spare[f] = sizes[kept:]
    for f, n in now.counts.items():
        kept = min(n, ref.counts.get(f, 0))
        if n > kept:
            need[f] = now.sizes_of(f)[kept:]
    return spare, need


def _pair(offered: Held, wanted: Held, allowed: State, ref: State) -> list[Carried]:
    """Give each wanted finding an offered entry, worst size to worst size."""
    carried = []
    for (_, f), (size, origin) in zip(_worst_first(wanted), _worst_first(offered), strict=False):
        _allow(allowed, f, [size], origin in ref.lower)
        carried.append(Carried(origin, f))
    return carried


def _use(pool: Unmatched, f: Finding, n: int) -> None:
    """Remove from `pool` the `n` worst sizes of `f`, which a pairing took."""
    rest = pool[f][n:]
    if rest:
        pool[f] = rest
    else:
        del pool[f]


def _copied(
    spare: Unmatched,
    need: Unmatched,
    allowed: State,
    ref: State,
    changes: Changes,
    move_key: MoveKey,
) -> list[Carried]:
    """Give a copy's whole-file finding the entry its source no longer uses."""
    carried: list[Carried] = []
    for source, copy in changes.copies:
        for f in [f for f in spare if f.path == source and move_key(f) is None]:
            g = replace(f, path=copy)
            if g in need:
                done = _pair([(s, f) for s in spare[f]], [(s, g) for s in need[g]], allowed, ref)
                _use(spare, f, len(done))
                _use(need, g, len(done))
                carried += done
    return carried


def _moved(
    spare: Unmatched, need: Unmatched, allowed: State, ref: State, move_key: MoveKey
) -> list[Carried]:
    """Give each finding that needs an entry a spare one with the same move key."""
    offered: dict[Hashable, Held] = defaultdict(list)
    wanted: dict[Hashable, Held] = defaultdict(list)
    for f, sizes in spare.items():
        if (key := move_key(f)) is not None:
            offered[key] += [(s, f) for s in sizes]
    for f, sizes in need.items():
        if (key := move_key(f)) is not None:
            wanted[key] += [(s, f) for s in sizes]
    carried = []
    for key in sorted(wanted, key=repr):
        carried += _pair(offered.get(key, []), wanted[key], allowed, ref)
    return carried


def carry(
    ref: State, now: State, policy: Policy, changes: Changes | None = None
) -> tuple[State, list[Carried]]:
    """Return what `ref` allows, restated in `now`'s identities, and the entries carried.

    `policy` is how the format's entries move. `changes`, which only a --base-ref
    command has, adds a tool change's re-keying, the renames and the copies.
    """
    move_key = policy.move_key
    origins: dict[Finding, Finding] = {}
    allowed = State(lower=set(ref.lower))
    carried: list[Carried] = []
    if changes is not None:
        rekeyed_ref, ref = partition(ref, lambda f: changes.rekeys(f.path))
        rekeyed_now, now = partition(now, lambda f: changes.rekeys(f.path))
        carried += _rekeyed(rekeyed_ref, rekeyed_now, allowed)
        ref, origins = _renamed(ref, changes.renames, move_key)
    spare, need = _match(ref, now, allowed)
    carried += [Carried(origins[f], f) for f in sorted(origins) if f in now.counts]
    if changes is not None and policy.copies:
        carried += _copied(spare, need, allowed, ref, changes, move_key)
    carried += _moved(spare, need, allowed, ref, move_key)
    for f, sizes in spare.items():
        if move_key(f) is None:
            # A whole-file entry that went nowhere stays where it was, allowing what it did.
            _allow(allowed, f, sizes, f in ref.lower)
    return allowed, carried
