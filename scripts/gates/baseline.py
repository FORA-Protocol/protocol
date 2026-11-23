"""A gate's baseline: its findings counted by identity, their sizes, and the comparisons.

ratchet.py runs a gate's tool and reads and writes the baseline file; this module
holds what it compares. A State counts findings by identity (formats.Finding) and
keeps the sizes of each identity's findings. A baseline file is a State written as
JSON, one entry per identity. `compare` reports a tool run against a baseline,
`exceeds` what one State has above another, and `record` the baseline a run
leaves behind. Nothing here runs a program or reads a file, and the module needs
only the Python standard library.
"""

from __future__ import annotations

import json
import math
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from formats import Finding

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

# A baseline entry's keys. A missing size allows any size, so a size is never
# removed by hand without the --base-ref check reporting it as raised.
ENTRY_KEYS = frozenset({"path", "rule", "message", "source", "count", "sizes", "lower_is_worse"})


class BaselineError(ValueError):
    """A baseline file that cannot be read as one."""


@dataclass
class State:
    """Findings counted by identity, and the sizes of each identity's findings.

    A size is held as how bad it is: the value itself, or its negation for a size
    that is worse when lower. Each list is sorted from the worst, with one value
    per finding; `math.inf` stands for a finding whose baseline entry records no
    size, which allows any size.
    """

    counts: Counter[Finding] = field(default_factory=Counter)
    sizes: dict[Finding, list[float]] = field(default_factory=dict)
    lower: set[Finding] = field(default_factory=set)

    def add(self, f: Finding, size: int | None, lower: bool) -> None:
        self.counts[f] += 1
        if size is not None:
            self.sizes.setdefault(f, []).append(-size if lower else size)
            self.sizes[f].sort(reverse=True)
            if lower:
                self.lower.add(f)

    def sizes_of(self, f: Finding) -> list[float]:
        return self.sizes.get(f) or [math.inf] * self.counts[f]


def shown(badness: float, lower: bool) -> str:
    """Return a held size as the value the tool printed, or `none` when none is recorded."""
    if math.isinf(badness):
        return "none"
    return str(int(-badness if lower else badness))


def to_entries(state: State) -> list[dict[str, object]]:
    """Return the baseline entries for `state`, sorted for a stable file."""
    entries: list[dict[str, object]] = []
    for f, n in sorted(state.counts.items()):
        entry: dict[str, object] = {"path": f.path, "rule": f.rule, "message": f.message}
        if f.source:
            entry["source"] = f.source
        entry["count"] = n
        if f in state.sizes:
            entry["sizes"] = [int(shown(b, f in state.lower)) for b in state.sizes[f]]
            if f in state.lower:
                entry["lower_is_worse"] = True
        entries.append(entry)
    return entries


def load_baseline(text: str, where: str) -> State:
    """Parse a baseline file's text; `where` names it in an error."""
    state = State()
    try:
        entries = json.loads(text)["findings"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise BaselineError(f"{where} is not a baseline file: {exc!r}") from exc
    for e in entries:
        unknown = set(e) - ENTRY_KEYS
        if unknown:
            raise BaselineError(
                f"{where}: an entry has keys a baseline does not use: {sorted(unknown)}"
            )
        f = Finding(str(e["path"]), str(e["rule"]), str(e["message"]), str(e.get("source", "")))
        if f in state.counts:
            raise BaselineError(f"{where}: an entry is listed twice: {describe(f, 1).strip()}")
        n = int(e["count"])
        state.counts[f] = n
        sizes = e.get("sizes")
        if sizes is not None:
            if len(sizes) != n:
                raise BaselineError(
                    f"{where}: an entry has {len(sizes)} sizes for count {n}: {f.path}"
                )
            lower = bool(e.get("lower_is_worse"))
            state.sizes[f] = sorted((-int(s) if lower else int(s) for s in sizes), reverse=True)
            if lower:
                state.lower.add(f)
    return state


def dump_baseline(state: State) -> str:
    """Serialize a state as a baseline file."""
    return json.dumps({"findings": to_entries(state)}, indent=2) + "\n"


def describe(f: Finding, n: int) -> str:
    """Return one line naming a finding and its count."""
    at = f" (at: {f.source})" if f.source else ""
    return f"  {f.path}: [{f.rule}] {f.message}{at}" + (f" (x{n})" if n > 1 else "")


def exceeds(a: State, b: State) -> tuple[Counter[Finding], list[str]]:
    """Return the findings `a` has more of than `b`, and the sizes in which `a` is worse.

    Each size line reads `(b's size, a's size)`, in the order `baseline, now`.
    """
    extra = a.counts - b.counts
    worse = []
    for f in sorted(a.counts.keys() & b.counts.keys()):
        if f not in a.sizes and f not in b.sizes:
            continue
        for x, y in zip(a.sizes_of(f), b.sizes_of(f), strict=False):
            if x > y:
                lower = f in a.lower | b.lower
                note = ", lower is worse" if lower else ""
                worse.append(f"{describe(f, 1)} ({shown(y, lower)}, {shown(x, lower)}{note})")
    return extra, worse


def section(heading: str, lines: Iterable[str]) -> list[str]:
    body = list(lines)
    return [heading, *body] if body else []


def compare(current: State, baseline: State) -> list[str]:
    """Return the problems with `current` against `baseline`; empty means pass."""
    new, grew = exceeds(current, baseline)
    gone, shrank = exceeds(baseline, current)
    return [
        *section(
            "findings not in the baseline (fix them; the baseline never grows):",
            (describe(f, n) for f, n in sorted(new.items())),
        ),
        *section(
            "baselined findings that grew, as (baseline, now) (shrink them; a size never grows):",
            grew,
        ),
        *section(
            "baseline entries that no longer occur (run `record` to remove them):",
            (describe(f, n) for f, n in sorted(gone.items())),
        ),
        *section(
            "baselined findings that shrank, as (now, baseline) "
            "(run `record` to lower their size):",
            shrank,
        ),
    ]


def record(current: State, baseline: State | None) -> tuple[State, list[str]]:
    """Return the baseline `record` writes, and what it refused to add or raise.

    A new baseline holds every current finding. An existing one keeps the findings
    that still occur, each size at the smaller of its baseline and current value,
    compared largest to largest.
    """
    if baseline is None:
        return current, []
    written = State(current.counts & baseline.counts, lower=current.lower | baseline.lower)
    for f, n in written.counts.items():
        _hold_smaller(written, f, n, current, baseline)
    # `written` holds only findings that occur, at no more than their size, so the
    # only problems left are the findings and sizes it refused.
    return written, compare(current, written)


def cap(a: State, b: State) -> State:
    """Return `a` with each identity `b` also holds limited to `b`'s count and sizes."""
    out = State(Counter(a.counts), {f: list(s) for f, s in a.sizes.items()}, set(a.lower))
    for f in a.counts.keys() & b.counts.keys():
        n = out.counts[f] = min(a.counts[f], b.counts[f])
        _hold_smaller(out, f, n, a, b)
    return out


def restrict(state: State, keep: Callable[[Finding], bool]) -> State:
    """Return the part of `state` whose findings `keep` accepts."""
    out = State(lower=set(state.lower))
    for f, n in state.counts.items():
        if keep(f):
            out.counts[f] = n
            if f in state.sizes:
                out.sizes[f] = list(state.sizes[f])
    return out


def _hold_smaller(out: State, f: Finding, n: int, a: State, b: State) -> None:
    """Set `out`'s sizes of `f` to the smaller of `a`'s and `b`'s, worst to worst, for `n`."""
    if f in a.sizes or f in b.sizes:
        pairs = zip(a.sizes_of(f)[:n], b.sizes_of(f)[:n], strict=True)
        out.sizes[f] = sorted((min(x, y) for x, y in pairs), reverse=True)
