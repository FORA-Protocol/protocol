"""Scopes / entitlements (ADR-020 §5) — Python port of the sdk/go oracle
(helpers/scopes.go). The subscriptions/entitlements a requester holds are a
SUPPLIED credential: the application hands the SDK what it holds and the SDK
plumbs it into the request. ``normalize_scopes``/``scopes_subset`` are pure,
byte-deterministic string ops pinned to the shared scopes-vectors.json;
``scope_covers``/``scopes_cover`` implement the protocol's segment-wise
scope-matching rule and are pinned to scope-match-vectors.json.
"""

from __future__ import annotations


def normalize_scopes(scopes: list[str]) -> list[str]:
    """Return scopes with empty entries dropped, duplicates removed (first-seen),
    and a stable (lexicographic) order — so two callers supplying the same set
    produce identical bytes on the wire. No casing change, no trimming.

    The sdk/go oracle returns ``nil`` for empty/all-empty input; the Python face
    returns ``[]`` (the parity comparator treats null == []).
    """
    seen: set[str] = set()
    out: list[str] = []
    for s in scopes:
        if s == "" or s in seen:
            continue
        seen.add(s)
        out.append(s)
    out.sort()
    return out


def scope_covers(granted: str, required: str) -> bool:
    """Report whether one granted scope covers one required scope under the
    protocol's scope-matching rule (stated on Requester.scopes): split both on
    ``:``; each granted segment equals the required segment or is ``*``; a
    ``*`` in the last position of the grant covers every remaining required
    segment and there must be at least one; no implicit prefix match; a grant
    with more segments than the requirement never covers it; a ``*`` inside the
    requirement is a literal segment; an empty string covers nothing and is
    covered by nothing. Case-sensitive, no trimming.
    """
    if granted == "" or required == "":
        return False
    g = granted.split(":")
    r = required.split(":")
    for i, seg in enumerate(g):
        if seg == "*" and i == len(g) - 1:
            return i < len(r)
        if i >= len(r) or (seg != "*" and seg != r[i]):
            return False
    return len(g) == len(r)


def scopes_cover(granted: list[str], required: list[str]) -> bool:
    """Report whether every scope in ``required`` is covered (``scope_covers``)
    by at least one scope in ``granted``. An empty ``required`` is always covered.
    """
    return all(any(scope_covers(g, req) for g in granted) for req in required)


def scopes_subset(sub: list[str], superset: list[str]) -> bool:
    """Report whether every scope in ``sub`` is covered by some scope in
    ``superset`` under ``scope_covers`` (grant containment, not exact set
    membership) — the delegation-attenuation rule. A child may narrow a parent
    wildcard but may not widen one. Same check as ``scopes_cover(superset, sub)``.
    """
    return scopes_cover(superset, sub)


def apply_scopes(scopes: list[str]) -> list[str]:
    """Functional analogue of the Go ApplyScopes (which mutates a proto
    Requester). The Python port has no generated Requester mutation face, so it
    returns the normalized scopes array the caller stamps onto its own request.
    """
    return normalize_scopes(scopes)
