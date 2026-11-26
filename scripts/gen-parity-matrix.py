#!/usr/bin/env python3
"""Generate docs/sdk-parity-matrix.md from machine-checked ground truth.

The parity matrix used to be three hand-maintained docs that drifted the moment a
face landed (the classic lockstep-duplication failure). This generator replaces them
with a single artifact derived from two sources that are ALREADY enforced against the
real code, so the rendered matrix cannot claim something the code contradicts:

  1. API surface  <- sdk/parity/symbol-map.json
     Enforced bidirectionally by sdk/python/tests/test_api_surface_parity.py:
     every Go public symbol is mapped-or-excluded, every mapped python/ts name exists
     on the live surface, the allowlist is shrink-only, every gap is documented. So the
     map is a verified-in-sync mirror of the exported surface across all three SDKs.

  2. Vector replay <- the conformance corpora the registry sdk/parity/corpora.json
     lists, each scanned for a Go+python+ts reference by scripts/gates/corpus_replay.py,
     the module the corpus-contract gate (scripts/gates/gate-corpus-contract.sh) reads.
     That gate holds the un-replayed count at zero with no exemption, so every row is ✅.

Narrative/rationale (L1/L2 layering, the SSRF transport-wiring invariant, naming
conventions) is editorial and lives in docs/design-history.md — this file links to it
rather than duplicating it.

Regenerate:  python3 scripts/gen-parity-matrix.py         (writes docs/sdk-parity-matrix.md)
Check drift: python3 scripts/gen-parity-matrix.py --check (nonzero exit if stale)
Drift-gated in scripts/ci-local.sh, mirroring the gen/ and sdk-types drift gates.
"""

from __future__ import annotations

import importlib
import json
import pathlib
import sys
from typing import Any

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

# The corpus registry's reader and the replay scan are the corpus-contract gate's own
# modules, so this table lists exactly the corpora and the references that gate checks.
sys.path.insert(0, str(_REPO_ROOT / "scripts" / "gates"))
_corpora = importlib.import_module("corpora")
_corpus_replay = importlib.import_module("corpus_replay")
_SYMBOL_MAP = _REPO_ROOT / "sdk" / "parity" / "symbol-map.json"
_ROW_DIVERGENCES = _REPO_ROOT / "sdk" / "parity" / "corpus-row-divergences.json"
_OUT = _REPO_ROOT / "docs" / "sdk-parity-matrix.md"

# Human-readable package headings, in the order Go layers them (L1 -> L2 -> server).
_PKG_ORDER = [
    "helpers",
    "resolvers",
    "core",
    "connect",
    "connectserver",
    "profiles/music",
    "helperstest",
]
_PKG_TITLE = {
    "helpers": (
        "helpers — L1 pure primitives (crypto, canonicalization, money, scopes, license terms)"
    ),
    "resolvers": "resolvers — L2 I/O (key/endpoint resolution, active-key, SSRF-guarded fetch)",
    "core": "core — L2 composition (verifier, signing transport, windows, replay)",
    "connect": "connect — Connect client + interceptors",
    "connectserver": "connectserver — server-verify handler binding",
    "profiles/music": "profiles/music — the fora-music-v1 extension profile type",
    "helperstest": "helperstest — test support: acceptance signers that admit an empty requester",
}


def _load_map() -> dict[str, Any]:
    return json.loads(_SYMBOL_MAP.read_text(encoding="utf8"))


def _pkg_of(symbol: str) -> str:
    return symbol.split(".", 1)[0]


def _cell(name: str | None) -> str:
    return f"`{name}`" if name else "—"


def _render(parity_map: dict[str, Any]) -> str:
    symbols: dict[str, dict[str, Any]] = parity_map["symbols"]
    exclusions: dict[str, str] = parity_map["go_exclusions"]

    mapped = {k: v for k, v in symbols.items() if not v.get("allowlist_reason")}
    diverged = {k: v for k, v in symbols.items() if v.get("allowlist_reason")}

    corpora: list[str] = _corpora.load().files()

    out: list[str] = []
    w = out.append

    w("# SDK API-Surface Parity Matrix (go · python · ts)")
    w("")
    w("<!-- GENERATED FILE — DO NOT EDIT BY HAND.")
    w("     Source of truth:")
    w("       • API surface   — sdk/parity/symbol-map.json")
    w("                          (enforced against live exports by")
    w("                           sdk/python/tests/test_api_surface_parity.py)")
    w("       • Vector replay  — the corpora sdk/parity/corpora.json lists (enforced by")
    w("                          gate-corpus-contract.sh), and rows a port meets another way")
    w("     Regenerate:  python3 scripts/gen-parity-matrix.py")
    w("     Drift-gated in scripts/ci-local.sh. Narrative/rationale: docs/design-history.md. -->")
    w("")
    w(
        "Go is the oracle "
        "(`sdk/go/{helpers,resolvers,core,connect,connectserver,profiles/music,helperstest}`); "
        "Python and TS mirror it. This document is **generated** from the same two "
        "artifacts CI already enforces against the code, so it cannot drift from the "
        "real surface — a mismatch fails the API-surface gate or the corpus-contract "
        "gate before it can reach this file."
    )
    w("")
    w(
        f"**At a glance:** {len(mapped)} symbols at cross-language parity · "
        f"{len(diverged)} documented divergences · {len(exclusions)} Go-idiomatic "
        f"exclusions · {len(corpora)} conformance corpora, each tri-replayed."
    )
    w("")
    w(
        "Layering (L1 pure trust core vs L2 I/O resolvers), the SSRF transport-wiring "
        "invariant, and naming conventions are recorded in "
        "[`design-history.md`](./design-history.md)."
    )
    w("")

    # --- Section 1: per-symbol parity, grouped by package ---
    w("## API surface — parity per Go public symbol")
    w("")
    w(
        "Legend: a name = the public face in that language · `—` = intentionally none "
        "(see Documented divergences). Every row here is at parity by construction: the "
        "gate rejects a mapped name that is absent from the live surface."
    )
    w("")
    seen_pkgs = [p for p in _PKG_ORDER if any(_pkg_of(k) == p for k in mapped)]
    extra_pkgs = sorted({_pkg_of(k) for k in mapped} - set(_PKG_ORDER))
    for pkg in seen_pkgs + extra_pkgs:
        rows = sorted((k, v) for k, v in mapped.items() if _pkg_of(k) == pkg)
        if not rows:
            continue
        w(f"### {_PKG_TITLE.get(pkg, pkg)}")
        w("")
        w("| Go | python | ts |")
        w("|---|---|---|")
        for key, entry in rows:
            go_name = key.split(".", 1)[1]
            w(f"| `{go_name}` | {_cell(entry.get('python'))} | {_cell(entry.get('ts'))} |")
        w("")

    # --- Section 2: documented divergences & DECISIONs ---
    w("## Documented divergences & DECISIONs")
    w("")
    w(
        "Deliberate, reason-backed asymmetries. The allowlist is **shrink-only** — a new "
        "undocumented gap cannot ship green. Each entry's rationale is the "
        "`allowlist_reason` from the symbol map; DECISION anchors are cross-checked by "
        "`test_api_surface_parity.py`."
    )
    w("")
    # Architectural DECISIONs — one bullet per distinct decision_anchor, rendered
    # verbatim. test_api_surface_parity.py asserts each anchor string appears here, so a
    # full divergence cannot masquerade as a silent gap.
    anchors: dict[str, list[str]] = {}
    anchor_reason: dict[str, str] = {}
    for key, entry in sorted(diverged.items()):
        anchor = entry.get("decision_anchor")
        if not anchor:
            continue
        anchors.setdefault(anchor, []).append(key)
        anchor_reason.setdefault(anchor, entry.get("allowlist_reason", ""))
    if anchors:
        w("### Architectural DECISIONs")
        w("")
        for anchor in sorted(anchors):
            syms = ", ".join(f"`{s}`" for s in anchors[anchor])
            w(f"- **DECISION — {anchor}.** {anchor_reason[anchor]} _(symbols: {syms})_")
        w("")

    if diverged:
        w("### Mapped symbols with an intentional per-language gap")
        w("")
        w("| Go symbol | python | ts | rationale |")
        w("|---|---|---|---|")
        for key, entry in sorted(diverged.items()):
            reason = entry.get("allowlist_reason", "").replace("|", "\\|")
            w(f"| `{key}` | {_cell(entry.get('python'))} | {_cell(entry.get('ts'))} | {reason} |")
        w("")
    w("### Go-idiomatic symbols with no cross-language face (by design)")
    w("")
    w(
        "Go constructs (functional-option builders, `errors.Is` sentinels, value types, "
        "context accessors) that Python/TS express idiomatically inline rather than as a "
        "named public symbol."
    )
    w("")
    w("| Go symbol | why no py/ts face |")
    w("|---|---|")
    for key, reason in sorted(exclusions.items()):
        w(f"| `{key}` | {reason.replace('|', chr(92) + '|')} |")
    w("")

    out.extend(_render_corpora(corpora))

    return "\n".join(out) + "\n"


def _render_corpora(corpora: list[str]) -> list[str]:
    """Return the conformance-vector replay section: each corpus file, and who names it."""
    sources = _corpus_replay.replay_sources()
    out = [
        "## Cross-language conformance-vector replay",
        "",
        "Go emits each corpus the registry `sdk/parity/corpora.json` lists; Python and TS "
        "replay it. The corpus-contract gate holds the un-replayed count at **zero with no "
        "exemption mechanism**, so every corpus below is referenced by all three trees.",
        "",
        "| Corpus | go | python | ts |",
        "|---|---|---|---|",
    ]
    for path in corpora:
        naming = _corpus_replay.languages_naming(path, sources)
        marks = {lang: "✅" if lang in naming else "❌" for lang in sources}
        out.append(f"| `{path}` | {marks['go']} | {marks['python']} | {marks['ts']} |")
    out.append("")
    out.extend(_render_row_divergences())
    return out


def _render_row_divergences() -> list[str]:
    """Return the corpus rows a port meets by another route, as
    sdk/parity/corpus-row-divergences.json records them."""
    out = [
        "### Corpus rows a port meets by another route",
        "",
        "The rows a port refuses or accepts as Go does, but for another reason, as "
        "`sdk/parity/corpus-row-divergences.json` records them. The replay each entry names "
        "asserts the outcome below, and fails when the rows it meets another way differ "
        "from the rows listed.",
        "",
        "| Row | port | outcome | replay | reason |",
        "|---|---|---|---|---|",
    ]
    for entry in json.loads(_ROW_DIVERGENCES.read_text(encoding="utf8"))["divergences"]:
        out.extend(
            f"| `{row}` | {entry['port']} | {entry['outcome']} | `{entry['replay']}` "
            f"| {entry['reason']} |"
            for row in entry["rows"]
        )
    out.append("")
    return out


def main() -> int:
    rendered = _render(_load_map())
    check = "--check" in sys.argv[1:]
    if check:
        current = _OUT.read_text(encoding="utf8") if _OUT.exists() else ""
        if current != rendered:
            sys.stderr.write(
                "docs/sdk-parity-matrix.md is stale — run "
                "'python3 scripts/gen-parity-matrix.py' and commit.\n"
            )
            return 1
        return 0
    _OUT.write_text(rendered, encoding="utf8")
    sys.stderr.write(f"wrote {_OUT.relative_to(_REPO_ROOT)}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
