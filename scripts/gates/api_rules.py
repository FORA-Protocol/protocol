"""The release the SDK API gates compare against, and the two ways a change is allowed.

Each API gate compares an SDK's public API in the tree against the API of the last
release: the newest `vX.Y.Z` tag reachable from HEAD. A tag is what integrators
installed, so a break is measured from it, and a break that several merges made
together is still one break against it. Without a tag nothing can be compared,
so the gate fails and says how to fetch the tags.

An incompatible change (a removal, a rename, a changed signature) fails, with two
exceptions. The first: the release the change goes into is a major version, and
the symbol is listed under "Breaking" in that SDK's changelog. The release is a major version
when the major of the version in the SDK's release manifest in the tree is above
the major of the last release: the manifests are the ones the release tooling
holds to the tag (scripts/release/check-versions.py), and the Go module, which has
no manifest of its own, reads the repository's package.json. The symbol is listed
when it appears in backticks, exactly as the gate prints it, under a `### Breaking`
heading in the first `## ` section of the changelog, and that section is headed
`Unreleased` or with the new version. A deprecated alias needs no exception: the
old name still exists with its old signature, so the tool reports no change.

The second: a new value of a protocol or manifest version constant
(VERSION_CONSTANTS) with the same major, which a minor release makes. kept() is the
one place each gate's findings are judged by both.

The module needs only the Python standard library.
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
from dataclasses import dataclass
from functools import cache
from typing import TYPE_CHECKING

from scope import REPO_ROOT, run

if TYPE_CHECKING:
    from formats import Reported

RELEASE_TAG = re.compile(r"^v(?P<major>\d+)\.\d+\.\d+$")
FETCH_TAGS = "git fetch --tags REMOTE (the remote of the FORA-Protocol/protocol repository)"


class ReleaseError(Exception):
    """The last release cannot be found, so no comparison can be made."""


@dataclass(frozen=True)
class Sdk:
    """Where an SDK's release version and its changelog are."""

    manifest: str
    changelog: str


SDKS = {
    "go": Sdk("package.json", "sdk/go/CHANGELOG.md"),
    "python": Sdk("sdk/python/pyproject.toml", "sdk/python/CHANGELOG.md"),
    "ts": Sdk("sdk/ts/package.json", "sdk/ts/CHANGELOG.md"),
}


# The protocol and manifest version constants, by SDK, spelled as each gate prints
# them: in Go sdk/go/helpers/constants.go, in TypeScript sdk/ts/src/wire.ts.
# ProtocolVersion is the version of the protocol the SDK speaks, stamped on every
# message's `ver`, and WellKnownManifestVersion is a separate namespace, the version
# of the /.well-known/fora.json layout, whose MAJOR a manifest reader gates on
# (fora.proto, "Protocol version"). A minor release of the protocol moves either one
# within its major, and a party reads the value rather than depending on an old one.
# So a new value of exactly these constants with the same major, and not empty, is
# not an incompatible change. In TypeScript the constant's type is its literal, which
# changes with the value; the same rule covers it. Any other change to one of them
# (a removal, a retype, a new major, an empty value) and any change to another
# constant still fails. Python needs no entry: the pinned griffe compares no
# attribute values, so it reports no value change at all.
VERSION_CONSTANTS = {
    "go": frozenset(
        {"./sdk/go/helpers.ProtocolVersion", "./sdk/go/helpers.WellKnownManifestVersion"}
    ),
    "ts": frozenset({"./wire.ProtocolVersion", "./wire.WellKnownManifestVersion"}),
}

# A changed constant value, in the words apidiff prints it. The TypeScript reader
# writes the same words with value_changed(), so the rule reads one wording.
VALUE_CHANGED = re.compile(r"^(?P<symbol>\S+): value changed from (?P<old>.+) to (?P<new>.+)$")


def value_changed(symbol: str, old: str, new: str) -> str:
    """Return the message of a constant whose value changed from `old` to `new`."""
    return f"{symbol}: value changed from {old} to {new}"


def string_value(literal: str) -> str | None:
    """Return the string a double-quoted literal holds, or None for any other literal."""
    try:
        value = json.loads(literal)
    except ValueError:
        return None
    return value if isinstance(value, str) else None


def version_value_allowed(sdk: str, finding: Reported) -> bool:
    """Return whether `finding` is a new value of a version constant within its major."""
    m = VALUE_CHANGED.match(finding.message)
    if finding.symbol not in VERSION_CONSTANTS.get(sdk, frozenset()) or m is None:
        return False
    old, new = string_value(m["old"]), string_value(m["new"])
    # An empty value has an empty major, so it never shares one with a version.
    if old is None or new is None or old.split(".", 1)[0] != new.split(".", 1)[0]:
        sys.stderr.write(
            f"api: {finding.symbol} is a version constant, but {m['old']} to {m['new']} "
            "is not a new value within its major\n"
        )
        return False
    sys.stderr.write(
        f"api: {finding.symbol} is a version constant, so a new value within its major is allowed\n"
    )
    return True


def kept(sdk: str, finding: Reported) -> bool:
    """Return whether an API gate keeps `finding`: everything but an allowed change.

    A finding that names no symbol, such as a stale TypeScript report, is always kept.
    """
    if finding.symbol is None:
        return True
    return not (version_value_allowed(sdk, finding) or allowed(sdk, finding.symbol))


@cache
def last_release() -> str:
    """Return the newest vX.Y.Z tag reachable from HEAD, or raise ReleaseError."""
    tags = run(
        ["git", "tag", "--merged", "HEAD", "--sort=-v:refname", "--list", "v*"]
    ).stdout.split()
    found = next((t for t in tags if RELEASE_TAG.match(t)), None)
    if found is None:
        raise ReleaseError(
            "no release tag (vX.Y.Z) is reachable from HEAD, so the public API has no "
            f"release to be compared against; fetch the tags: {FETCH_TAGS}"
        )
    return found


def manifest_version(sdk: str) -> str:
    """Return the release version in the SDK's manifest in the tree."""
    path = REPO_ROOT / SDKS[sdk].manifest
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".toml":
        return str(tomllib.loads(text)["project"]["version"])
    return str(json.loads(text)["version"])


def major(version: str) -> int:
    return int(version.removeprefix("v").split(".", 1)[0])


def breaking_section(text: str, version: str) -> str | None:
    """Return the `### Breaking` text of the changelog's first section, or None.

    None also when the first section is headed neither `Unreleased` nor `version`.
    """
    sections = re.split(r"^## ", text, flags=re.MULTILINE)[1:]
    if not sections:
        return None
    heading, _, body = sections[0].partition("\n")
    if heading.strip() not in ("Unreleased", version):
        return None
    parts = re.split(r"^### ", body, flags=re.MULTILINE)
    return next((p for p in parts[1:] if p.partition("\n")[0].strip() == "Breaking"), None)


@dataclass(frozen=True)
class Release:
    """What the gate knows about the release a change goes into."""

    version: str
    last: str
    listed: frozenset[str]

    @property
    def is_major(self) -> bool:
        return major(self.version) > major(self.last)


@cache
def release(sdk: str) -> Release:
    """Return the release a change goes into; raise ReleaseError when it cannot be told."""
    path = REPO_ROOT / SDKS[sdk].changelog
    try:
        version, text = manifest_version(sdk), path.read_text(encoding="utf-8")
    except (OSError, KeyError, ValueError) as exc:
        raise ReleaseError(
            f"cannot read the release version or {SDKS[sdk].changelog}: {exc}"
        ) from exc
    breaking = breaking_section(text, version) or ""
    return Release(version, last_release(), frozenset(re.findall(r"`([^`\n]+)`", breaking)))


def allowed(sdk: str, symbol: str | None) -> bool:
    """Return whether the incompatible change to `symbol` is allowed, and say why on stderr.

    When the release cannot be told, nothing is allowed.
    """
    try:
        rel = release(sdk)
    except ReleaseError as exc:
        sys.stderr.write(f"api: {symbol} is not allowed: {exc}\n")
        return False
    changelog = SDKS[sdk].changelog
    if rel.is_major and symbol in rel.listed:
        sys.stderr.write(
            f"api: {symbol} is listed under Breaking in {changelog} for the major release "
            f"{rel.version}, so its incompatible change is allowed\n"
        )
        return True
    why = (
        f"{symbol} is not listed under Breaking in {changelog}"
        if rel.is_major
        else f"{rel.version} is not a major release after {rel.last}"
    )
    sys.stderr.write(
        f"api: {why}. Keep the old name as a deprecated alias that calls the new one, "
        f"or list {symbol} under Breaking for a major release (ADR-004)\n"
    )
    return False
