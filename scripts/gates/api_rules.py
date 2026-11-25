"""The release the SDK API gates compare against, and the one way a break is allowed.

Each API gate compares an SDK's public API in the tree against the API of the last
release: the newest `vX.Y.Z` tag reachable from HEAD. A tag is what integrators
installed, so a break is measured from it, and a break that several merges made
together is still one break against it. Without a tag nothing can be compared,
so the gate fails and says how to fetch the tags.

An incompatible change (a removal, a rename, a changed signature) fails, with one
exception: the release the change goes into is a major version, and the symbol is
listed under "Breaking" in that SDK's changelog. The release is a major version
when the major of the version in the SDK's release manifest in the tree is above
the major of the last release: the manifests are the ones the release tooling
holds to the tag (scripts/release/check-versions.py), and the Go module, which has
no manifest of its own, reads the repository's package.json. The symbol is listed
when it appears in backticks, exactly as the gate prints it, under a `### Breaking`
heading in the first `## ` section of the changelog, and that section is headed
`Unreleased` or with the new version. A deprecated alias needs no exception: the
old name still exists with its old signature, so the tool reports no change.

The protocol and manifest version constants are not breaks when their value
changes (VERSION_CONSTANTS).

The module needs only the Python standard library.
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
from dataclasses import dataclass
from functools import cache

from scope import REPO_ROOT, run

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
# them. Their value is the version of the protocol the SDK implements, which the
# proto states once (fora.proto's version options) and a minor protocol release
# moves, as profile 1.1 moves both from "1.0" to "1.1"; a party reads the value
# instead of depending on an old one. So a changed value of exactly these constants
# is not an incompatible change. Any other change to one of them, such as its
# removal, and any change to another constant, still is.
VERSION_CONSTANTS = {
    "go": frozenset(
        {"./sdk/go/helpers.ProtocolVersion", "./sdk/go/helpers.WellKnownManifestVersion"}
    ),
    "ts": frozenset({"./wire.ProtocolVersion", "./wire.WellKnownManifestVersion"}),
}


def version_value_changed(sdk: str, symbol: str | None, message: str) -> bool:
    """Return whether a finding is only a changed value of a version constant, and say so.

    Each gate words a changed value as `SYMBOL: value changed from OLD to NEW`.
    """
    if symbol not in VERSION_CONSTANTS.get(sdk, frozenset()):
        return False
    if not message.startswith(f"{symbol}: value changed from "):
        return False
    sys.stderr.write(f"api: {symbol} is a protocol version constant, so a new value is allowed\n")
    return True


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
