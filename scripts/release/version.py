#!/usr/bin/env python3
"""Release version spellings, from the release tag.

A release tag is vX.Y.Z (a final release), vX.Y.Z-beta.N or vX.Y.Z-rc.N (a
prerelease). Any other tag is refused, so a tag no check knows how to spell
never reaches a registry. The leading v is optional, so the version can be
passed with or without it.

The Go module version is the tag itself and the npm version is the tag without
the v. Python spells the same version in PEP 440 normalized form (beta.N is bN,
rc.N is rcN), which is what the wheel and sdist file names and PyPI carry. A
prerelease is published to npm under the dist-tag `next`, so `latest` keeps
pointing at the newest final release; a final release is published as `latest`.

    scripts/release/version.py v1.3.0-beta.1 npm         # 1.3.0-beta.1
    scripts/release/version.py v1.3.0-beta.1 python      # 1.3.0b1
    scripts/release/version.py v1.3.0-beta.1 dist-tag    # next
    scripts/release/version.py v1.3.0-beta.1 prerelease  # true
"""

import re
import sys
from collections.abc import Callable
from typing import NamedTuple

_TAG = re.compile(
    r"v?(?P<core>(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))"
    r"(?:-(?P<kind>beta|rc)\.(?P<n>0|[1-9][0-9]*))?"
)
_PEP440 = {"beta": "b", "rc": "rc"}


class Spellings(NamedTuple):
    npm: str
    python: str
    prerelease: bool

    @property
    def dist_tag(self) -> str:
        return "next" if self.prerelease else "latest"


def parse(tag: str) -> Spellings:
    m = _TAG.fullmatch(tag)
    if not m:
        raise ValueError(
            f"unsupported release version {tag!r}: expected vX.Y.Z, vX.Y.Z-beta.N or vX.Y.Z-rc.N"
        )
    core, kind, n = m["core"], m["kind"], m["n"]
    if kind is None:
        return Spellings(npm=core, python=core, prerelease=False)
    return Spellings(npm=f"{core}-{kind}.{n}", python=f"{core}{_PEP440[kind]}{n}", prerelease=True)


_FIELDS: dict[str, Callable[[Spellings], str]] = {
    "npm": lambda s: s.npm,
    "python": lambda s: s.python,
    "dist-tag": lambda s: s.dist_tag,
    "prerelease": lambda s: "true" if s.prerelease else "false",
}


def main(argv: list[str]) -> int:
    match argv[1:]:
        case [tag, field] if field in _FIELDS:
            pass
        case _:
            print(f"usage: {argv[0]} <tag> {{{','.join(_FIELDS)}}}", file=sys.stderr)
            return 2
    try:
        spellings = parse(tag)
    except ValueError as e:
        print(f"::error::{e}", file=sys.stderr)
        return 1
    print(_FIELDS[field](spellings))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
