#!/usr/bin/env python3
"""Fail unless each npm package directory holds exactly what its lockfile pins.

The TypeScript gates run the biome and tsc that sdk/ts/package-lock.json pins, and
tsc reads the types of every package the checked code imports. A tool of another
version, or a dependency left over from `npm install --no-save`, would change what
the gates report, so they refuse to run on one.

A directory passes when every package npm recorded in node_modules/.package-lock.json
has the version the lockfile pins, the package.json installed for it says the same
version, and every package the lockfile pins is installed, except the optional ones
(platform binaries built for another system). The installed package.json is read
too because npm's own record is not the package: a package replaced or edited on
disk after `npm ci` changes what the gates run without changing the record.

Usage:  npm_installed.py DIR [DIR...]
Exit:   0 = every DIR matches its lockfile; 1 = at least one does not, and what
        differs is printed. The caller prints the install command, which installs
        every directory at once.

The script needs only the Python standard library.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def problems(pkg_dir: Path) -> list[str]:
    """Return how `pkg_dir`'s node_modules differs from its lockfile; empty means none."""
    lock = pkg_dir / "package-lock.json"
    installed = pkg_dir / "node_modules" / ".package-lock.json"
    if not installed.exists():
        return ["node_modules is not installed"]
    want = {k: v for k, v in json.loads(lock.read_text())["packages"].items() if k}
    have = json.loads(installed.read_text())["packages"]
    out = []
    for name, entry in sorted(have.items()):
        pinned = want.get(name)
        if pinned is None:
            out.append(f"{name} {entry.get('version')} is installed but not in the lockfile")
        elif pinned.get("version") != entry.get("version"):
            out.append(
                f"{name} is {entry.get('version')}, the lockfile pins {pinned.get('version')}"
            )
        else:
            out += manifest_problems(pkg_dir, name, pinned)
    out += [
        f"{name} {entry.get('version')} is not installed"
        for name, entry in sorted(want.items())
        if name not in have and not entry.get("optional")
    ]
    return out


def manifest_problems(pkg_dir: Path, name: str, pinned: dict[str, object]) -> list[str]:
    """Return how the package.json installed for `name` differs from its pin."""
    if pinned.get("link") or "version" not in pinned:
        return []
    manifest = pkg_dir / name / "package.json"
    if not manifest.exists():
        return [f"{name} has no package.json"]
    version = json.loads(manifest.read_text()).get("version")
    if version != pinned["version"]:
        return [f"{name}/package.json says {version}, the lockfile pins {pinned['version']}"]
    return []


def main(argv: list[str]) -> int:
    """Check every directory in `argv`; return the process exit code."""
    failed = False
    for arg in argv:
        found = problems(Path(arg))
        if found:
            failed = True
            print(f"{arg}: the installed packages do not match {arg}/package-lock.json:")
            print("\n".join(f"  {p}" for p in found))
    return 1 if failed else 0


if __name__ == "__main__":
    if not sys.argv[1:]:
        raise SystemExit("usage: npm_installed.py DIR [DIR...]")
    sys.exit(main(sys.argv[1:]))
