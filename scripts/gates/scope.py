#!/usr/bin/env python3
"""The hand-written code the gates cover, written once.

A file is hand-written when git tracks it, its suffix names one of the LANGUAGES,
it is outside the one declared exclusion (EXCLUDED: website/, the documentation
site), and GENERATED does not list it. GENERATED is the one declaration of
generated code: each entry names the paths a generator writes and the generator.
Every listed file says so in the comments it opens with, by the Go convention
the generators follow in each language (`Code generated ... DO NOT EDIT.`), and
every tracked file that says so is listed; `check_generated` holds both, so the
list can neither hide a hand-written file nor miss a generated one. The
hand-written files beside the generated ones under gen/, such as
gen/jsonschema/jsonschema.go and gen/python/wire/base.py, are in scope, as is
schemas/schemas.go.

GATES names the gates that read each language. gate-scope.sh asks each gate's
tool which files it reads, and fails on a hand-written file a gate of its
language does not read, and on a generated file any gate reads. The scanners in
this directory read their files through `sources()`.

Usage:  scope.py files [--language L]...   print the hand-written paths, one per line
        scope.py check                     print what is wrong with GENERATED; exit 1 if any
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

REPO_ROOT = Path(__file__).resolve().parents[2]

# The language of each gated file suffix. A suffix that is not here is not gated.
LANGUAGES = {
    ".go": "go",
    ".py": "python",
    ".pyi": "python",
    ".ts": "typescript",
    ".mts": "typescript",
    ".js": "javascript",
    ".mjs": "javascript",
    ".sh": "shell",
}

# The gates that read each language, by the name in scripts/gates/gate-<name>.sh.
# Shell has no format, lint, type or file-length gate. The duplication gate reads it,
# and so does the inline-suppression gate, for jscpd's markers: it reads every
# language the duplication gate reads.
_SOURCE_GATES = ("file-length", "inline-suppressions", "duplication")
_TS_GATES = ("ts-format", "ts-lint", "ts-types", *_SOURCE_GATES)
GATES = {
    "go": ("go-format", "go-lint", *_SOURCE_GATES),
    "python": ("python-format", "python-lint", "python-types", *_SOURCE_GATES),
    "typescript": _TS_GATES,
    "javascript": _TS_GATES,
    "shell": ("inline-suppressions", "duplication"),
}

# Generated code: glob patterns over repository paths (`**` crosses directories),
# each with the generator that writes the files.
GENERATED = {
    "gen/go/**/*_version.pb.go": "buf generate (proto/buf.gen.yaml: cmd/protoc-gen-foraversion)",
    "gen/python/wire/version.py": "buf generate (proto/buf.gen.yaml: cmd/protoc-gen-foraversion)",
    "gen/ts/wire/version.ts": "buf generate (proto/buf.gen.yaml: cmd/protoc-gen-foraversion)",
    "gen/go/comp/**": "buf generate (proto/buf.gen.yaml: protoc-gen-go)",
    "gen/go/fora/**": "buf generate (proto/buf.gen.yaml: protoc-gen-go and connect-go)",
    "gen/go/vocab/**": "buf generate (proto/buf.gen.yaml: cmd/protoc-gen-foravocab)",
    "gen/python/vocab/**": "buf generate (proto/buf.gen.yaml: cmd/protoc-gen-foravocab)",
    "gen/ts/vocab/**": "buf generate (proto/buf.gen.yaml: cmd/protoc-gen-foravocab)",
    "gen/python/wire/models.py": "scripts/gen-sdk-types.sh (datamodel-code-generator)",
    "gen/python/wire/unique.py": "scripts/gen-sdk-types.sh (conformance/uniquegen)",
    "gen/ts/wire/schemas.ts": "scripts/gen-sdk-types.sh (scripts/sdk-types/gen_zod.mjs)",
    "gen/ts/strict/**": "scripts/gen-sdk-types.sh (scripts/sdk-types/gen_strict_validators.mjs)",
}

# The one hand-written tree outside the gates, with its reason. No other
# hand-written path is excluded; a tree is brought inside the gates, never added.
EXCLUDED = {
    "website/": (
        "the documentation site, which has its own toolchain (its own package, build "
        "and tests) and is not covered by these gates"
    ),
}
_EXCLUDED = tuple(EXCLUDED)

GENERATED_HEADER = re.compile(r"\bCode generated\b.*\bDO NOT EDIT\b", re.DOTALL)
COMMENT_LINE = re.compile(r"\s*(?:$|#|//|/\*|\*)")


@dataclass(frozen=True)
class Source:
    """One hand-written file: its path relative to the root, its language and its text."""

    path: str
    language: str
    text: str


def lines(text: str) -> list[str]:
    """Return the lines of `text`, split at each newline and nowhere else.

    ratchet.py reads the line a finding points at by this split, and this
    repository's scanners number their findings by it, so the two agree;
    `str.splitlines` also breaks at other characters, and would not.
    """
    return text.split("\n")


def has_generated_header(text: str) -> bool:
    """Return whether `text` says, in the comments it opens with, that it is generated."""
    header = []
    for line in lines(text):
        if not COMMENT_LINE.match(line):
            break
        header.append(line)
    return GENERATED_HEADER.search("\n".join(header)) is not None


def _pattern(glob: str) -> re.Pattern[str]:
    """Return the regex for `glob`: `*` within one path segment, a `**` segment across any."""
    out = ""
    for i, part in enumerate(glob.split("/")):
        sep = "/" if i else ""
        if part == "**":
            out += f"(?:{sep}[^/]+)*" if i else "(?:[^/]+/)*"
        else:
            out += sep + "[^/]*".join(re.escape(piece) for piece in part.split("*"))
    return re.compile(out + r"\Z")


_GENERATED = {glob: _pattern(glob) for glob in GENERATED}


def generated_by(path: str) -> str | None:
    """Return the GENERATED entry that lists `path`, or None."""
    return next((g for g, p in _GENERATED.items() if p.match(path)), None)


def read(path: str) -> str:
    """Return the text of the file at `path`, relative to the repository root."""
    return (REPO_ROOT / path).read_text(encoding="utf-8", errors="replace")


def gated_files() -> list[tuple[str, str]]:
    """Return (path, language) for every tracked file with a gated suffix, sorted."""
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    ).stdout
    found = []
    for path in sorted(p for p in out.split("\0") if p):
        language = LANGUAGES.get(Path(path).suffix)
        if language is not None and not path.startswith(_EXCLUDED):
            found.append((path, language))
    return found


def check_generated() -> list[str]:
    """Return what is wrong with GENERATED against the tree; empty means nothing."""
    files = gated_files()
    matched = {generated_by(path) for path, _ in files}
    problems = [
        f"GENERATED lists {glob}, which matches no tracked file"
        for glob in GENERATED
        if glob not in matched
    ]
    for path, _ in files:
        listed, header = generated_by(path), has_generated_header(read(path))
        if listed and not header:
            problems.append(f"{path} is listed as generated ({listed}) but has no generated header")
        elif header and not listed:
            problems.append(f"{path} has a generated header but GENERATED does not list it")
    return problems


def sources(gate: str) -> Iterator[Source]:
    """Yield every hand-written file of the languages `gate` reads, sorted by path."""
    for path, language in gated_files():
        if gate in GATES[language] and generated_by(path) is None:
            yield Source(path, language, read(path))


def hand_written(languages: list[str]) -> list[str]:
    """Return the hand-written paths of `languages`, or of every language when empty."""
    return [
        path
        for path, language in gated_files()
        if (not languages or language in languages) and generated_by(path) is None
    ]


def main(argv: list[str]) -> int:
    """Run the `files` or the `check` command."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("command", choices=["files", "check"])
    parser.add_argument("--language", action="append", default=[], choices=sorted(GATES))
    args = parser.parse_args(argv)
    lines = hand_written(args.language) if args.command == "files" else check_generated()
    for line in lines:
        print(line)
    return 1 if args.command == "check" and lines else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
