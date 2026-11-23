#!/usr/bin/env python3
"""List every inline suppression in the hand-written code, for the suppression gate.

AGENTS.md forbids silencing a finding inline: an exclusion goes in the tool's
config, with its reason. This script finds the inline forms in every file
scope.py puts in scope, and prints one `path<TAB>line<TAB>kind<TAB>-<TAB>inline
suppression` row for each, in ratchet.py's `lines` format, with the number of
the line the suppression is on. The ratchet reads that line's text, so a
suppression is identified by its file, its kind and the text of its line: moving
the line keeps its baseline entry, to another file too, and editing it makes a
new one. The row carries no size, so no number in the line is measured. Lines
are counted at each newline, as the ratchet counts them.

KINDS lists the forms, each written to the grammar of the tool that reads it:
- Go: `//nolint`, which golangci-lint reads, and `#nosec` in a comment, which
  gosec reads.
- Python: `# noqa` in any letter case, and the file-wide `# ruff: noqa` and
  `# flake8: noqa`, which ruff reads; the isort action comments
  (`# isort: skip`, `skip_file`, `off`), which ruff's import sorting reads;
  `# fmt: off` and `# fmt: skip`, which ruff's formatter reads; and
  `# type: ignore`, a `# mypy:` inline config line and the `@no_type_check`
  decorator, which mypy reads.
- TypeScript and JavaScript: `biome-ignore`, which biome reads; `@ts-ignore`,
  `@ts-expect-error` and `@ts-nocheck`, which tsc reads in a `//` comment, in a
  `/*` or `/**` comment, and on the last line of a block comment; and
  `eslint-disable`. TypeScript also has the double assertion through `unknown`
  (`as unknown as`, `(x as unknown) as`, and the angle-bracket `<unknown>`
  form), which turns off the compiler's check that the two types overlap.

A comment marker that follows a quote character is inside a string, such as a
generator writing `// @ts-nocheck` into its output, and is not counted. A line of
a multi-line string cannot be told apart that way, so a generator that writes a
marker on a line of its own builds it from parts, as `${"@ts-"}nocheck`.

Usage: inline_suppressions.py   (prints the rows; exits 0)
"""

from __future__ import annotations

import re
import sys

from scope import sources

NOT_IN_STRING = r"(?<![\"'`])"
# A comment in the C family: `//`, `///`, `/*` or `/**`, or the `*`s that open a
# line inside a block comment.
C_COMMENT = r"(?:" + NOT_IN_STRING + r"/[/*]+|^\s*\*+)\s*"
HASH = NOT_IN_STRING + r"#\s*"

JS_KINDS = (
    ("biome-ignore", re.compile(C_COMMENT + r"biome-ignore\b")),
    ("ts-ignore", re.compile(C_COMMENT + r"@ts-ignore\b")),
    ("ts-expect-error", re.compile(C_COMMENT + r"@ts-expect-error\b")),
    ("ts-nocheck", re.compile(C_COMMENT + r"@ts-nocheck\b")),
    ("eslint-disable", re.compile(C_COMMENT + r"eslint-disable")),
    ("as-unknown-as", re.compile(r"\bas\s+unknown\s*\)*\s+as\b")),
)
KINDS: dict[str, tuple[tuple[str, re.Pattern[str]], ...]] = {
    "go": (
        ("nolint", re.compile(NOT_IN_STRING + r"//\s*nolint\b")),
        ("nosec", re.compile(NOT_IN_STRING + r"/[/*].*#nosec\b")),
    ),
    "python": (
        ("noqa", re.compile(HASH + r"noqa\b", re.IGNORECASE)),
        ("file-noqa", re.compile(HASH + r"(?:ruff|flake8)\s*:\s*noqa\b", re.IGNORECASE)),
        ("isort-skip", re.compile(HASH + r"(?:ruff:\s*)?isort:\s*(?:skip_file|skip|off)\b")),
        ("fmt-off", re.compile(HASH + r"fmt:\s*(?:off|skip)\b")),
        ("type-ignore", re.compile(HASH + r"type:\s*ignore\b")),
        ("mypy-config", re.compile(HASH + r"mypy:")),
        ("no-type-check", re.compile(r"^\s*@(?:typing\.)?no_type_check\b")),
    ),
    "typescript": (
        *JS_KINDS,
        ("unknown-assertion", re.compile(r"(?<![\w$.)\]])<\s*unknown\s*>\s*[\w$(<\[]")),
    ),
    "javascript": JS_KINDS,
}


def suppressions(language: str, text: str) -> list[tuple[str, int]]:
    """Return the (kind, 1-based line number) of each suppression in `text`."""
    kinds = KINDS[language]
    found = []
    for number, line in enumerate(text.split("\n"), start=1):
        for kind, pattern in kinds:
            if pattern.search(line):
                found.append((kind, number))
    return found


def main() -> int:
    """Print one `path<TAB>line<TAB>kind<TAB>-<TAB>inline suppression` row per suppression."""
    for source in sources("inline-suppressions"):
        for kind, number in suppressions(source.language, source.text):
            print(f"{source.path}\t{number}\t{kind}\t-\tinline suppression")
    return 0


if __name__ == "__main__":
    sys.exit(main())
