#!/usr/bin/env python3
"""List every inline suppression in the hand-written code, for the suppression gate.

AGENTS.md forbids silencing a finding inline: an exclusion goes in the tool's
config, with its reason. This script finds the inline forms in every file
scope.py puts in scope, and prints one `path<TAB>line<TAB>kind<TAB>-<TAB>inline
suppression` row for each, in ratchet.py's `lines` format, with the number of
the line the suppression is on. The ratchet reads that line's text, so a
suppression is identified by its file, its kind and the text of its line: moving
the line within its file keeps its baseline entry, and editing it makes a new
one. The gate reads the rows as the `suppressions` format, whose entries never
move to another file (carry.py). The row carries no size, so no number in the
line is measured. Lines are counted by scope.lines, as the ratchet counts them.

KINDS lists the forms, each written to the grammar of the tool that reads it:
- Go: `//nolint`, which golangci-lint reads after any further `/`s and spaces;
  `//lint:ignore` and `//lint:file-ignore`, which its `unused` linter reads;
  `//revive:disable` in each of its forms, which revive reads; and
  `//gocognit:ignore` and `//gocyclo:ignore`, which those two linters read on a
  function. `#nosec` in a comment and `//gosec:disable` are gosec's forms:
  .golangci.yml turns both off (gosec's `nosec` setting), and the gate lists
  them anyway, so that changing that setting cannot let one in.
- Python: `# noqa` in any letter case, the file-wide `# ruff: noqa` and
  `# flake8: noqa`, and ruff's own `# ruff: ignore[...]` for a line,
  `# ruff: file-ignore[...]` for a file and `# ruff: disable[...]` for a range,
  which ruff reads; the isort action comments (`# isort: skip` anywhere in a
  comment, `skip_file` and `off`), which ruff's import sorting reads;
  `# fmt: off`, `# fmt: skip` and `# yapf: disable`, which ruff's formatter
  reads; and `# type: ignore`, a `# mypy:` inline config line, and
  `no_type_check` on any line of code that names it, which takes in the
  decorator under any name and the import that binds it, which mypy reads.
- TypeScript and JavaScript: `biome-ignore`, which biome reads; `@ts-ignore`,
  `@ts-expect-error` and `@ts-nocheck` (in any letter case), which tsc reads;
  and `eslint-disable`. Each is found in a line or a block comment, and at the
  start of any line of a block comment, after any `*`s or `/`s: tsc reads the
  last such line, biome any. Both languages have the double assertion through
  `unknown` (`as unknown as`, `(x as unknown) as`), which turns off the
  compiler's check that the two types overlap; TypeScript also has the
  angle-bracket `<unknown>` form.
- Astro: the TypeScript forms, in the frontmatter, a script, a template
  expression (`{/* ... */}`) or a style block, and `biome-ignore` in an HTML
  comment (`<!-- biome-ignore ... -->`), which biome reads in the template.

A comment marker that follows a quote character is inside a string, such as a
generator writing `// @ts-nocheck` into its output, and is not counted. A line of
a multi-line string cannot be told apart that way, so a generator that writes a
marker on a line of its own builds it from parts, as `${"@ts-"}nocheck`.

Usage: inline_suppressions.py   (prints the rows; exits 0)
"""

from __future__ import annotations

import re
import sys

from scope import lines, sources

NOT_IN_STRING = r"(?<![\"'`])"
# A comment in the C family: `//`, `///`, `/*` or `/**`, or the start of a line
# inside a block comment, after any `*`s or `/`s that open it.
C_COMMENT = r"(?:" + NOT_IN_STRING + r"/[/*]+|^\s*[/*]*)\s*"
HASH = NOT_IN_STRING + r"#\s*"

UNKNOWN_ASSERTION = re.compile(r"(?<![\w$.)\]])<\s*unknown\s*>\s*[\w$(<\[]")
JS_KINDS = (
    ("biome-ignore", re.compile(C_COMMENT + r"biome-ignore\b")),
    ("ts-ignore", re.compile(C_COMMENT + r"@ts-ignore\b")),
    ("ts-expect-error", re.compile(C_COMMENT + r"@ts-expect-error\b")),
    ("ts-nocheck", re.compile(C_COMMENT + r"@ts-nocheck\b", re.IGNORECASE)),
    ("eslint-disable", re.compile(C_COMMENT + r"eslint-disable")),
    ("as-unknown-as", re.compile(r"\bas\s+unknown\s*\)*\s+as\b")),
)
KINDS: dict[str, tuple[tuple[str, re.Pattern[str]], ...]] = {
    "go": (
        ("nolint", re.compile(NOT_IN_STRING + r"//[/\s]*nolint\b")),
        ("lint-ignore", re.compile(NOT_IN_STRING + r"//lint:ignore\b")),
        ("lint-file-ignore", re.compile(NOT_IN_STRING + r"//lint:file-ignore\b")),
        ("revive-disable", re.compile(NOT_IN_STRING + r"//\s*revive:disable\b")),
        ("gocognit-ignore", re.compile(NOT_IN_STRING + r"//gocognit:ignore\b")),
        ("gocyclo-ignore", re.compile(NOT_IN_STRING + r"//gocyclo:\s*ignore\b")),
        ("nosec", re.compile(NOT_IN_STRING + r"/[/*].*#nosec\b")),
        ("gosec-disable", re.compile(NOT_IN_STRING + r"//gosec:disable\b")),
    ),
    "python": (
        ("noqa", re.compile(HASH + r"noqa\b", re.IGNORECASE)),
        ("file-noqa", re.compile(HASH + r"(?:ruff|flake8)\s*:\s*noqa\b", re.IGNORECASE)),
        ("ruff-ignore", re.compile(HASH + r"ruff\s*:\s*ignore\b")),
        ("ruff-file-ignore", re.compile(HASH + r"ruff\s*:\s*file-ignore\b")),
        ("ruff-disable", re.compile(HASH + r"ruff\s*:\s*disable\b")),
        # ruff's import sorting reads a skip comment anywhere in a comment, and the
        # skip_file and off comments only as written, so this also lists some it does not.
        ("isort-skip", re.compile(NOT_IN_STRING + r"#.*isort:\s*(?:skip|off)")),
        ("fmt-off", re.compile(HASH + r"fmt:\s*(?:off|skip)\b")),
        ("yapf-disable", re.compile(HASH + r"yapf:\s*disable\b")),
        ("type-ignore", re.compile(HASH + r"type:\s*ignore\b")),
        ("mypy-config", re.compile(HASH + r"mypy:")),
        ("no-type-check", re.compile(r"^[^#\"'`]*\bno_type_check\b")),
    ),
    "typescript": (
        *JS_KINDS,
        ("unknown-assertion", UNKNOWN_ASSERTION),
    ),
    "javascript": JS_KINDS,
    "astro": (
        *JS_KINDS,
        ("unknown-assertion", UNKNOWN_ASSERTION),
        ("biome-ignore", re.compile(NOT_IN_STRING + r"<!--\s*biome-ignore\b")),
    ),
}


def suppressions(language: str, text: str) -> list[tuple[str, int]]:
    """Return the (kind, 1-based line number) of each suppression in `text`."""
    kinds = KINDS[language]
    found = []
    for number, line in enumerate(lines(text), start=1):
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
