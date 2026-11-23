#!/usr/bin/env python3
"""List every hand-written file longer than its language's limit, for the file-length gate.

The limits are this repository's decision, recorded in ADR-001 decision 8 and
listed in AGENTS.md; LIMITS below holds them. Test files take the same limit as
any other file, because a test is code that has to be read and kept as much as
the code it checks. The files are the ones scope.py defines. A line is any line,
blank or comment included, counted as `wc -l` counts them, with a last line that
has no newline counted too.

The script prints one `path<TAB>file-length<TAB>length<TAB>message` row per file
over its limit, in ratchet.py's `lines` format. The ratchet keeps the length as
the entry's size: a baselined long file may shrink, and the gate fails if it
grows.

Usage: file_length.py   (prints the rows; exits 0)
"""

from __future__ import annotations

import sys

from scope import sources

LIMITS = {"go": 500, "python": 500, "typescript": 400, "javascript": 400}


def line_count(text: str) -> int:
    """Return the number of lines in `text`: its newlines, and a last line without one."""
    return text.count("\n") + (1 if text and not text.endswith("\n") else 0)


def main() -> int:
    """Print one row per file over its limit."""
    for source in sources("file-length"):
        limit = LIMITS[source.language]
        length = line_count(source.text)
        if length > limit:
            print(f"{source.path}\tfile-length\t{length}\tover the limit of {limit} lines")
    return 0


if __name__ == "__main__":
    sys.exit(main())
