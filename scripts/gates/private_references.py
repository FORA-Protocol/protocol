#!/usr/bin/env python3
"""List every reference to a private resource in the tracked files, for its gate.

This repository is public, so no tracked file may point at something a reader
cannot open. The scanner reads every text file git tracks, the documentation
site and the generated code included, and prints one
`path<TAB>line<TAB>kind<TAB>-<TAB>private reference` row per line that
matches a kind, in ratchet.py's `lines` format, so the ratchet keys each
finding by the text of its line. It reads every tracked path too, and prints a
row about the whole file, with `private reference in the path`, for a path that
matches a kind.

A spelling that hides a reference from a plain match is still found. Each line
is matched as it is and in a normalized form: HTML character references
decoded, the dashes U+2010 to U+2015 read as `-`, the zero-width characters
U+200B to U+200D dropped, and then asterisks, underscores and backslashes
dropped as well. A line that ends inside a key, a task id or a repository name
is also matched joined to the next line, and the finding is reported on the
first. A file that starts
with a UTF-16 byte order mark is read as UTF-16; any other file with a NUL byte
in its first 8000 bytes is binary and is not read.

The kinds, in KINDS:

- tracker-key: an issue key of the project's private tracker (`FORA-` and a
  number, in any letter case, after anything but a letter or a digit). The
  key of the project's former name is not repeated here:
  scripts/check-doc-conformance.sh refuses that name anywhere in the tree, in
  any letter case, so any such key already fails it.
- tracker: the private tracker by name, or the local task tracker the private
  repositories use.
- task-id: an id of the local task tracker in this project's own form: the
  project's lowercase name, a hyphen, and a short id that holds a digit,
  optionally with dotted child numbers. NOT_TASK_IDS lists the names of that
  form that are not ids, such as the C2PA profile's. The form under the
  project's former name is refused by scripts/check-doc-conformance.sh, as above.
- private-repository: the name of a private repository, in any letter case,
  with its words joined by a hyphen, an underscore or nothing (so in camel case
  too). Some local task ids carry their repository's name as their prefix, and
  this kind finds those.
- local-path: a developer's home directory: `/Users/<name>` or `/home/<name>`
  anywhere, quoted or not; a lower-case `/users/<name>/...` path that does not
  follow an HTTP method, a quote or a `#`; under `/root/`, a dot-file or a
  usual working directory anywhere and any two segments outside that context;
  `C:\\Users\\` in any letter case; a home named by a tilde and a user name; a
  macOS per-user temporary directory (the folders under /private/var); and a
  path under `~/` or `$HOME/` that does not start with a dot. A dot-directory
  there is where a tool keeps its own files, which documentation names on
  purpose. A `file://` URL is read too; a home directory in a web address
  follows its host, so it is not.
- service-path: a path into the services' repository written as though it
  were in this one: one of its source trees (`src/` followed by one of its
  services, the edge worker's whole tree included), or an `internal/` package
  that sdk/go/internal does not hold, either one with or without a leading
  `./`. A link to a published repository names its host first, so a path that
  follows a `/`, a word character, a dot or a hyphen is not a finding.

A pattern that would match its own text spells one character as a class, as in
`[s]`, so this file reads clean. The tests build every sample from parts.

A deliberate exception is an entry in ALLOWED, this gate's config: the path, the
kind, the exact text of the line with its outer whitespace removed, and the
reason. An entry allows that one line in that one file. An entry that matches no
line is printed as a `stale-allowance` row about its file, which fails the
gate, so the list only holds exceptions that are still needed. There is no inline form.

Usage: private_references.py   (prints the rows; exits 0)
"""

from __future__ import annotations

import html
import re
import sys
from dataclasses import dataclass

from scope import REPO_ROOT, lines, tracked


@dataclass(frozen=True)
class Allowed:
    """One allowed line: its file, its kind, its stripped text, and why it may stay."""

    path: str
    kind: str
    line: str
    reason: str


ALLOWED: tuple[Allowed, ...] = ()

# Not preceded by a path, a host or a hyphen, so `github.com/org/repo/blob/main/src/...`,
# `sdk/go/internal/...` and `my-src/...` are not read as bare paths. A leading
# `./` still is.
BARE = r"(?<![\w./-])(?:\./)?"
SERVICES = "mcp|edge|exchange|broker|identity|console|onboarding"
# Names of the task-id form that are not task ids: the C2PA profile is named for it.
NOT_TASK_IDS = ("c2pa",)
# Not preceded by a letter or a digit: an underscore or a hyphen before a key
# does not hide it, as a word boundary would let `fix_` do.
START = r"(?<![A-Za-z0-9])"
END = r"(?![A-Za-z0-9])"
TASK_ID = (
    START
    + r"(?<!-)for[a]-(?!(?:"
    + "|".join(NOT_TASK_IDS)
    + r")\b)(?=[a-z0-9]*[0-9])(?=[a-z0-9]*[a-z])[a-z0-9]{2,8}(?:\.[0-9]+)*"
    + END
)
# The words of a repository name, joined by a hyphen, an underscore or nothing.
SEP = r"[-_]?"
REPOSITORIES = (
    rf"agentic{SEP}content{SEP}acces[s]|{START}piarc[h]{END}|{START}pi{SEP}terrafor[m]{END}"
)
# A home directory. `/Users/<name>` (macOS) and `/home/<name>` (Linux) count in any
# position, quoted or not, with or without a path under the name, matched in their
# own letter case. A leaked path is most often quoted, so that is the safe side to
# err on; a web route under /home is a finding too, and a real one takes an
# ALLOWED entry. Lower-case `/users/` is also a common URL path, so it counts
# only as a path, a user name and a file or directory under it, and not after an
# HTTP method, a quote or a `#` (`GET /users/me/settings`, a JSON pointer). Under
# the superuser's home a dot-file or a usual working directory counts anywhere, and
# any two segments count outside that context (root's default GOPATH, go/src under
# /root, among them), so `"/root/child/name"` does not.
NOT_A_PATH_START = r"(?<![\w.#\"'-])(?<!GET )(?<!PUT )(?<!POST )(?<!PATCH )(?<!DELETE )"
ROOT_DIRS = "projects|work|src|code|repos|git|dev|desktop|documents|downloads|tmp"
HOME = (
    r"(?<![\w.-])(?-i:/(?:Users|home)/)[a-z0-9_]"
    + r"|"
    + NOT_A_PATH_START
    + r"(?-i:/users/)[a-z0-9_][\w.-]*/[\w.-]"
    + r"|(?<![\w.-])/root/(?:\.[\w-]|(?:"
    + ROOT_DIRS
    + r")/)"
    + r"|"
    + NOT_A_PATH_START
    + r"/root/[\w-]+/[\w.-]"
    + r"|\b[a-z]:\\+users\\+[a-z0-9_]"
    + r"|(?<![\w.-])/private/var/folder[s]/"
)
HOME_RELATIVE = (
    r"(?<![\w./-])(?:~|\$\{?home\}?)/[a-z0-9_]"
    r"|(?<![\w./&|^-])~[a-z][a-z0-9_-]*/(?=[\w.-]*[a-z])[\w.-]"
)
KINDS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("tracker-key", re.compile(START + r"FOR[A]-[0-9]+" + END, re.IGNORECASE)),
    ("tracker", re.compile(r"\bjir[a]\b|atlassia[n]\.net|\bbead[s]\b|\.bead[s]/", re.IGNORECASE)),
    ("task-id", re.compile(TASK_ID, re.IGNORECASE)),
    ("private-repository", re.compile(REPOSITORIES, re.IGNORECASE)),
    ("local-path", re.compile(f"{HOME}|{HOME_RELATIVE}", re.IGNORECASE)),
    ("service-path", re.compile(BARE + rf"src/(?:{SERVICES})/")),
)
# The kinds a line break can split: a key, a task id, a repository name.
JOINABLE = frozenset({"tracker-key", "task-id", "private-repository"})
DASHES = str.maketrans(
    {chr(c): "-" for c in range(0x2010, 0x2016)} | {0x200B: None, 0x200C: None, 0x200D: None}
)
HIDING = str.maketrans({"*": None, "_": None, "\\": None})
UTF16_BOMS = (b"\xff\xfe", b"\xfe\xff")
# A word every kind's match contains part of; a spelling without one is not searched.
TRIGGER = re.compile(
    r"for[a]|jir[a]|atlassia[n]|bead[s]|agentic|piarc[h]|terrafor[m]|users|home|root|/private/"
    r"|~|src/|internal/",
    re.IGNORECASE,
)
SPLIT_WINDOW = 64
# A comment marker that opens the second line of a split key; it is not part of the key.
CONTINUATION = re.compile(r"^\s*(?://+|#+|\*+|--)\s*")
INTERNAL = re.compile(BARE + r"internal/([a-z0-9_]+)")
SDK_INTERNAL = "sdk/go/internal/"
BINARY_PROBE = 8000


def sdk_internal_packages(paths: list[str]) -> frozenset[str]:
    """Return the names of the packages under sdk/go/internal that hold a tracked file."""
    return frozenset(
        p[len(SDK_INTERNAL) :].split("/", 1)[0]
        for p in paths
        if p.startswith(SDK_INTERNAL) and "/" in p[len(SDK_INTERNAL) :]
    )


def text_of(path: str) -> str | None:
    """Return the file's text, or None for a binary file or one missing from the tree."""
    try:
        data = (REPO_ROOT / path).read_bytes()
    except (FileNotFoundError, IsADirectoryError):
        return None
    if data.startswith(UTF16_BOMS):
        return data.decode("utf-16", errors="replace")
    if b"\0" in data[:BINARY_PROBE]:
        return None
    return data.decode("utf-8", errors="replace")


def spellings(line: str) -> tuple[str, ...]:
    """Return the distinct spellings of `line` that could hold a reference.

    They are `line` as it is, normalized, and normalized with `*`, `_` and `\\`
    dropped; a spelling with no word any kind starts from is left out, so most
    lines cost one search.
    """
    normal = (html.unescape(line) if "&" in line else line).translate(DASHES)
    forms = dict.fromkeys((line, normal, normal.translate(HIDING)))
    return tuple(form for form in forms if TRIGGER.search(form))


def kinds_in(line: str, internal: frozenset[str]) -> list[str]:
    """Return the kinds any spelling of `line` matches, in KINDS order.

    service-path for an `internal/` package sdk/go/internal does not hold comes last.
    """
    forms = spellings(line)
    found = [kind for kind, pattern in KINDS if any(pattern.search(form) for form in forms)]
    foreign = any(m[1] not in internal for form in forms for m in INTERNAL.finditer(form))
    if "service-path" not in found and foreign:
        found.append("service-path")
    return found


def split_kinds(line: str, following: str) -> list[str]:
    """Return the joinable kinds a match across the end of `line` and the start of
    `following` finds. A key, a task id or a name is short, so SPLIT_WINDOW characters
    of each side hold it; a comment marker that opens `following` is left out.

    A match counts only when it spans the break and its part on the first line is
    not a whole key, task id or name itself, so a key that ends a line is not joined
    to the next line's first word.
    """
    tail = line.rstrip()[-SPLIT_WINDOW:]
    head = CONTINUATION.sub("", following, count=1).lstrip()[:SPLIT_WINDOW]
    if not tail or not head or (head.startswith("-") and not tail.endswith("-")):
        # A line that starts with a minus or a list dash starts a new phrase.
        return []
    joined, cut = tail + head, len(tail)
    joinable = [(kind, pattern) for kind, pattern in KINDS if kind in JOINABLE]
    found = []
    for kind, pattern in joinable:
        for m in pattern.finditer(joined):
            spans = m.start() < cut < m.end()
            if spans and not any(p.fullmatch(joined, m.start(), cut) for _, p in joinable):
                found.append(kind)
                break
    return found


def references(text: str, internal: frozenset[str]) -> list[tuple[str, int, str]]:
    """Return the (kind, 1-based line number, stripped line) of each reference in `text`.

    Lines are counted at each newline, as the ratchet counts them.
    """
    numbered = lines(text)
    found = []
    for number, line in enumerate(numbered, start=1):
        following = numbered[number] if number < len(numbered) else ""
        kinds = kinds_in(line, internal) + split_kinds(line, following)
        found += [(kind, number, line.strip()) for kind in kinds]
    return found


def main() -> int:
    """Print one row per reference not in ALLOWED, and one per stale ALLOWED entry."""
    paths = tracked()
    internal = sdk_internal_packages(paths)
    allowed = {(a.path, a.kind, a.line): a for a in ALLOWED}
    used: set[tuple[str, str, str]] = set()
    for path in paths:
        for kind in kinds_in(path, internal):
            print(f"{path}\t-\t{kind}\t-\tprivate reference in the path")
        text = text_of(path)
        if text is None:
            continue
        for kind, number, line in references(text, internal):
            if (path, kind, line) in allowed:
                used.add((path, kind, line))
            else:
                print(f"{path}\t{number}\t{kind}\t-\tprivate reference")
    for key, entry in allowed.items():
        if key not in used:
            print(f"{entry.path}\t-\tstale-allowance\t-\t{entry.kind}: {entry.line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
