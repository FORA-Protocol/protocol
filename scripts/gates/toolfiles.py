"""What a gate script declares: its baseline, its tool files, and the helper it runs.

A gate script passes ratchet.py its baseline and, as `--tool-file FILE`, each file
that decides what its tool reports; the helper it runs (go-tools.sh, python-tools.sh
or node-tools.sh) passes the files that pin its toolchain the same way. `declared`
reads those from a script's text as the shell reads its words, so a path that is
only mentioned, in a comment or inside a longer path, declares nothing. ratchet.py
reads the declaration at HEAD, to refuse a --tool-file the scripts do not pass, and
at the merge base, where only what was declared there can make a change a tool
change.

A tool file is a path, or `PATH#PART` for the part of a TOML or JSON file that
decides the tool's report: a dotted key path, in which a step into a list takes
the element whose `name` is that step (`sdk/python/uv.lock#package.ruff`). So the
version field of a package manifest is not part of a tool. The reader of the
gate's format is a tool file of every gate, as `scripts/gates/formats.py#FORMAT`:
the code that reading that format runs, without comments and docstrings, so a
comment or another format's reader is not a change to it.

The module needs only the Python standard library.
"""

from __future__ import annotations

import ast
import copy
import itertools
import json
import re
import shlex
import tomllib
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

# Where the gates keep their baselines, and how a gate script names one.
BASELINE_PATH = re.compile(r"scripts/gates/baselines/[\w.-]+\.json")
# The helper a gate script runs its tool through.
RUNNER_PATH = re.compile(r"scripts/gates/[\w.-]+\.sh")
# The module that reads every tool's output into findings.
FORMATS_FILE = "scripts/gates/formats.py"
TOOL_FILE = "--tool-file"
# A shell comment: a `#` at the start of a line or after a blank, to the line's end.
COMMENT = re.compile(r"(?m)(?:^|(?<=[ \t]))#.*$")


@dataclass(frozen=True)
class Declared:
    """What one script's words declare. `runner` is the helper script it execs, if any."""

    baselines: frozenset[str] = frozenset()
    tool_files: frozenset[str] = frozenset()
    runner: str | None = None

    def __or__(self, other: Declared) -> Declared:
        return Declared(
            self.baselines | other.baselines,
            self.tool_files | other.tool_files,
            self.runner or other.runner,
        )


def words(text: str) -> list[str]:
    """Return the words of a shell script, as the shell splits them, without comments.

    As in the shell, a `#` starts a comment only where a word would start, so
    `FILE#PART` is one word.
    """
    script = COMMENT.sub("", text.replace("\\\n", " "))
    lexer = shlex.shlex(script, posix=True, punctuation_chars=True)
    lexer.commenters = ""
    lexer.whitespace_split = True
    return list(lexer)


def declared(text: str) -> Declared:
    """Return what the script `text` declares, or refuse a script the shell cannot split."""
    try:
        ws = words(text)
    except ValueError as exc:
        raise ValueError(f"cannot split it into shell words: {exc}") from exc
    tools = {b for a, b in itertools.pairwise(ws) if a == TOOL_FILE}
    tools |= {w.removeprefix(TOOL_FILE + "=") for w in ws if w.startswith(TOOL_FILE + "=")}
    after_exec = [b for a, b in itertools.pairwise(ws) if a == "exec"]
    runner = next((w for w in after_exec if RUNNER_PATH.fullmatch(w)), None)
    baselines = frozenset(w for w in ws if BASELINE_PATH.fullmatch(w))
    return Declared(baselines, frozenset(tools), runner)


def declare(text: str, where: str, read: Callable[[str], str | None]) -> Declared:
    """Return what the gate script `where`, whose text is `text`, and its helper declare.

    `read` returns the helper's text at the commit `text` is from. A script the
    shell cannot split is refused with a ValueError that names it.
    """
    found = _declared_in(text, where)
    helper = read(found.runner) if found.runner is not None else None
    if found.runner is None or helper is None:
        return found
    return found | _declared_in(helper, found.runner)


def _declared_in(text: str, name: str) -> Declared:
    try:
        return declared(text)
    except ValueError as exc:
        raise ValueError(f"{name}: {exc}") from exc


def tool_edits(
    specs: frozenset[str],
    changed: frozenset[str],
    before: Callable[[str], str | None],
    now: Callable[[str], str | None],
) -> tuple[list[str], list[str]]:
    """Return the tool files of `specs` that differ between `before` and `now`, and the
    other files of `changed`, baselines aside: the edits that are not to the tool.
    """
    edited = sorted(s for s in specs if path_of(s) in changed and _held(s, before) != _held(s, now))
    paths = {path_of(s) for s in specs}
    others = sorted(p for p in changed if p not in paths and not BASELINE_PATH.fullmatch(p))
    return edited, others


def _held(spec: str, read: Callable[[str], str | None]) -> str | None:
    """Return `content`, or a note that the file cannot be read as the part names it."""
    try:
        return content(spec, read)
    except ValueError as exc:
        return f"unreadable: {exc}"


def unreadable(spec: str, read: Callable[[str], str | None]) -> str | None:
    """Return why the tool file `spec` cannot be read now, or None if it can."""
    path = path_of(spec)
    if read(path) is None:
        return "does not exist; name it from the repository root"
    try:
        if content(spec, read) is None:
            return f"names a part that {path} does not have"
    except ValueError as exc:
        return f"cannot be read: {exc}"
    return None


def reader_spec(fmt: str) -> str:
    """Return the tool file that stands for the reader of the format `fmt`."""
    return f"{FORMATS_FILE}#{fmt}"


def path_of(spec: str) -> str:
    """Return the file a tool file names, without its part."""
    return spec.partition("#")[0]


def content(spec: str, read: Callable[[str], str | None]) -> str | None:
    """Return what the tool file `spec` holds, as text, or None if it holds nothing.

    `read` returns a file's text, or None when the file does not exist.
    """
    path, _, part = spec.partition("#")
    text = read(path)
    if text is None or not part:
        return text
    if path == FORMATS_FILE:
        return reader_source(text, part)
    data: object = json.loads(text) if path.endswith(".json") else tomllib.loads(text)
    for step in part.split("."):
        if isinstance(data, list):
            data = next((e for e in data if isinstance(e, dict) and e.get("name") == step), None)
        elif isinstance(data, dict):
            data = data.get(step)
        else:
            data = None
        if data is None:
            return None
    return json.dumps(data, sort_keys=True)


def reader_source(text: str, fmt: str) -> str | None:
    """Return the code that reading the format `fmt` runs, in the module source `text`.

    That is the entry of `fmt` in FORMATS and `measure`, which reads every format's
    messages, and each top-level definition they use, transitively, written out
    without comments and docstrings. None if FORMATS has no entry `fmt`.
    """
    tree = ast.parse(text)
    defs: dict[str, ast.stmt] = {}
    for node in tree.body:
        names: list[str] = []
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names = [node.name]
        elif isinstance(node, ast.Assign):
            names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names = [node.target.id]
        defs.update(dict.fromkeys(names, node))
    entry = _entry(defs.pop("FORMATS", None), fmt)
    if entry is None:
        return None
    used: dict[str, ast.stmt] = {}
    pending: list[ast.AST] = [entry, *([defs["measure"]] if "measure" in defs else [])]
    while pending:
        for n in ast.walk(pending.pop()):
            if isinstance(n, ast.Name) and n.id in defs and n.id not in used:
                used[n.id] = defs[n.id]
                pending.append(defs[n.id])
    parts = [ast.unparse(entry), *(_unparsed(used[name]) for name in sorted(used))]
    return "\n".join(parts)


def _entry(node: ast.stmt | None, fmt: str) -> ast.expr | None:
    """Return the value of the key `fmt` in the dict that the statement `node` assigns."""
    value = node.value if isinstance(node, (ast.Assign, ast.AnnAssign)) else None
    if not isinstance(value, ast.Dict):
        return None
    for key, item in zip(value.keys, value.values, strict=True):
        if isinstance(key, ast.Constant) and key.value == fmt:
            return item
    return None


def _unparsed(node: ast.stmt) -> str:
    """Return `node` written out without the docstrings of the definitions in it."""
    node = copy.deepcopy(node)
    for n in ast.walk(node):
        body = getattr(n, "body", None)
        if (
            isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and isinstance(body, list)
            and body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            n.body = body[1:] or [ast.Pass()]
    return ast.unparse(node)
