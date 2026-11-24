"""What a gate script declares: its baseline, its tool files, and the helper it runs.

A gate script passes ratchet.py its baseline and, as `--tool-file FILE`, each file
that decides what its tool reports; the helper it runs (go-tools.sh, python-tools.sh
or node-tools.sh) passes the files that pin its toolchain the same way. `declared`
reads those from a script's text as the shell reads its words, so a path that is
only mentioned, in a comment or inside a longer path, declares nothing. ratchet.py
reads the declaration at HEAD, to refuse a --tool-file the scripts do not pass, and
at the merge base, where only what was declared there can make a change a tool
change.

A tool file is a path, or `PATH#PART` for the part of a file that decides the
tool's report:
- in a TOML or JSON file, a dotted key path, in which a step into a list takes the
  first element whose `name` is that step (`sdk/python/pyproject.toml#tool.ruff`).
  So the version field of a package manifest is not part of a tool;
- in a lockfile (`package-lock.json`, `uv.lock`), a package
  (`sdk/python/uv.lock#package.ruff`): the package, the packages only the gate's
  tools bring, and the entries that record the project's pin of it (lockfiles.py);
- the reader of the gate's format, a tool file of every gate, as
  `scripts/gates/formats.py#FORMAT`: the code that reading that format runs, without
  comments and docstrings, so a comment or another format's reader is not a change
  to it.

`tool_edits` tells a change's edits to the tool from its other edits. The rest of a
file named only in part, outside its parts, is not the tool: the rest of a manifest
or a lockfile is the code's own version and dependencies, and the rest of formats.py
is the other readers and the ratchet's own code. So an edit to it is an edit to
something else, which re-keys nothing.

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
from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING

import lockfiles

if TYPE_CHECKING:
    from collections.abc import Callable, Collection, Iterable

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


def tool_args(text: str, program: str) -> list[str]:
    """Return the words the script `text` passes to `program`, in the tool command after `--`.

    gate-ts-types.sh passes its tsc projects to tsc-projects.sh this way, after the
    path of tsc. Empty if the tool command does not run `program`.
    """
    ws = words(text)
    command = ws[ws.index("--") + 1 :] if "--" in ws else []
    return command[command.index(program) + 1 :] if program in command else []


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
    edits of `changed` that are not to the tool, baselines aside.

    An edit that is not to the tool is an edit to a file no spec names, or to a file
    named only in part beyond its parts (the rest of a manifest or a lockfile is the
    code's own version and dependencies). A file named in part that cannot be read as
    its parts name it, on either side, counts as both: nothing shows its tool unchanged,
    or the rest of it.
    """
    named = _specs_by_path(specs)
    edited: list[str] = []
    others = [p for p in changed if p not in named and not BASELINE_PATH.fullmatch(p)]
    for path in sorted(changed.intersection(named)):
        parts = named[path]
        try:
            (was, was_rest), (held, rest) = _held(path, parts, before), _held(path, parts, now)
        except ValueError:
            edited += parts.values()
            others.append(f"{path}, which cannot be read as its tool files name it")
            continue
        edited += [spec for part, spec in parts.items() if was[part] != held[part]]
        if was_rest != rest:
            others.append(f"{path} beyond the tool's part")
    return sorted(edited), sorted(others)


def _specs_by_path(specs: Iterable[str]) -> dict[str, dict[str, str]]:
    """Return each path `specs` name, with each part named in it (`""` for the whole file)
    and the spec that names it."""
    by_path: dict[str, dict[str, str]] = defaultdict(dict)
    for spec in specs:
        path, _, part = spec.partition("#")
        by_path[path][part] = spec
    return by_path


def unreadable(spec: str, read: Callable[[str], str | None]) -> str | None:
    """Return why the tool file `spec` cannot be read now, or None if it can."""
    path = path_of(spec)
    try:
        if read(path) is None:
            return "does not exist; name it from the repository root"
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

    `read` returns a file's text, or None when the file does not exist. A part of a
    file that cannot be read as the part names it raises ValueError.
    """
    path, _, part = spec.partition("#")
    return _held(path, [part], read)[0][part]


def _held(
    path: str, parts: Collection[str], read: Callable[[str], str | None]
) -> tuple[dict[str, str | None], str | None]:
    """Return what each of `parts` (`""` for the whole file) holds in `path`, as text, and
    the rest of the file outside every part: None when a part is the whole file.

    A part of a file that does not exist, or that cannot be read as the part names it,
    raises ValueError.
    """
    text = read(path)
    named = [part for part in parts if part]
    if text is None:
        if named:
            raise ValueError(f"{path} does not exist")
        return {"": None}, None
    held, rest = _split(path, text, named) if named else ({}, None)
    if "" in parts:
        return {**held, "": text}, None
    return held, rest


def _split(path: str, text: str, parts: list[str]) -> tuple[dict[str, str | None], str]:
    """Return what each of `parts` holds in the file `path`, whose text is `text`, and the
    rest of the file."""
    if path == FORMATS_FILE:
        return _readers(text, parts)
    if lockfiles.is_lockfile(path):
        found, rest = lockfiles.split(path, text, parts)
        held = {part: None if value is None else _canonical(value) for part, value in found.items()}
        return held, _canonical(rest)
    return _keys(path, text, parts)


def _canonical(value: object) -> str:
    """Return `value` as JSON text that is the same for the same value: keys sorted, and
    a value JSON has no type for (a TOML date) written as its repr, unlike any string."""
    return json.dumps(value, sort_keys=True, default=repr)


def _keys(path: str, text: str, parts: list[str]) -> tuple[dict[str, str | None], str]:
    """Return the value at each key path of `parts` in the JSON or TOML file `path`, and
    the file without them."""
    data: object = json.loads(text) if path.endswith(".json") else tomllib.loads(text)
    held: dict[str, str | None] = {}
    rest = data
    for part in parts:
        steps = part.split(".")
        value = _walk(data, steps)
        held[part] = None if value is None else _canonical(value)
        rest = _without(rest, steps)
    return held, _canonical(rest)


def _first_named(items: list[object], name: str) -> int | None:
    """Return the index of the first element of `items` whose `name` is `name`."""
    found = (
        i for i, item in enumerate(items) if isinstance(item, dict) and item.get("name") == name
    )
    return next(found, None)


def _walk(data: object, steps: list[str]) -> object | None:
    """Return the value at the key path `steps` in `data`, or None if it has none. A step
    into a list takes the first element whose `name` is that step."""
    for step in steps:
        if isinstance(data, list):
            index = _first_named(data, step)
            data = None if index is None else data[index]
        elif isinstance(data, dict):
            data = data.get(step)
        else:
            data = None
        if data is None:
            return None
    return data


def _without(data: object, steps: list[str]) -> object:
    """Return `data` without the value that `_walk` finds at the key path `steps`."""
    head, rest = steps[0], steps[1:]
    if isinstance(data, dict) and head in data:
        table = dict(data)
        if rest:
            table[head] = _without(table[head], rest)
        else:
            del table[head]
        return table
    index = _first_named(data, head) if isinstance(data, list) else None
    if index is None or not isinstance(data, list):
        return data
    items = list(data)
    if rest:
        items[index] = _without(items[index], rest)
    else:
        del items[index]
    return items


def _readers(text: str, fmts: list[str]) -> tuple[dict[str, str | None], str]:
    """Return the code that reading each format of `fmts` runs, in the module source
    `text`, and the rest of the module.

    A format's reader is its entry in FORMATS, `measure`, which reads every format's
    messages, and each top-level definition and import they use, transitively, written
    out without comments and docstrings; None if FORMATS has no entry for the format.
    The rest is every other top-level statement, FORMATS without the readers' entries,
    also without comments and docstrings: a comment changes no tool's report outside its
    own file, and an edited formats.py keeps the exact entries of its own findings.
    """
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        raise ValueError(f"it is not Python: {exc}") from exc
    defs = _definitions(tree)
    table = defs.pop("FORMATS", None)
    held: dict[str, str | None] = {}
    taken: set[ast.stmt] = set()
    for fmt in fmts:
        entry = _entry(table, fmt)
        used = {} if entry is None else _closure(entry, defs)
        taken.update(used.values())
        nodes = dict.fromkeys(used[name] for name in sorted(used))
        code = [ast.unparse(entry), *map(_unparsed, nodes)] if entry is not None else None
        held[fmt] = None if code is None else "\n".join(code)
    rest = [
        _unparsed(_without_entries(node, fmts))
        for node in tree.body
        if node not in taken and not _is_text(node)
    ]
    return held, "\n".join(rest)


def _definitions(tree: ast.Module) -> dict[str, ast.stmt]:
    """Return each top-level statement of `tree` that binds a name, by that name."""
    defs: dict[str, ast.stmt] = {}
    for node in tree.body:
        defs.update(dict.fromkeys(_bound(node), node))
    return defs


def _bound(node: ast.stmt) -> list[str]:
    """Return the names a top-level statement binds: a definition, an assignment or an
    import, so a reader that needs a new import still changes only its own code."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [node.name]
    if isinstance(node, ast.Assign):
        return [t.id for t in node.targets if isinstance(t, ast.Name)]
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return [node.target.id]
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return [(alias.asname or alias.name).partition(".")[0] for alias in node.names]
    return []


def _closure(entry: ast.expr, defs: dict[str, ast.stmt]) -> dict[str, ast.stmt]:
    """Return the top-level statements reading with `entry` runs, by name: `measure`, which
    reads the messages of every format, and every statement they use, transitively."""
    used: dict[str, ast.stmt] = {"measure": defs["measure"]} if "measure" in defs else {}
    pending: list[ast.AST] = [entry, *used.values()]
    while pending:
        for n in ast.walk(pending.pop()):
            if isinstance(n, ast.Name) and n.id in defs and n.id not in used:
                used[n.id] = defs[n.id]
                pending.append(defs[n.id])
    return used


def _entry(node: ast.stmt | None, fmt: str) -> ast.expr | None:
    """Return the value of the key `fmt` in the dict that the statement `node` assigns."""
    value = node.value if isinstance(node, (ast.Assign, ast.AnnAssign)) else None
    if not isinstance(value, ast.Dict):
        return None
    for key, item in zip(value.keys, value.values, strict=True):
        if isinstance(key, ast.Constant) and key.value == fmt:
            return item
    return None


def _without_entries(node: ast.stmt, fmts: Collection[str]) -> ast.stmt:
    """Return `node` without the entries of `fmts`, if it is the statement assigning FORMATS."""
    if "FORMATS" not in _bound(node):
        return node
    node = copy.deepcopy(node)
    table = node.value if isinstance(node, (ast.Assign, ast.AnnAssign)) else None
    if isinstance(table, ast.Dict):
        kept = [
            (key, item)
            for key, item in zip(table.keys, table.values, strict=True)
            if not (isinstance(key, ast.Constant) and key.value in fmts)
        ]
        table.keys = [key for key, _ in kept]
        table.values = [item for _, item in kept]
    return node


def _is_text(node: ast.stmt) -> bool:
    """Say whether `node` is a bare string, such as the module's docstring."""
    return (
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    )


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
