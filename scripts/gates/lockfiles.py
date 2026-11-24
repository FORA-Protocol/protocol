"""The part of a lockfile that a tool is: its package, what only it brings, and its pin.

A gate names a tool that a lockfile pins as `LOCK#PART` (toolfiles.py), where PART
names the tool's package: `packages.node_modules/NAME` in an npm package-lock.json,
`package.NAME` in a uv.lock. The lockfile also locks the code's own dependencies, so
the tool is not the whole file. What it is:

- the tool's package entry (in a uv.lock, every entry of that name);
- each package the gate's tools bring that the project's own requirements do not:
  reachable from the tool, and not reachable from the project's requirements when the
  walk stops at every tool. So the packages only a tool needs (biome's per-platform
  binaries, the dependencies only mypy has) are the tool's, and a package the code
  also needs (typing-extensions, which mypy and pydantic both use) is the code's;
- the entries in which the lockfile records the project's requirement of the tool: its
  key in the install maps of the project's entries (npm), and the list elements that
  name it in the project's entries and the manifest (uv).

Everything else in the lockfile is the code's: a package the project's requirements
reach belongs to no tool. Each side of a comparison is read from its own lockfile, so a
package that a new version of a tool starts to bring is the tool's without a word.

Every dependency counts on every platform and in every extra: npm's optional
dependencies (biome's binaries) count although npm installs only the one that fits, and
uv's markers are not evaluated. npm finds a dependency by name from the install path of
the package that needs it, as Node does; uv names it.

What this cannot tell apart, and so counts as the code's: npm moving a package the code
shares to another install path during a tool's upgrade, and a newer npm or uv rewriting
the lockfile's own fields. And a package only a tool brings is the tool's even when code
imports it without requiring it; review catches that import.

The module needs only the Python standard library.
"""

from __future__ import annotations

import json
import tomllib
from collections import defaultdict
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable, Collection, Iterable, Iterator

NODE_MODULES = "node_modules/"
# The fields of an npm package entry that list the packages npm installs for it.
NPM_NEEDS = ("dependencies", "optionalDependencies", "peerDependencies")
# The fields of an npm project entry that record what the project installs. Its peer
# ranges are its published interface, not a record of a tool's pin, so they stay the code's.
NPM_INSTALLS = ("dependencies", "devDependencies", "optionalDependencies")
# The sources of a uv package that is the project itself or a member of its workspace.
UV_LOCAL = ("editable", "virtual", "directory")


@dataclass(frozen=True)
class Graph:
    """A lockfile's packages: what each one needs, and what the project requires.

    `needs` maps each locked package to the packages it needs. `required` lists the
    packages that the project and its workspace members require, and `projects` the
    entries that are the project and those members.
    """

    needs: dict[str, list[str]]
    required: list[str]
    projects: list[str]


@dataclass(frozen=True)
class Format:
    """How one lockfile format is read: its parts, its packages, a tool's part and the rest."""

    example: str
    prefix: str
    load: Callable[[str], object]
    names: Callable[[str], bool]
    graph: Callable[[dict[str, object]], Graph]
    footprint: Callable[[dict[str, object], Graph, str, set[str]], object]
    rest: Callable[[dict[str, object], Graph, set[str], set[str]], object]


def _map(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _list(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def _named(value: object, names: Collection[str]) -> bool:
    return isinstance(value, dict) and value.get("name") in names


def _reach(needs: dict[str, list[str]], starts: Iterable[str], stop: Collection[str]) -> set[str]:
    """Return the packages reachable from `starts`, never entering one in `stop`."""
    seen: set[str] = set()
    pending = [s for s in starts if s not in stop]
    while pending:
        node = pending.pop()
        if node not in seen:
            seen.add(node)
            pending += [n for n in needs.get(node, []) if n not in stop and n not in seen]
    return seen


def _owned(graph: Graph, tools: Collection[str]) -> dict[str, set[str]]:
    """Return, for each tool, the packages it brings that the project's requirements do not."""
    shared = _reach(graph.needs, graph.required, tools)
    return {t: _reach(graph.needs, [t], set(tools) - {t}) - shared for t in tools}


def _requirements(value: object, names: Collection[str], at: str) -> Iterator[list[object]]:
    """Yield [where, element] for each list element, at any depth of `value`, naming one of
    `names`."""
    if isinstance(value, dict):
        for key, item in sorted(value.items()):
            yield from _requirements(item, names, f"{at}.{key}")
    elif isinstance(value, list):
        for item in value:
            if _named(item, names):
                yield [at, item]
            else:
                yield from _requirements(item, names, at)


def _drop_named(value: object, names: Collection[str]) -> object:
    """Return `value` without the list elements, at any depth, that name one of `names`."""
    if isinstance(value, dict):
        return {key: _drop_named(item, names) for key, item in value.items()}
    if isinstance(value, list):
        return [_drop_named(item, names) for item in value if not _named(item, names)]
    return value


# npm package-lock.json (lockfileVersion 2 or 3): `packages` maps each install path to
# its entry. The project and its workspace members are the entries outside node_modules.


def _npm_find(packages: dict[str, object], at: str, name: str) -> str | None:
    """Return the install path at which Node finds `name` for the package installed at `at`."""
    base = at
    while True:
        found = f"{base}/{NODE_MODULES}{name}" if base else f"{NODE_MODULES}{name}"
        if found in packages:
            return found
        if not base:
            return None
        cut = base.rfind(f"/{NODE_MODULES}")
        base = base[:cut] if cut >= 0 else ""


def _npm_needs(packages: dict[str, object], at: str, fields: Iterable[str]) -> list[str]:
    """Return the install paths of the packages that the entry at `at` lists in `fields`."""
    entry = _map(packages.get(at))
    names = [name for field in fields for name in _map(entry.get(field))]
    return [path for name in names if (path := _npm_find(packages, at, name)) is not None]


def _npm_graph(doc: dict[str, object]) -> Graph:
    packages = _map(doc.get("packages"))
    if "" not in packages:
        raise ValueError("it has no `packages` map holding the project (lockfileVersion 2+)")
    projects = [path for path in packages if NODE_MODULES not in path]
    requires = (*NPM_INSTALLS, "peerDependencies")
    return Graph(
        needs={p: _npm_needs(packages, p, NPM_NEEDS) for p in packages if NODE_MODULES in p},
        required=[n for p in projects for n in _npm_needs(packages, p, requires)],
        projects=projects,
    )


def _npm_names(path: str) -> bool:
    """Say whether `path` is the install path of a package at the top of node_modules."""
    name = path.removeprefix(NODE_MODULES)
    return name != path and bool(name) and NODE_MODULES not in name


def _npm_pins(packages: dict[str, object], projects: Iterable[str], name: str) -> list[object]:
    """Return [project, field, range] for each install map of a project that requires `name`."""
    pins: list[object] = []
    for project in projects:
        for field in NPM_INSTALLS:
            installs = _map(_map(packages[project]).get(field))
            if name in installs:
                pins.append([project, field, installs[name]])
    return pins


def _npm_footprint(doc: dict[str, object], graph: Graph, tool: str, own: set[str]) -> object:
    packages = _map(doc.get("packages"))
    pins = _npm_pins(packages, graph.projects, tool.removeprefix(NODE_MODULES))
    return {"packages": {path: packages[path] for path in sorted(own)}, "pins": pins}


def _npm_rest(doc: dict[str, object], graph: Graph, owned: set[str], tools: set[str]) -> object:
    packages = _map(doc.get("packages"))
    names = {t.removeprefix(NODE_MODULES) for t in tools}
    kept = {path: entry for path, entry in packages.items() if path not in owned}
    for project in graph.projects:
        entry = _map(packages[project])
        installs = {f: _without_keys(entry[f], names) for f in NPM_INSTALLS if f in entry}
        kept[project] = {**entry, **installs}
    return {**doc, "packages": kept}


def _without_keys(value: object, names: Collection[str]) -> object:
    return {key: item for key, item in _map(value).items() if key not in names}


# uv.lock: `package` lists each package's entry, more than one for a name locked at
# several versions. The project and its workspace members have a local source.


def _uv_entries(doc: dict[str, object]) -> dict[str, list[object]]:
    entries: dict[str, list[object]] = defaultdict(list)
    for entry in _list(doc.get("package")):
        name = _map(entry).get("name")
        if isinstance(name, str):
            entries[name].append(entry)
    return entries


def _uv_local(entry: object) -> bool:
    source = _map(_map(entry).get("source"))
    return any(key in source for key in UV_LOCAL)


def _uv_needs(entry: object, *, project: bool) -> list[str]:
    """Return what `entry` needs: its dependencies, every extra's and, for a project, every
    group's."""
    fields = _map(entry)
    lists = [fields.get("dependencies"), *_map(fields.get("optional-dependencies")).values()]
    if project:
        lists += _map(fields.get("dev-dependencies")).values()
    found = [_map(d).get("name") for items in lists for d in _list(items)]
    return [name for name in found if isinstance(name, str)]


def _uv_manifest(value: object) -> list[str]:
    """Return every name the manifest requires: each requirement's name, and each member."""
    name = _map(value).get("name")
    if isinstance(name, str):
        return [name]
    if isinstance(value, list):
        return [
            n for item in value for n in ([item] if isinstance(item, str) else _uv_manifest(item))
        ]
    return [n for item in _map(value).values() for n in _uv_manifest(item)]


def _uv_graph(doc: dict[str, object]) -> Graph:
    entries = _uv_entries(doc)
    if not entries:
        raise ValueError("it has no [[package]] entries")
    projects = sorted(n for n, versions in entries.items() if any(map(_uv_local, versions)))
    needs = {
        n: [d for e in versions for d in _uv_needs(e, project=n in projects)]
        for n, versions in entries.items()
    }
    required = [d for p in projects for d in needs[p]] + _uv_manifest(doc.get("manifest"))
    return Graph(needs=needs, required=required, projects=projects)


def _uv_names(name: str) -> bool:
    return bool(name) and "/" not in name and "." not in name


def _uv_footprint(doc: dict[str, object], graph: Graph, tool: str, own: set[str]) -> object:
    entries = _uv_entries(doc)
    pins = [
        pin
        for project in graph.projects
        for entry in entries[project]
        for pin in _requirements(entry, [tool], project)
    ]
    pins += _requirements(doc.get("manifest"), [tool], "manifest")
    return {"packages": {name: entries[name] for name in sorted(own)}, "pins": pins}


def _uv_rest(doc: dict[str, object], graph: Graph, owned: set[str], tools: set[str]) -> object:
    kept = [
        _drop_named(entry, tools) if _map(entry).get("name") in graph.projects else entry
        for entry in _list(doc.get("package"))
        if _map(entry).get("name") not in owned
    ]
    rest = {**doc, "package": kept}
    if "manifest" in doc:
        rest["manifest"] = _drop_named(doc["manifest"], tools)
    return rest


FORMATS = {
    "package-lock.json": Format(
        example="packages.node_modules/NAME",
        prefix="packages.",
        load=json.loads,
        names=_npm_names,
        graph=_npm_graph,
        footprint=_npm_footprint,
        rest=_npm_rest,
    ),
    "uv.lock": Format(
        example="package.NAME",
        prefix="package.",
        load=tomllib.loads,
        names=_uv_names,
        graph=_uv_graph,
        footprint=_uv_footprint,
        rest=_uv_rest,
    ),
}


def is_lockfile(path: str) -> bool:
    """Say whether `path` is a lockfile whose tool parts this module reads."""
    return PurePosixPath(path).name in FORMATS


def _format(path: str) -> Format:
    found = FORMATS.get(PurePosixPath(path).name)
    if found is None:
        raise ValueError(f"{path} is not a lockfile whose parts name a package")
    return found


def tool_name(path: str, part: str) -> str:
    """Return the package that `part` of the lockfile `path` names, or refuse it.

    The part is the format's prefix and the package: an npm install path at the top of
    node_modules, or a uv package name. Only that prefix is split off, so a name with a
    dot in it (`lodash.merge`) is one package.
    """
    fmt = _format(path)
    tool = part.removeprefix(fmt.prefix)
    if tool == part or not fmt.names(tool):
        raise ValueError(f"names no package: a part of {PurePosixPath(path).name} is {fmt.example}")
    return tool


def split(path: str, text: str, parts: Collection[str]) -> tuple[dict[str, object | None], object]:
    """Return what each of `parts` is in the lockfile `path`, whose text is `text`, and the rest.

    A part whose package is not locked is None. The rest is the lockfile without any
    part's package, the packages only the tools bring, or the entries that pin them.
    """
    fmt = _format(path)
    tools = {part: tool_name(path, part) for part in parts}
    doc = fmt.load(text)
    if not isinstance(doc, dict):
        raise ValueError(f"{path} does not hold a table")
    graph = fmt.graph(doc)
    present = {tool for tool in tools.values() if tool in graph.needs}
    owned = _owned(graph, present)
    found = {
        part: fmt.footprint(doc, graph, tool, owned[tool]) if tool in present else None
        for part, tool in tools.items()
    }
    every = {package for own in owned.values() for package in own}
    return found, fmt.rest(doc, graph, every, set(tools.values()))
