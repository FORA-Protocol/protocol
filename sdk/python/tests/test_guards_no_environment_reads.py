"""Structural guard: the Python SDK's library code reads no environment variable.

An SDK that reads an environment variable lets whoever controls the process environment
change what the library does, and the variables this repository inherited (SKIP_SSRF and
ALLOW_INSECURE) did exactly that to the SSRF guard. AGENTS.md forbids any switch a test
could use to relax a check; a caller that needs different behavior passes its own client.

The rule, the same in all three SDKs: every source file under the SDK's root is
parsed, except a path the exemption table names with its reason, and a finding is
any occurrence in code of a name in the language's set of environment readers: as an
identifier, as a member of any receiver, as an imported name, or as a string literal
whose whole value is the name. The receiver does not matter, so a reader reached
through an alias, a reflective lookup or a string key is refused like a direct call,
and so is an unrelated name that happens to match; rename it. Comments are not code.
A name assembled at run time, for example by joining strings, is not caught. An
exemption that matches no file fails the guard.

In Python the SDK's root is the package directory ``fora_sdk`` (the suite lives outside
it), the files are read with :mod:`ast`, and the set is ``environ``, ``environb``,
``getenv``, ``getenvb``, ``putenv``, ``unsetenv``, ``expandvars``, ``expanduser``,
``gettempdir`` and ``gettempdirb``: the members of ``os``, ``os.path`` and ``tempfile``
that read or write the environment, including the ones that read HOME or TMPDIR. A name
counts as an identifier, an attribute, a name in an import, a definition's name, a
parameter or a keyword argument. The Go and TypeScript SDKs hold the same rule with their
own parsers.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1] / "fora_sdk"
_READERS = frozenset(
    {
        "environ",
        "environb",
        "getenv",
        "getenvb",
        "putenv",
        "unsetenv",
        "expandvars",
        "expanduser",
        "gettempdir",
        "gettempdirb",
    }
)

#: The guard's config: each path under the SDK's root it does not read, as a regular
#: expression over the slash-separated relative path, and the reason. Nothing in the
#: package is exempt.
EXEMPTIONS: dict[str, str] = {}


def _names(node: ast.AST) -> list[str]:
    """The names ``node`` writes in code, by the forms the rule counts."""
    match node:
        case ast.Name(id=name) | ast.Attribute(attr=name) | ast.arg(arg=name):
            return [name]
        case ast.alias(name=name, asname=asname):
            return [*name.split("."), *([asname] if asname else [])]
        case ast.FunctionDef(name=name) | ast.AsyncFunctionDef(name=name) | ast.ClassDef(name=name):
            return [name]
        case ast.keyword(arg=str(name)):
            return [name]
        case ast.Constant(value=str(value)):
            return [value]
    return []


def environment_readers(source: str) -> list[str]:
    """Each environment reader ``source`` names, as ``line:column name``."""
    found: list[tuple[int, int, str]] = []
    for node in ast.walk(ast.parse(source)):
        hits = [name for name in _names(node) if name in _READERS]
        found += [(getattr(node, "lineno", 0), getattr(node, "col_offset", 0), h) for h in hits]
    return [f"{line}:{col} {name}" for line, col, name in sorted(found)]


def _exempt(path: str) -> str | None:
    """The exemption pattern that covers ``path``, or None."""
    return next((p for p in EXEMPTIONS if re.search(p, path)), None)


def test_no_library_module_reads_the_environment() -> None:
    sources = sorted(_ROOT.rglob("*.py"))
    assert sources, f"no source file under {_ROOT}; the guard would check nothing"
    used: set[str] = set()
    offenders: dict[str, list[str]] = {}
    for path in sources:
        relative = path.relative_to(_ROOT).as_posix()
        if (pattern := _exempt(relative)) is not None:
            used.add(pattern)
        elif reads := environment_readers(path.read_text(encoding="utf-8")):
            offenders[relative] = reads
    assert offenders == {}, "pass the value in through the API instead"
    assert set(EXEMPTIONS) - used == set(), "an exemption matches no file; remove it"


@pytest.mark.parametrize(
    ("source", "count"),
    [
        ("import os\nX = os.environ['X']\n", 1),
        ("import os\nX = os.getenv('X'), os.getenvb(b'X'), os.environb\n", 3),
        ("import os\nos.putenv('X', ''); os.unsetenv('X')\n", 2),
        ("import os\nX = os.path.expandvars('$X'), os.path.expanduser('~')\n", 2),
        ("import tempfile\nX = tempfile.gettempdir(), tempfile.gettempdirb()\n", 2),
        ("import os as o\nX = o.environ\n", 1),
        ("import posix\nX = posix.environ\n", 1),
        ("from os import environ\n", 1),
        ("from os import path, getenv as g\n", 1),
        ("from os import (\n    environ,\n)\n", 1),
        ("from os import *\nX = environ\n", 1),
        ("import os\nX = getattr(os, 'environ')\n", 1),
        ("import os\nX = os.__dict__['environ']\n", 1),
        ("import importlib\nX = importlib.import_module('os').environ\n", 1),
        ("X = __import__('os').getenv('X')\n", 1),
        ("import os\nread = os.getenv\n", 1),
        ("def getenv():\n    return 1\n", 1),
        ("def f(environ):\n    return environ\n", 2),
        ("f(environ=1)\n", 1),
        ("X = f'environ'\n", 1),
        ("import os\nX = 'a // b # c'; Y = os.environ\n", 1),
    ],
)
def test_the_guard_catches_every_form(source: str, count: int) -> None:
    assert len(environment_readers(source)) == count, environment_readers(source)


@pytest.mark.parametrize(
    "source",
    [
        "# os.environ is not read\nimport os\n",
        "import os\nX = 'os.environ and os.getenv'\n",
        "import os\nos.environment_name = 1\n",
        "import os\nX = getattr(os, 'env' + 'iron')\n",
    ],
)
def test_a_mention_or_an_assembled_name_is_not_caught(source: str) -> None:
    assert environment_readers(source) == []
