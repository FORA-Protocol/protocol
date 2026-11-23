"""Structural guard: the Python SDK's library code reads no environment variable.

An SDK that reads an environment variable lets whoever controls the process environment
change what the library does, and the variables this repository inherited (SKIP_SSRF and
ALLOW_INSECURE) did exactly that to the SSRF guard. AGENTS.md forbids any switch a test
could use to relax a check; a caller that needs different behavior passes its own client.

Every module under ``fora_sdk`` is parsed with :mod:`ast`, and the guard fails on:

- an attribute ``environ``, ``environb``, ``getenv`` or ``getenvb`` of a name bound to the
  ``os``, ``posix`` or ``nt`` module, whatever the import calls it (``import os as o``
  included), read, called or not;
- ``from os import ...`` (or ``posix``, ``nt``) naming one of those four, in any spelling
  the grammar allows, parenthesised and aliased included, and ``from os import *``.

Comments and string literals are not code, so a mention there is not a read. The Go and
TypeScript SDKs hold the same rule with their own parsers.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_LIBRARY = Path(__file__).resolve().parents[1] / "fora_sdk"
_MODULES = {"os", "posix", "nt"}
_READS = {"environ", "environb", "getenv", "getenvb"}


def environment_reads(source: str) -> list[str]:
    """Each environment read in ``source``, as the spelling that names it."""
    tree = ast.parse(source)
    aliases: set[str] = set()
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for name in node.names:
                if name.name.split(".")[0] in _MODULES:
                    aliases.add(name.asname or name.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module in _MODULES:
            found += [
                f"from {node.module} import {n.name}"
                for n in node.names
                if n.name in _READS or n.name == "*"
            ]
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and node.attr in _READS
            and isinstance(node.value, ast.Name)
            and node.value.id in aliases
        ):
            found.append(f"{node.value.id}.{node.attr}")
    return found


def test_no_library_module_reads_the_environment() -> None:
    modules = sorted(_LIBRARY.rglob("*.py"))
    assert modules, f"no module under {_LIBRARY}; the guard would check nothing"
    offenders = {
        str(path.relative_to(_LIBRARY.parent)): reads
        for path in modules
        if (reads := environment_reads(path.read_text(encoding="utf-8")))
    }
    assert offenders == {}, "pass the value in through the API instead"


@pytest.mark.parametrize(
    ("source", "want"),
    [
        ("import os\nX = os.environ['X']\n", ["os.environ"]),
        ("import os\nX = os.getenv('X')\n", ["os.getenv"]),
        ("import os\nX = os.environb\n", ["os.environb"]),
        ("import os as o\nX = o.environ\n", ["o.environ"]),
        ("import os.path\nX = os.environ\n", ["os.environ"]),
        ("import posix\nX = posix.environ\n", ["posix.environ"]),
        ("from os import environ\n", ["from os import environ"]),
        ("from os import path, getenv as g\n", ["from os import getenv"]),
        ("from os import (\n    environ,\n)\n", ["from os import environ"]),
        ("from os import *\n", ["from os import *"]),
        ("import os\nX = 'a // b # c'; Y = os.environ\n", ["os.environ"]),
    ],
)
def test_the_guard_catches_every_form(source: str, want: list[str]) -> None:
    assert environment_reads(source) == want


@pytest.mark.parametrize(
    "source",
    [
        "# os.environ is not read\nimport os\n",
        "import os\nX = 'os.environ and os.getenv'\n",
        "import os\nos.environment_name = 1\n",
        "import path as os\nfrom os import path\n",
        "environ = {}\nX = environ.get('X')\n",
    ],
)
def test_a_mention_is_not_a_read(source: str) -> None:
    assert environment_reads(source) == []
