"""Every README snippet outside the executed example, checked against the real API.

``test_readme_agent_example.py`` extracts ONE block — the one behind the
``fora:agent-example`` anchor — and runs it. That leaves the L1 sections below it
unguarded, and two of those snippets called functions with keywords the functions do
not take: ``sign_request(..., seed=...)`` where the parameter is ``signer_seed`` and
three required arguments were missing, and ``verify_request_server(..., replay=...)``
where the parameter is ``replay_store``. Both raise ``TypeError`` on the first line a
reader copies.

Those snippets cannot be executed. They are deliberate fragments: ``url``, ``body``,
``resolver`` and ``replay_store`` stand for values the reader supplies, and giving them
bodies would turn a three-line illustration into a program. So this BINDS instead of
running. For every call to a name the package exports, it asks
``inspect.signature(...).bind`` whether that argument list would be accepted at all.

What that catches: a renamed parameter, a removed one, a newly required one, a changed
arity. What it does NOT catch: a value of the wrong TYPE under a correct name. The
original ``now=lambda: int(time.time())`` passed a callable where an ``int`` is wanted,
and binding cannot see it. That gap is why the agent example is EXECUTED rather than
bound, and why the executed block is the one a reader is pointed at for a full program.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

import fora_sdk

_README = Path(__file__).resolve().parents[1] / "README.md"
_FENCE = "```"
_PYTHON = "```python"

#: The executed block is longer than any illustration and is covered by its own module.
_EXECUTED_BLOCK_MIN_LINES = 30


def _python_snippets() -> list[tuple[int, str]]:
    """Every ```python block in the README except the executed agent example.

    Keyed by the line the fence opens on, so a failure names a place in the file.
    """
    lines = _README.read_text(encoding="utf-8").split("\n")
    out: list[tuple[int, str]] = []
    body: list[str] = []
    inside = False
    lang = ""
    start = 0
    for number, line in enumerate(lines, 1):
        if line.startswith(_FENCE) and not inside:
            inside, lang, body, start = True, line.strip(), [], number
            continue
        if line.startswith(_FENCE) and inside:
            inside = False
            if lang == _PYTHON and len(body) < _EXECUTED_BLOCK_MIN_LINES:
                out.append((start, "\n".join(body)))
            continue
        if inside:
            body.append(line)
    return out


def _calls(source: str) -> list[ast.Call]:
    return [n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.Call)]


def test_there_are_snippets_to_check() -> None:
    """A README that stopped carrying illustrations would make this suite vacuous."""
    assert len(_python_snippets()) >= 4


@pytest.mark.parametrize("line_and_source", _python_snippets(), ids=lambda p: f"line-{p[0]}")
def test_the_snippet_parses(line_and_source: tuple[int, str]) -> None:
    """A fragment must at least be Python, or nothing below can look at it."""
    line, source = line_and_source
    ast.parse(source)  # raises SyntaxError, naming the offending line
    assert line > 0


@pytest.mark.parametrize("line_and_source", _python_snippets(), ids=lambda p: f"line-{p[0]}")
def test_every_call_would_bind_against_the_real_signature(
    line_and_source: tuple[int, str],
) -> None:
    """Each call to an exported name is accepted by the function it names.

    Only calls to names the package actually exports are checked. A snippet also calls
    things the reader supplies (``resolve``, a transport, a store); those resolve to
    nothing here and are skipped rather than guessed at.

    ``bind`` rather than ``bind_partial``, because these snippets show WHOLE calls. A
    partial bind would accept ``sign_request(method=..., url=..., body=...)`` and miss
    that the reader is three required arguments short of a call that runs.
    """
    line, source = line_and_source
    problems: list[str] = []
    for call in _calls(source):
        if not isinstance(call.func, ast.Name):
            continue
        function = getattr(fora_sdk, call.func.id, None)
        if function is None or not callable(function):
            continue
        keywords = {kw.arg: None for kw in call.keywords if kw.arg is not None}
        try:
            inspect.signature(function).bind(*[None] * len(call.args), **keywords)
        except TypeError as exc:
            problems.append(f"{call.func.id}(...): {exc}")

    assert not problems, (
        f"README.md line {line}: the snippet calls the SDK with arguments it does not "
        f"take — " + "; ".join(problems)
    )
