"""The README's agent example, extracted from README.md and RUN.

An example whose only guarantee is that someone read it carefully is how a set of docs
ends up describing an API that no longer exists. This test takes the exact block the
README ships, executes it against a real in-process Exchange, and fails if any name in
it stops resolving — a renamed verb, a renamed ClientConfig field, a moved module, a
changed wire field.

Executing is what makes that true. Resolving the block's symbols statically would catch
the imports and nothing else: not ``client.discover``, not the attributes of the objects
that come back, and not a keyword-argument rename on a dataclass, which fails only when
it is called.

The origin listens on 127.0.0.1 and speaks http, which the SDK's guarded transports and
its scheme gate both refuse by default. The two documented environment flags are what
open that, and they are set here rather than injecting an unguarded client, for two
reasons. The scheme gate sits ABOVE the transport on the offer-derived legs and reads
ALLOW_INSECURE at call time, so an injected client would not reach the origin anyway.
And the README must show the production wiring: an injected escape hatch in the one
example a reader copies is the wrong thing to teach.

Both flags are process-global, so this module must not be run under in-process test
parallelism. pytest-xdist forks processes, so it is fine today.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from exchange_harness import fake_exchange

if TYPE_CHECKING:
    from collections.abc import Iterator

    from exchange_harness import FakeExchange

_README = Path(__file__).resolve().parents[1] / "README.md"
_MARKER = "<!-- fora:agent-example"
_FACES_OPEN = "<!-- fora:l1-faces"
_FACES_CLOSE = "<!-- /fora:l1-faces -->"
_FENCE = "```python"

#: The agent key the example signs with. Any 32 bytes; fixed so a failure reproduces.
_SEED = bytes(range(32))

#: A URI the example asks for. Reserved by RFC 6761, so it can never resolve to a real
#: party even if something in the chain tried to dial it.
_URI = "https://publisher.example/article"

#: The WBA directory the example says it publishes its key in. The fake Exchange is
#: told to trust exactly this origin, so it can resolve the keyid off the covered
#: Signature-Agent header the way a real one does. Kept in step with the README by
#: test_the_readme_names_the_directory_the_exchange_resolves_against below.
_AGENT_DIRECTORY = "https://agent.example"


def _example_source() -> str:
    """The README's marked python block, verbatim.

    Anchored on an HTML comment rather than a heading or an ordinal. A heading couples
    the test to prose that will legitimately be reworded; "the third python block" breaks
    the moment an install snippet is inserted above it, and breaks by silently testing a
    different block, which is worse than not testing at all. The comment renders as
    nothing, on PyPI included, and the single-anchor assertion turns a copied block into
    a loud failure.
    """
    lines = _README.read_text(encoding="utf-8").splitlines()
    marks = [i for i, line in enumerate(lines) if line.startswith(_MARKER)]
    assert len(marks) == 1, (
        f"expected exactly one {_MARKER!r} anchor in README.md, found {len(marks)}"
    )

    opened = marks[0] + 1
    assert lines[opened].strip() == _FENCE, (
        f"the line after the {_MARKER!r} anchor must open a {_FENCE!r} fence, "
        f"found {lines[opened]!r}"
    )
    closed = next(i for i in range(opened + 1, len(lines)) if lines[i].strip() == "```")
    return "\n".join(lines[opened + 1 : closed]) + "\n"


def test_the_example_is_shaped_so_that_exec_runs_nothing() -> None:
    """Module level holds only imports, constants, defs and the ``__main__`` guard.

    This is what makes "exec does not run the tail" a CHECKED property rather than an
    assumption. Setting ``__name__`` keeps the guard inert, but a future edit that drops
    a bare ``buy_and_fetch(...)`` at module level would have the suite quietly dial out
    at import time instead of failing.
    """
    tree = ast.parse(_example_source())
    allowed = (ast.Import, ast.ImportFrom, ast.Assign, ast.AnnAssign, ast.FunctionDef, ast.If)
    for node in tree.body:
        assert isinstance(node, allowed), f"module-level {type(node).__name__} in the example"
        if isinstance(node, ast.If):
            # ast.unparse normalizes string quoting, so compare against its spelling.
            assert ast.unparse(node.test) == "__name__ == '__main__'", (
                "the only module-level `if` may be the __main__ guard"
            )

    functions = {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}
    assert functions == {"buy_and_fetch"}, f"expected one entry point, found {functions}"

    entry = next(n for n in tree.body if isinstance(n, ast.FunctionDef))
    assert [a.arg for a in entry.args.kwonlyargs] == ["exchange", "uri", "seed"]
    assert not entry.args.args, "the example's entry point takes keyword arguments only"


def _load(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Execute the README block and hand back its namespace."""
    monkeypatch.setenv("FORA_WELLKNOWN_SCHEME", "http")
    monkeypatch.setenv("ALLOW_INSECURE", "true")
    monkeypatch.setenv("SKIP_SSRF", "true")
    namespace: dict[str, Any] = {"__name__": "fora_readme_example"}
    source = _example_source()
    compiled = compile(source, "sdk/python/README.md#fora:agent-example", "exec")
    exec(compiled, namespace)  # noqa: S102 — running the README IS the assertion
    return namespace


@pytest.fixture
def exchange() -> Iterator[FakeExchange]:
    ex = fake_exchange(agent_seed=_SEED, agent_directory=_AGENT_DIRECTORY)
    yield ex
    ex.close()


def test_the_readme_example_buys_and_fetches(
    exchange: FakeExchange, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The block runs end to end and returns the licensed bytes.

    Every leg is real HTTP over a socket: the manifest read that discovers the endpoint,
    the Web Bot Auth directory the offer key comes from, the three RPCs, and the delivery
    fetch whose proof of possession the edge verifies before serving anything.
    """
    namespace = _load(monkeypatch)

    body = namespace["buy_and_fetch"](exchange=exchange.domain, uri=_URI, seed=_SEED)

    assert body == exchange.content
    assert [path for path, _ in exchange.seen] == [
        "/fora.v1.ExchangeService/DiscoverResources",
        "/fora.v1.ExchangeService/ExecuteTransaction",
        "/fora.v1.ExchangeService/ReportUsage",
    ], "the example did not drive all three verbs, in order"

    report = exchange.seen[-1][1]
    assert report["exchange"] == exchange.domain
    assert report["transaction_id"] == "tx-1"
    assert report["usage"]["consumed_quantity"] == len(exchange.content)


@pytest.mark.parametrize(
    ("flag", "expected_reason"),
    [
        ("tamper_offer", "offer signature invalid"),
        ("serve_directory", "no offer-signing key"),
    ],
)
def test_the_example_fails_closed(
    monkeypatch: pytest.MonkeyPatch, flag: str, expected_reason: str
) -> None:
    """A success-only test would pass against a client that verified nothing.

    Two failures, chosen because they fail closed for DIFFERENT reasons and the example
    must distinguish them. ``tamper_offer`` corrupts the offer signature, so the key
    resolves and the signature does not check out. ``serve_directory=False`` makes the
    directory a 404, so no key resolves at all and the offer is refused before its
    signature is even considered. Asserting the two reasons differ is what proves the key
    map was consulted rather than the check skipped.

    Both surface through the example's own error branch, so this also exercises the
    handling the README documents rather than only the SDK underneath it.
    """
    ex = fake_exchange(
        agent_seed=_SEED, agent_directory=_AGENT_DIRECTORY, **{flag: flag != "serve_directory"}
    )
    try:
        namespace = _load(monkeypatch)
        with pytest.raises(RuntimeError) as excinfo:
            namespace["buy_and_fetch"](exchange=ex.domain, uri=_URI, seed=_SEED)
    finally:
        ex.close()

    message = str(excinfo.value)
    assert f"no verifiable offer for {_URI}" in message
    assert expected_reason in message, f"expected {expected_reason!r} in {message!r}"
    assert [path for path, _ in ex.seen] == ["/fora.v1.ExchangeService/DiscoverResources"], (
        "nothing may be purchased after an offer fails to verify"
    )


def test_every_symbol_the_example_imports_is_public() -> None:
    """The example imports only names the package actually exports.

    An example that reaches into a private module teaches a reader to depend on something
    with no stability promise. This reads the block's own import statements rather than a
    hand-kept list, so a newly added import is checked the moment it appears.
    """
    tree = ast.parse(_example_source())
    private = [
        f"{node.module}.{alias.name}"
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("fora_sdk")
        for alias in node.names
        if alias.name.startswith("_") or re.search(r"\._", node.module or "")
    ]
    assert not private, f"the README example reaches into private API: {private}"


# --------------------------------------------------------------------------- #
# The README's PROSE, not just its code block
# --------------------------------------------------------------------------- #
_BACKTICKED = re.compile(r"`([a-z_][a-z0-9_]*)`")


def _marked_faces_source() -> str:
    """The README text between the l1-faces markers."""
    text = _README.read_text(encoding="utf-8")
    opens = text.count(_FACES_OPEN)
    assert opens == 1, f"expected exactly one {_FACES_OPEN!r} marker, found {opens}"
    start = text.index(_FACES_OPEN)
    end = text.index(_FACES_CLOSE, start)
    return text[start:end]


def test_every_l1_face_the_readme_names_in_prose_exists() -> None:
    """A name the README lists as an L1 face must be one.

    The code block is executed, so a rename there fails loudly. The prose was not
    checked at all, and it drifted: the L1 inventory listed `redact_url`, which is a Go
    face (`helpers.RedactURL`) with no Python counterpart anywhere. Nothing caught it,
    because every other check in this suite reads the executable block.

    The check is scoped to a marked region rather than the whole file, because most
    backticks in this README quote wire field names, environment variables and JSON
    keys rather than Python symbols. Widening the markers widens the guard; the answer
    to a name that fails here is to ship it or to stop claiming it, never to move it
    outside the markers.
    """
    import fora_sdk

    named = sorted(set(_BACKTICKED.findall(_marked_faces_source())))
    assert named, "the l1-faces region names nothing — the markers or the regex moved"

    missing = [n for n in named if not hasattr(fora_sdk, n)]
    assert not missing, (
        f"the README lists {missing} as L1 faces, but they are not on the public "
        f"fora_sdk surface. Either export them or remove the claim."
    )


def test_the_readme_names_the_directory_the_exchange_resolves_against(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The README's AGENT_DIRECTORY is the origin the fake Exchange trusts.

    The two are written in different files, and the suite is only meaningful while they
    agree: if the README moved to another origin and this module did not, every RPC
    would be refused and the failure would look like a broken harness rather than a
    README that changed.
    """
    namespace = _load(monkeypatch)

    assert namespace["AGENT_DIRECTORY"] == _AGENT_DIRECTORY


def test_an_agent_that_names_no_directory_is_refused(
    exchange: FakeExchange, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Drop signature_agent and the first RPC fails, with nothing bought.

    This is the negative path for the whole identity step, and it is the failure a
    reader following the README used to walk into. Signature-Agent defaults to empty,
    the signature covers it either way, and an Exchange reading an empty value has no
    directory to fetch the caller's key from. The reference Exchange answers 401.

    Asserted through the README's own entry point with one constructor argument
    removed, rather than by driving the transport directly, so it fails if the README
    stops passing the argument at all.
    """
    namespace = _load(monkeypatch)
    transport = namespace["SigningTransport"]

    def unnamed(*, signer_seed: bytes, keyid: str, signature_agent: str = "") -> Any:
        # Ignore what the README passes: sign as an agent that published nothing.
        _ = signature_agent
        return transport(signer_seed=signer_seed, keyid=keyid)

    namespace["SigningTransport"] = unnamed

    with pytest.raises(Exception, match="unauthenticated|401"):
        namespace["buy_and_fetch"](exchange=exchange.domain, uri=_URI, seed=_SEED)

    assert exchange.seen == [], "nothing may be bought by a caller the Exchange cannot identify"
