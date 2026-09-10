"""Cross-language fetcher-level host+port join parity (Python side).

The pure URL builder is already pinned by ``wba-url-vectors.json``, but that corpus
takes an ALREADY-JOINED host. The join that produces the host lives in each
language's directory fetcher, and it was hand-written three times: Go used
``net.JoinHostPort``, TypeScript interpolated without bracketing, and Python
bracketed only an unbracketed literal. The three disagreed on an IPv6 host, so one
exchange domain resolved to different URLs depending on the SDK.

``sdk/go/resolvers/testdata/wba-join-vectors.json`` is what ends that. It is emitted
by RUNNING the Go ``joinDirectoryHost`` oracle, and this module replays it. Each
vector is ``{label, domain, port, expected_host}``.

Asserted through ``create_wba_offer_directory_fetch``, never through the private
join helper. Two things are proved that way instead of one: the join agrees with Go,
AND the fetch really builds its URL from the shared ``wba_directory_url`` builder
rather than from a string of its own. The transport records the URL httpx actually
constructed, so the assertion is on a dialed request rather than on a return value.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import httpx
import pytest
from conftest import GO_RESOLVERS_TESTDATA, load_json

from fora_sdk.resolvers import create_wba_offer_directory_fetch, wba_directory_url

if TYPE_CHECKING:
    from collections.abc import Iterator

    from wire.models import WBAFile

    from fora_sdk.resolvers import DirectoryFetch


def _run(fetch: DirectoryFetch, domain: str) -> WBAFile | None:
    """Drive one fetch to completion.

    ``DirectoryFetch`` is declared as returning an ``Awaitable``, which
    ``asyncio.run`` does not accept; awaiting it inside a coroutine is what gives the
    call a type instead of an ignore comment.
    """

    async def go() -> WBAFile | None:
        return await fetch(domain)

    return asyncio.run(go())


_CORPUS = load_json(GO_RESOLVERS_TESTDATA / "wba-join-vectors.json")

# The corpus MUST cover exactly these behaviors (stated here as the contract so a
# thinner corpus fails this suite, not just the completeness gate):
#   - empty-port          : the domain passes through so the scheme default applies
#   - plain-domain        : an ordinary domain gains :port
#   - bare-ipv6           : an unbracketed IPv6 literal gains brackets before the port
#   - bracketed-ipv6      : an already-bracketed literal is bracketed AGAIN, as
#                           net.JoinHostPort does
#   - domain-with-port    : a domain already carrying a port is treated as a
#                           colon-bearing host and bracketed
#   - empty-port-bare-ipv6: an empty port wins over the colon rule
_REQUIRED_LABELS = frozenset(
    {
        "empty-port",
        "plain-domain",
        "bare-ipv6",
        "bracketed-ipv6",
        "domain-with-port",
        "empty-port-bare-ipv6",
    }
)


def test_wba_join_corpus_nonempty() -> None:
    assert len(_CORPUS["vectors"]) > 0


def test_wba_join_corpus_covers_required_behaviors() -> None:
    labels = {v["label"] for v in _CORPUS["vectors"]}
    missing = _REQUIRED_LABELS - labels
    assert not missing, f"corpus is missing required vectors: {sorted(missing)}"


class _Recorder:
    """Captures the URL of every request the client actually dialled."""

    def __init__(self) -> None:
        self.urls: list[str] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.urls.append(str(request.url))
        # An empty body is enough: the fetch's decode arm turns it into None, and
        # this module asserts on the URL rather than on the decoded directory.
        return httpx.Response(200, content=b"")


@pytest.fixture
def recorder() -> Iterator[tuple[_Recorder, httpx.Client]]:
    rec = _Recorder()
    client = httpx.Client(transport=httpx.MockTransport(rec.handle))
    yield rec, client
    client.close()


@pytest.mark.parametrize(
    "vec",
    _CORPUS["vectors"],
    ids=[v["label"] for v in _CORPUS["vectors"]],
)
def test_the_fetch_dials_the_host_the_go_oracle_joins(
    vec: dict[str, Any], recorder: tuple[_Recorder, httpx.Client]
) -> None:
    """The URL the fetch dials is the shared builder applied to Go's joined host.

    Three of the oracle's answers do not form a URL at all. ``net.JoinHostPort``
    brackets any colon-bearing host without checking for brackets it already has, so
    ``[::1]`` joins to ``[[::1]]:8443``; and an empty port leaves a bare IPv6 literal
    unbracketed, so ``::1`` stays ``::1``. Neither is a valid authority. The expected
    behavior there is that the fetch dials NOTHING and contains the failure as None —
    which is also the only coverage the ``httpx.InvalidURL`` arm of the failure
    contract has, so it is asserted here rather than assumed.

    Which branch a vector takes is decided by asking httpx whether the URL parses,
    not by a hand-kept list of labels, so a corpus change moves the expectation with
    it.
    """
    rec, client = recorder
    expected_url = wba_directory_url("https", vec["expected_host"])

    try:
        httpx.URL(expected_url)
    except httpx.InvalidURL:
        dialable = False
    else:
        dialable = True

    fetch = create_wba_offer_directory_fetch(http=client, scheme="https", port=vec["port"])
    result = _run(fetch, vec["domain"])

    if not dialable:
        assert rec.urls == [], (
            f"{vec['label']}: the Go oracle joins domain={vec['domain']!r} "
            f"port={vec['port']!r} to {vec['expected_host']!r}, which is not a valid "
            f"authority — the fetch must dial nothing, but it dialled {rec.urls}"
        )
        assert result is None, (
            f"{vec['label']}: an unformable URL must be contained as None, got {result!r}"
        )
        return

    assert rec.urls == [expected_url], (
        f"{vec['label']}: the fetch dialled {rec.urls} for domain={vec['domain']!r} "
        f"port={vec['port']!r}, but the Go oracle joins that to {vec['expected_host']!r}"
    )
