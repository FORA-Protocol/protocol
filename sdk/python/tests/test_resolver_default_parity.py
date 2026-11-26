"""Replays resolver-default-vectors.json: which transport each resolver face takes when the
caller injects none, and what that default does with each target.

The Go oracle (``sdk/go/resolvers/gen_resolver_default_vectors_test.go``) emits every row by
driving its own face against a real listener, so the outcomes are Go's observed behaviour,
not a table written by hand. Each row carries the scheme and host it dials, and the corpus
carries the license digest, so this replay keeps no copy of either. It drives the same face
through this SDK's public constructor against the same harness:

- one loopback origin (the shared harness's ``Origin``) that counts the TCP connections it
  accepts, so a refusal before the dial is observable as zero connections; a row with an
  empty host dials it;
- the row's own host for the targets that have no listener.

A refusal is classified by the oracle's own rule (``classifyRefusal``), so a face refused for
another reason does not pass. Nothing in the SDK is replaced: the transport under test is the
face's own default, except in a control row, which injects the harness's plain
``loopback_client()``.

The rule the rows pin is that a resolver's default follows its URL's provenance: a fixed,
operator-chosen address takes the plain client, a host another party named takes the guarded
one. Changing a row obliges a check of the ``License.uri`` SSRF guards in
``proto/fora/v1/fora.proto`` and Licensing Terms (``/protocol/licensing-terms/``), which say
what a consumer must apply before it fetches a URL another party named.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import pytest
from harness.corpus import GO_RESOLVERS_TESTDATA, load_json
from harness.loopback import loopback_client
from harness.origin import Origin
from wire.models import License

from fora_sdk.resolvers import (
    WBAKeyResolver,
    WellKnownEndpointResolver,
    WellKnownKeyResolver,
    WellKnownRequirementsReader,
    create_wba_offer_directory_fetch,
    read_license_document,
    read_manifest,
    read_revocation_list,
    read_wba_directory,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    import httpx

_CORPUS = load_json(GO_RESOLVERS_TESTDATA / "resolver-default-vectors.json")
_VECTORS = _CORPUS["resolver_defaults"]


def _offer_directory(scheme: str, host: str, http: httpx.Client | None = None) -> None:
    fetch = create_wba_offer_directory_fetch(scheme=scheme, http=http)

    async def read() -> None:
        await fetch(host)

    asyncio.run(read())


def _license(base: str) -> None:
    read_license_document(License(uri=f"{base}/license", uri_digest=_CORPUS["license_digest"]))


# Each face's DEFAULT construction, as a caller injecting nothing: (scheme, host, base),
# where base is scheme://host.
_FACES: dict[str, Callable[[str, str, str], object]] = {
    "wellknown_key_resolver": lambda _s, _h, base: WellKnownKeyResolver(
        f"{base}/.well-known/fora.json"
    ).resolve("ex.v1"),
    "wellknown_endpoint_resolver": lambda s, h, _b: WellKnownEndpointResolver(
        scheme=s
    ).resolve_endpoint(h),
    "registration_requirements_reader": lambda s, h, _b: WellKnownRequirementsReader(
        scheme=s
    ).resolve_registration_requirements(h),
    "manifest_reader": lambda s, h, _b: read_manifest(h, scheme=s),
    "wba_directory_reader": lambda s, h, _b: read_wba_directory(h, scheme=s),
    "revocation_list_reader": lambda _s, _h, base: read_revocation_list(f"{base}/revocation"),
    "license_document_reader": lambda _s, _h, base: _license(base),
    "wba_key_resolver": lambda _s, _h, base: WBAKeyResolver().resolve("ex.v1", base),
    "offer_directory_fetch": lambda s, h, _b: _offer_directory(s, h),
}


def _exercise(face: str, scheme: str, host: str, http: httpx.Client | None) -> None:
    """Run one face against ``scheme://host`` as a caller would: with its own default
    client, or with ``http`` injected. Only the offer-directory fetch has a control row."""
    if http is None:
        _FACES[face](scheme, host, f"{scheme}://{host}")
    elif face == "offer_directory_fetch":
        _offer_directory(scheme, host, http)
    else:
        raise AssertionError(f"{face} takes no injected client in this replay")


def _classify(exc: BaseException | None) -> str:
    """Which check refused, by the Go oracle's ``classifyRefusal`` rule applied to the
    exception's message and the messages of its ``__cause__`` chain, as Go applies it to
    a wrapped error. Python words the scheme refusal "non-https scheme" where Go says
    "disallowed scheme", and both Python refusals say "refusing to dial", so the scheme
    phrase is checked first."""
    if exc is None:
        return "no error"
    messages: list[str] = []
    cur: BaseException | None = exc
    while cur is not None:
        messages.append(str(cur))
        cur = cur.__cause__
    text = ": ".join(messages)
    if "non-https scheme" in text and "SSRF guard" in text:
        return "refused_scheme"
    if "refusing to dial" in text and "SSRF guard" in text:
        return "refused_address"
    return f"other: {text}"


def _run(vector: dict[str, Any], host: str) -> BaseException | None:
    """The exception the face raised, or None when it returned."""
    try:
        if vector["transport"] == "plain":
            with loopback_client() as client:
                _exercise(vector["face"], vector["scheme"], host, client)
        else:
            _exercise(vector["face"], vector["scheme"], host, None)
    except Exception as exc:  # the refusal is classified, not handled
        return exc
    return None


@pytest.mark.parametrize("vector", _VECTORS, ids=[v["name"] for v in _VECTORS])
def test_resolver_default_matches_the_oracle(
    vector: dict[str, Any], ssrf_env: pytest.MonkeyPatch
) -> None:
    if vector["allow_insecure"]:
        ssrf_env.setenv("ALLOW_INSECURE", "1")

    if vector["host"]:
        got = _classify(_run(vector, vector["host"]))
    else:
        origin = Origin()
        try:
            exc = _run(vector, origin.host)
        finally:
            origin.close()
        # A face that contains its failures returns "no directory": with no connection
        # made, that is all its seam reports.
        if origin.connections() > 0:
            got = "reached"
        elif exc is None:
            got = "not_reached"
        else:
            got = _classify(exc)

    assert got == vector["outcome"], (
        f"{vector['name']}: this SDK's default transport gave {got!r}, the Go oracle "
        f"{vector['outcome']!r}. If the change is intended, change the oracle and check it "
        "against the License.uri SSRF guards in proto/fora/v1/fora.proto."
    )
