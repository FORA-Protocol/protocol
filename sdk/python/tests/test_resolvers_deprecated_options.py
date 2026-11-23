"""The deprecated ``scheme`` arguments accept only https (mirror of
sdk/go/resolvers/deprecated_options_test.go).

Anything else is refused with the reader's own error before a request reaches the
client, injected or not, so no value of them reaches a plaintext peer. The offer
directory fetch's ``scheme`` and ``port`` are pinned in
test_resolvers_wba_offer_directory_fetch.py.
"""

from __future__ import annotations

import warnings
from typing import TYPE_CHECKING, Any

import httpx
import pytest

from fora_sdk.resolvers import (
    WellKnownEndpointResolver,
    WellKnownRequirementsReader,
    create_wba_offer_directory_fetch,
    read_manifest,
    read_wba_directory,
)
from fora_sdk.resolvers._ssrf import SsrfError
from fora_sdk.resolvers.errors import DirectoryUnavailableError

if TYPE_CHECKING:
    from collections.abc import Callable


def _faces(client: httpx.Client, scheme: str) -> dict[str, Callable[[], Any]]:
    return {
        "read_manifest": lambda: read_manifest("exchange.example", scheme=scheme, http=client),
        "read_wba_directory": lambda: read_wba_directory(
            "exchange.example", scheme=scheme, http=client
        ),
        "endpoint": lambda: WellKnownEndpointResolver(scheme=scheme, http=client).resolve_endpoint(
            "exchange.example"
        ),
        "requirements": lambda: WellKnownRequirementsReader(
            scheme=scheme, http=client
        ).resolve_registration_requirements("exchange.example"),
    }


@pytest.mark.parametrize("scheme", ["http", "ftp", "HTTP"])
def test_a_scheme_other_than_https_warns_and_is_refused_before_dialling(scheme: str) -> None:
    dialled: list[str] = []

    def record(request: httpx.Request) -> httpx.Response:
        dialled.append(str(request.url))
        return httpx.Response(404)

    with httpx.Client(transport=httpx.MockTransport(record)) as client:
        for name, call in _faces(client, scheme).items():
            with (
                pytest.warns(DeprecationWarning, match="deprecated, removed in 2.0"),
                pytest.raises(DirectoryUnavailableError) as caught,
            ):
                call()
            assert isinstance(caught.value.__cause__, SsrfError), name
    assert dialled == [], "a refused scheme must reach no client"


def test_https_is_still_accepted_with_a_warning() -> None:
    dialled: list[str] = []

    def record(request: httpx.Request) -> httpx.Response:
        dialled.append(str(request.url))
        return httpx.Response(404)

    with (
        httpx.Client(transport=httpx.MockTransport(record)) as client,
        pytest.warns(DeprecationWarning, match="deprecated, removed in 2.0"),
        pytest.raises(DirectoryUnavailableError),
    ):
        read_manifest("exchange.example", scheme="https", http=client)
    assert dialled == ["https://exchange.example/.well-known/fora.json"]


def test_each_argument_passed_with_its_default_value_still_warns() -> None:
    """A caller that passes the default explicitly is broken by the removal too, so the
    warning depends on whether the argument was passed, not on its value."""
    with pytest.warns(DeprecationWarning) as record:
        WellKnownEndpointResolver(scheme="https")
        WellKnownRequirementsReader(scheme="https")
        create_wba_offer_directory_fetch(scheme="", port="")
        with (
            httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(404))) as client,
            pytest.raises(DirectoryUnavailableError),
        ):
            read_manifest("exchange.example", scheme="https", http=client)
    messages = [str(w.message) for w in record]
    assert messages == [
        "WellKnownEndpointResolver(scheme=...) is deprecated, removed in 2.0",
        "WellKnownRequirementsReader(scheme=...) is deprecated, removed in 2.0",
        "create_wba_offer_directory_fetch(scheme=...) is deprecated, removed in 2.0",
        "create_wba_offer_directory_fetch(port=...) is deprecated, removed in 2.0",
        "read_manifest(scheme=...) is deprecated, removed in 2.0",
    ]


def test_omitting_the_deprecated_arguments_warns_nothing() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        WellKnownEndpointResolver()
        WellKnownRequirementsReader()
        create_wba_offer_directory_fetch()


def test_the_warning_names_the_line_that_passed_the_argument() -> None:
    with pytest.warns(DeprecationWarning) as record:
        WellKnownEndpointResolver(scheme="https")
        create_wba_offer_directory_fetch(port="443")
        with pytest.raises(ValueError):
            read_wba_directory("not a host", scheme="https")
    assert [w.filename for w in record] == [__file__, __file__, __file__]
