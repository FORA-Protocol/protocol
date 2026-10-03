"""The edge discovery headers: what a publisher's edge tells an unlicensed agent.

Python port of the sdk/go oracle (helpers/discoveryhint.go).

A publisher's edge answers a request for licensed content that carries no valid
signed delivery URL with 403. That answer carries up to two headers, specified
under "Edge discovery headers" in the fora.proto file header::

    X-Content-Rules: https://publisher.example/.well-known/fora.json
    X-FORA-Exchange: exchange.example

``X-Content-Rules`` points at the publisher's manifest, which is the authority on
the licensing terms and on which Exchanges sell the content. ``X-FORA-Exchange``
names one Exchange that sells it directly, so an agent can start discovery there
without reading the manifest first. The second is an optimisation over the first
and never a replacement for it.

:func:`parse_discovery_hint` reads the two headers off a response and checks each
value's shape. :func:`reconcile_discovery_hint` compares the hinted Exchange with
the Exchanges the manifest lists, once the agent has read it. Neither dials
anything: fetching the manifest, and resolving the Exchange's endpoint from the
Exchange's own manifest, are the resolvers' job. The header names an Exchange; it
never supplies the address to dial.

Pure string work, no IO. Pinned to the Go oracle by the shared corpus at
``sdk/go/helpers/testdata/discovery-hint-vectors.json``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from fora_sdk.hosts import check_audience, is_bare_domain
from fora_sdk.wire import ContentRulesHeader, ExchangeHeader, WellKnownPath

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping

#: What :func:`parse_discovery_hint` found in one discovery header. The tokens are
#: the Go ``HintState.String()`` vocabulary verbatim.
#:
#: ``"absent"``: the header was not sent, or the response was not a 403, where the
#: headers carry no meaning. ``"valid"``: one value of the shape the protocol
#: defines. ``"malformed"``: sent, but not of that shape, or sent more than once.
#: An agent ignores a malformed header as if it were absent; it is reported apart
#: so a caller can log an edge that is misconfigured.
HintState = Literal["absent", "valid", "malformed"]

#: The outcome of comparing a hint's Exchange with the Exchanges the publisher's
#: manifest lists. The tokens are the Go ``HintAgreement.String()`` vocabulary.
#:
#: ``"no_exchange"``: the hint names no usable Exchange, so there is nothing to
#: reconcile. ``"listed"``: the manifest lists it. ``"unlisted"``: it does not, and
#: the manifest wins — the agent discards the hint, does not transact on an offer
#: from that Exchange, and discovers at the Exchanges the manifest lists.
HintAgreement = Literal["no_exchange", "listed", "unlisted"]

_FORBIDDEN = 403
_OWS = " \t"


@dataclass(frozen=True)
class DiscoveryHint:
    """The typed reading of a 403's discovery headers.

    ``content_rules`` and ``exchange`` hold the header values, with surrounding
    spaces and tabs removed, only when their state is ``"valid"``; otherwise they
    are ``None``. ``exchange`` is kept exactly as sent apart from that trimming.
    Compare it with another domain through :func:`reconcile_discovery_hint` or
    :func:`fora_sdk.check_audience`, which fold case and an explicit ``:443``,
    never with ``==``.
    """

    content_rules: str | None = None
    content_rules_state: HintState = "absent"
    exchange: str | None = None
    exchange_state: HintState = "absent"


def parse_discovery_hint(status: int, headers: Mapping[str, str]) -> DiscoveryHint:
    """Read the ``X-Content-Rules`` and ``X-FORA-Exchange`` headers of a response.

    ``headers`` is any mapping of header names to values: an ``httpx.Headers`` (its
    repeated lines are read one by one) or a plain ``dict``. Names are matched
    case-insensitively.

    The headers carry meaning only on a 403. For any other status both states are
    ``"absent"``, whatever the headers hold. Each header is checked on its own, so a
    malformed ``X-FORA-Exchange`` does not discard a valid ``X-Content-Rules``, and
    the other way round.

    ``X-Content-Rules`` is valid when it is exactly ``https://`` or ``http://``,
    then a bare domain (:func:`fora_sdk.is_bare_domain`, a port allowed), then
    :data:`fora_sdk.WellKnownPath`, with nothing after it: no userinfo, query,
    fragment or trailing slash. The http scheme is admitted because whether a leg
    may run in plaintext is the guarded transport's decision, not a shape
    question; the guarded clients refuse it unless plaintext is enabled.
    ``X-FORA-Exchange`` is valid when it is a bare domain, the same shape as
    ``Offer.exchange``.

    A header sent more than once is malformed: its lines are joined with ``", "``
    before the check, and a comma can appear in neither shape.
    """
    if status != _FORBIDDEN:
        return DiscoveryHint()
    content_rules, content_rules_state = _judge(
        _header_value(headers, ContentRulesHeader), _is_content_rules_url
    )
    exchange, exchange_state = _judge(_header_value(headers, ExchangeHeader), is_bare_domain)
    return DiscoveryHint(content_rules, content_rules_state, exchange, exchange_state)


def reconcile_discovery_hint(hint: DiscoveryHint, listed: Iterable[str]) -> HintAgreement:
    """Report whether the publisher's manifest lists the Exchange the hint names.

    ``listed`` holds the domain of every entry in the publisher manifest's
    ``WellKnownManifest.exchanges``. The comparison is the identity match the
    protocol uses for a request's recipient, :func:`fora_sdk.check_audience`: exact
    domain, case folded, an explicit ``:443`` the same as no port, and a subdomain a
    different party. A listed value that is not a bare domain names nobody and
    matches nothing.

    The hint is never authorization. ``"listed"`` says the two sources agree, not
    that the Exchange's offers can be trusted: those are verified by their own
    signatures, as on every other path.
    """
    if hint.exchange_state != "valid" or hint.exchange is None:
        return "no_exchange"
    for domain in listed:
        if is_bare_domain(domain) and check_audience(domain, hint.exchange) == "accepted":
            return "listed"
    return "unlisted"


def _judge(value: str | None, valid: Callable[[str], bool]) -> tuple[str | None, HintState]:
    if value is None:
        return None, "absent"
    if valid(value):
        return value, "valid"
    return None, "malformed"


def _header_value(headers: Mapping[str, str], name: str) -> str | None:
    """Every line of the named header joined with ", ", trimmed, or None if absent."""
    # httpx.Headers.items() merges a repeated header into one comma-joined value;
    # multi_items() keeps the lines apart. Either way the join below is the same.
    multi = getattr(headers, "multi_items", None)
    items: Iterable[tuple[str, str]] = multi() if callable(multi) else headers.items()
    want = name.lower()
    values = [v for k, v in items if k.lower() == want]
    if not values:
        return None
    return ", ".join(values).strip(_OWS)


def _is_content_rules_url(v: str) -> bool:
    """Whether ``v`` is the absolute URL of a FORA manifest.

    String work rather than a URL parse on purpose: the three languages' URL
    parsers disagree on edge cases, and a fixed shape with no optional parts leaves
    nothing for them to disagree about.
    """
    for scheme in ("https://", "http://"):
        if v.startswith(scheme):
            rest = v[len(scheme) :]
            break
    else:
        return False
    if not rest.endswith(WellKnownPath):
        return False
    return is_bare_domain(rest[: -len(WellKnownPath)])
