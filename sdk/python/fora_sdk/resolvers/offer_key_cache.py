"""Cached, domain-keyed offer-signing-key resolver (DRY-01).

Home of the per-domain TTL cache → WBA-directory fetch → active-key-with-expiry
selection → not_after clamp that the Broker (``offerkeys.Resolver``) and the MCP
shim (``ExchangeOfferKeyCache``) each re-implemented. Consolidating them here means
the clamp — the off-by-one-prone ``min(now + ttl, not_after)`` — lives and is fixed
once.

Selection is REVOCATION-AWARE (:func:`active_ed25519_key_with_expiry_screened`): a
window-active-but-revoked key still listed in a CDN-cached directory is skipped, so
the cache is safe to feed a verification path.

The async prefetch face mirrors ``ExchangeOfferKeyCache``: because
:class:`fora_sdk.core.Verifier` resolves keys synchronously, the caller prefetches
the keys for the exchanges present in a response, then seeds a
:class:`~fora_sdk.core.StaticOfferKeyResolver` for the sort. The WBA-directory fetch
is an INJECTED seam (``fetch``) — the app supplies its SSRF-guarded client + URL
builder, a test supplies a directory table with no network — so this type owns only
the cache, selection, and clamp.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterable
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from wire.models import WBAFile

from fora_sdk.resolvers._http import guarded_client
from fora_sdk.resolvers.errors import DirectoryUnavailableError
from fora_sdk.resolvers.wba import (
    _get_wba_directory,
    active_ed25519_key_with_expiry_screened,
    wba_directory_url,
)

if TYPE_CHECKING:
    import httpx

_DEFAULT_TTL_SECONDS = 300

# DirectoryFetch resolves one exchange domain to its WBA directory, or None when the
# directory is unresolvable (unreachable, malformed, blocked). The fetcher MUST
# contain its own failures as None rather than raise, so one bad exchange never
# crashes the prefetch batch — the same fail-closed shape the app fetchers already use.
DirectoryFetch = Callable[[str], Awaitable[WBAFile | None]]


def _default_now() -> datetime:
    return datetime.now(UTC)


def _never_revoked(_thumbprint: str) -> bool:
    return False


def _clamp_expiry(now: float, ttl_seconds: float, not_after: float) -> float:
    """Bound a cache entry's expiry to the key's validity window.

    The entry expires at ``min(now + ttl, not_after)`` (all epoch seconds), so a key
    is never served past its ``not_after`` even within the TTL. Extracted as a pure
    helper so the tri-language clamp corpus (``offer-key-clamp-vectors.json``) replays
    the SAME arithmetic the resolver runs, not a re-inlined copy that could drift.
    """
    return min(now + ttl_seconds, not_after)


class CachedOfferKeyResolver:
    """domain → exchange offer-signing key, via an injected WBA-directory fetch,
    TTL-cached with a not_after clamp and revocation-aware selection."""

    def __init__(
        self,
        *,
        fetch: DirectoryFetch,
        now: Callable[[], datetime] | None = None,
        ttl_seconds: int = _DEFAULT_TTL_SECONDS,
        revoked: Callable[[str], bool] | None = None,
    ) -> None:
        """Wire the resolver.

        ``fetch`` resolves a domain to its WBA directory (required). ``now`` is the
        cache-freshness + selection clock (default :func:`datetime.now(UTC)`).
        ``ttl_seconds`` bounds the per-domain cache. ``revoked`` screens a candidate
        key by its RFC 7638 thumbprint — a revoked key is skipped during selection so
        a window-active-but-revoked key is never served; default screens nothing, so
        a verification-path caller SHOULD inject :meth:`WBAKeyResolver.revoked` (or an
        equivalent revoked-set predicate).
        """
        self._fetch = fetch
        self._now = now if now is not None else _default_now
        self._ttl = ttl_seconds
        self._revoked: Callable[[str], bool] = revoked if revoked is not None else _never_revoked
        self._cache: dict[str, tuple[bytes, float]] = {}

    async def prefetch(self, exchanges: Iterable[str]) -> dict[str, bytes]:
        """Return ``{exchange: raw 32-byte key}`` for every resolvable exchange.

        A cache hit within the (clamped) TTL short-circuits; misses are fetched
        concurrently, their active non-revoked key selected, and cached with an expiry
        clamped to ``min(now + ttl, not_after)``. An unresolvable exchange (fetch
        returned None, no active/non-revoked key) is simply absent from the map — the
        Verifier then rejects its offers fail-closed.

        ONE exchange never costs the others their keys. The injected fetch is contracted
        to return None rather than raise, but this gathers with ``return_exceptions=True``
        and treats a raised exception as "absent" anyway, because the domains in this
        batch come off UNVERIFIED offers: a single hostile or relayed offer must not be
        able to empty the whole map and have every legitimate exchange's offers rejected.
        The contract is what the default fetch upholds; this is what makes the batch hold
        for any fetch at all.
        """
        now_dt = self._now()
        now = now_dt.timestamp()
        wanted = {e for e in exchanges if e}
        out: dict[str, bytes] = {}
        misses: list[str] = []
        for ex in wanted:
            hit = self._cache.get(ex)
            if hit is not None and now < hit[1]:
                out[ex] = hit[0]
            else:
                misses.append(ex)
        if not misses:
            return out
        results = await asyncio.gather(
            *(self._fetch(ex) for ex in misses), return_exceptions=True
        )
        for ex, wba in zip(misses, results, strict=True):
            if wba is None or isinstance(wba, BaseException):
                continue
            selected = active_ed25519_key_with_expiry_screened(wba, now_dt, self._revoked)
            if selected is None:
                continue
            key, not_after = selected
            # Clamp the cache entry to the key's validity window: never serve a key
            # past its not_after, even within the TTL (mirrors the Go resolver's
            # exp = min(now+ttl, not_after)). The read check above then evicts the key
            # at not_after and a refetch fails closed once the key is inactive.
            expiry = _clamp_expiry(now, self._ttl, not_after.timestamp())
            self._cache[ex] = (key, expiry)
            out[ex] = key
        return out


def _join_host_port(host: str, port: str) -> str:
    """Join ``host`` and ``port`` into the authority the directory URL is built on.

    Port of the Go oracle ``joinDirectoryHost``
    (``sdk/go/resolvers/cachedofferkeyresolver.go``), and held to it by the
    tri-language ``wba-join-vectors.json`` corpus that
    ``tests/test_resolvers_wba_join_parity.py`` replays.

    An empty port leaves the host alone so the scheme default applies. Otherwise the
    rule is ``net.JoinHostPort``'s: a host containing a colon is wrapped in brackets,
    with no check for what the host already carries. That covers two shapes. A host
    already carrying brackets becomes ``[[::1]]:8443``, and a host already carrying a
    port becomes ``[exchange.example:8443]:9000``.

    The first cannot arrive through a validated offer: ``Offer.exchange`` is
    constrained to a bare domain with an OPTIONAL NUMERIC PORT, so no bracket and no
    bare IPv6 literal passes. The second is reachable in production, because that
    optional port is exactly what admits ``exchange.example:8443`` — the spelling the
    field's own doc comment uses as its example. An Exchange whose offers name a
    port, read by a fetch configured with a port of its own, joins to an authority
    httpx refuses. The directory is then never fetched and every offer from that
    Exchange fails to verify, silently, down the fail-closed path.

    The corpus pins all of it, dialability included, so the three SDKs cannot answer
    different URLs for the same exchange.
    """
    if port == "":
        return host
    if ":" in host:
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def create_wba_offer_directory_fetch(
    *,
    http: httpx.Client | None = None,
    scheme: str = "",
    port: str = "",
) -> DirectoryFetch:
    """The default :data:`DirectoryFetch`: GET one exchange's Web Bot Auth directory
    and decode the ``WBAFile``.

    Port of the Go oracle's ``NewWBADirectoryFetcher(client, scheme, port)`` and the
    TypeScript ``createWBAOfferDirectoryFetch({fetch, scheme, port})``. An exchange's
    offer-signing key is published ONLY here — not in ``fora.json`` — so this fetch is
    what makes an offer verifiable at all. Until it existed every Python integrator
    hand-wrote it, including the fail-closed contract below, which is the part that is
    easy to get wrong.

    ``http`` defaults to the SSRF-guarded :func:`~fora_sdk.resolvers._http.guarded_client`.
    Which default a fetch takes follows its URL's PROVENANCE: the exchange domain
    arrives inside an offer, so the party choosing the address is not the party running
    the process. A caller that must reach a private directory injects its own client,
    the same escape hatch the other resolver faces expose. Empty ``scheme`` means https
    and empty ``port`` means the scheme default; the URL is built by
    :func:`~fora_sdk.resolvers.wba.wba_directory_url`, so it is the exact string the
    tri-language ``wba-url-vectors.json`` corpus pins.

    **Every failure is contained as None and none is raised.** That is
    :data:`DirectoryFetch`'s contract rather than a preference:
    :meth:`CachedOfferKeyResolver.prefetch` gathers these calls through
    ``asyncio.gather`` WITHOUT ``return_exceptions``, so one raised error abandons the
    whole batch instead of leaving a single exchange unresolved. An unresolvable
    exchange is simply absent from the map, and the Verifier then rejects that
    exchange's offers fail-closed.

    The GET runs on a worker thread because the guarded client is synchronous.
    :mod:`fora_sdk.client` records the reason for that shape: an async twin of each
    blocking tier would be a Python-only public face with no Go or TypeScript
    counterpart, for a seam a thread already crosses correctly. Crossing with a thread
    also keeps the 1 MiB body bound and the overall wall-clock deadline that
    :func:`~fora_sdk.resolvers._http.fetch_strict` already applies — a hand-written
    ``await client.get(...)`` has neither.
    """
    client = http if http is not None else guarded_client()

    async def fetch(domain: str) -> WBAFile | None:
        url = wba_directory_url(scheme, _join_host_port(domain, port))
        try:
            return await asyncio.to_thread(_get_wba_directory, client, url)
        except Exception:
            # EVERY exception, because the seam's contract is absolute: a
            # DirectoryFetch returns None and never raises, so a caller batching
            # several exchanges keeps the rest when one fails. TypeScript's
            # createWBAOfferDirectoryFetch contains the same way, with a bare `catch`;
            # Go's seam is (file, error) and returns the error for that one domain.
            #
            # DirectoryUnavailableError is the expected arrival, because
            # _get_wba_directory is the shared GET-and-decode and it folds every arm
            # into this error: fetch_strict maps httpx.HTTPError and OSError (SsrfError
            # is one, so is the deadline's TimeoutError) plus any non-200, and the
            # helper adds the malformed-URL and not-a-directory arms on top. Catching a
            # list of families here is what let the docstring's "every failure" drift
            # away from what the code actually contained.
            return None

    return fetch
