"""FORA SDK fetching resolver faces (ADR-020 §4).

These are the FIRST IO in the Python SDK, so they live OUTSIDE ``fora_sdk.core``
(which keeps its httpx-ban / IO-free guard green) in this dedicated package. Three
fetching faces port the Go oracle — a well-known JWKS key resolver, a host-keyed
well-known endpoint resolver, and the WBA identity-directory resolver +
revocation poller — alongside the typed exceptions that preserve the oracle's
errors.Is-DISTINCT fail-closed taxonomy. The static face stays in
:mod:`fora_sdk.keyresolver` (:class:`~fora_sdk.keyresolver.StaticKeyResolver`).
"""

from __future__ import annotations

from fora_sdk.resolvers._http import (
    async_ssrf_guard,
    guarded_async_client,
    guarded_client,
    ssrf_guard,
)
from fora_sdk.resolvers._ssrf import SsrfError, blocked_address
from fora_sdk.resolvers.errors import (
    DirectoryUnavailableError,
    EndpointRefusedError,
    KeyExpiredError,
    KeyRevokedError,
    NoEndpointError,
    ResolverError,
    RevocationUnevaluatedError,
    UnknownKeyError,
)
from fora_sdk.resolvers.offer_key_cache import CachedOfferKeyResolver, DirectoryFetch
from fora_sdk.resolvers.wba import (
    WBA_DIRECTORY_PATH,
    WBAKeyResolver,
    active_ed25519_key,
    active_ed25519_key_screened,
    active_ed25519_key_with_expiry,
    active_ed25519_key_with_expiry_screened,
    wba_directory_url,
)
from fora_sdk.resolvers.wellknown import WellKnownEndpointResolver, WellKnownKeyResolver

__all__ = [
    "WBA_DIRECTORY_PATH",
    "CachedOfferKeyResolver",
    "DirectoryFetch",
    "DirectoryUnavailableError",
    "EndpointRefusedError",
    "KeyExpiredError",
    "KeyRevokedError",
    "NoEndpointError",
    "ResolverError",
    "RevocationUnevaluatedError",
    "SsrfError",
    "UnknownKeyError",
    "WBAKeyResolver",
    "WellKnownEndpointResolver",
    "WellKnownKeyResolver",
    "active_ed25519_key",
    "active_ed25519_key_screened",
    "active_ed25519_key_with_expiry",
    "active_ed25519_key_with_expiry_screened",
    "async_ssrf_guard",
    "blocked_address",
    "guarded_async_client",
    "guarded_client",
    "ssrf_guard",
    "wba_directory_url",
]
