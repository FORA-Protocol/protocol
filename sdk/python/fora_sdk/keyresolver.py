"""Verifying-key resolution seam (ADR-020 §4) — the injection point for key lookup.

Mirrors the sdk/go split (sdk/go/helpers/keyresolver.go): the pure L1 verify takes
a resolved key directly; the resolver is how an application supplies keys — from a
key directory, a private registry, a preloaded set, a proxy, or mTLS. This module
carries only the PURE ``StaticKeyResolver``; the fetching WBA resolver (IO) is the
injected default that lives OUTSIDE the pure L1 verify.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class KeyResolver(Protocol):
    """Resolve the raw 32-byte Ed25519 public key for a keyid, or None if unknown.

    ``directory`` is the https origin of the key directory the signature being verified
    names in its own covered Signature-Agent member — a fresh value per signature, so a
    request carrying several signers' signatures resolves each key in its own signer's
    directory. Go threads the same value through the context
    (``helpers.SignatureAgentFromContext``). A resolver that serves one fixed key set
    may ignore it; one that fetches keys must look ``keyid`` up in that directory and
    nowhere else.
    """

    def resolve(self, keyid: str | None, directory: str) -> bytes | None:
        """Return the public key ``directory`` publishes for ``keyid``, or None."""
        ...


class StaticKeyResolver:
    """Serve public keys from an in-memory map — for preloaded key sets and tests.

    The keys are keyed by keyid alone, whatever directory a signature names: a
    preloaded set is trusted as a whole, so it answers for every directory.
    """

    def __init__(self, keys: dict[str, bytes] | None = None) -> None:
        """Seed the resolver with a copy of ``keys``."""
        self._keys: dict[str, bytes] = dict(keys or {})

    def resolve(self, keyid: str | None, directory: str = "") -> bytes | None:  # noqa: ARG002 - one key set answers for every directory
        """Return the public key for ``keyid``, or None when unknown/absent."""
        if keyid is None:
            return None
        return self._keys.get(keyid)

    def put(self, keyid: str, pub: bytes) -> None:
        """Register a ``keyid -> public-key`` mapping (dynamic / test seeding)."""
        self._keys[keyid] = pub
