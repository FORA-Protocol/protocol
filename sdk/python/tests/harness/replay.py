"""The collaborators a replay injects into the SDK's public faces, and its checks.

The SDK owns no keys and no replay state: a caller passes a key resolver and a replay
store. These are the ones the suites pass, so a replay observes which keys were asked
for through the resolver it injected, never through a private function.
``ed25519_identity`` gives the keyid and public key of a test seed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fora_sdk.errordetail import REASON_FIELDS, reason
from fora_sdk.thumbprint import thumbprint

if TYPE_CHECKING:
    from collections.abc import Mapping

    from wire.models import ErrorDetail


class RecordingResolver:
    """A key resolver that records every ``(directory, keyid)`` it is asked for.

    A key is listed under ``(directory, keyid)`` and is found only in that directory, so
    a signature resolved through the wrong Signature-Agent member finds no key. A key
    listed under ``(None, keyid)`` is found in any directory.
    """

    def __init__(self, keys: Mapping[tuple[str | None, str], bytes]) -> None:
        self._keys = dict(keys)
        self.calls: list[tuple[str, str | None]] = []

    def resolve(self, keyid: str | None, directory: str) -> bytes | None:
        self.calls.append((directory, keyid))
        if keyid is None:
            return None
        return self._keys.get((directory, keyid), self._keys.get((None, keyid)))


class MemoryReplayStore:
    """A replay store held in memory: a nonce is seen once it has been added, and stays
    seen for the life of the store. ``seen`` records the TTL each entry was added with."""

    def __init__(self) -> None:
        self.seen: dict[str, int] = {}

    def seen_nonce(self, nonce: str) -> bool:
        return nonce in self.seen

    def seen_or_add(self, nonce: str, ttl_seconds: int) -> bool:
        if nonce in self.seen:
            return True
        self.seen[nonce] = ttl_seconds
        return False


def ed25519_identity(seed: bytes) -> tuple[str, bytes]:
    """The RFC 7638 thumbprint keyid and the raw public key of a 32-byte Ed25519 seed."""
    pub = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    return thumbprint(pub), pub


def vector_headers(vector: Mapping[str, Any], signature_agent: str | None = None) -> dict[str, str]:
    """The header bag a signed-request vector describes.

    The base five come from the vector's columns, with ``signature_agent`` in place of
    its ``signature_agent`` column when given. An ``entitlement`` column adds an
    X-Entitlement-Token header. ``omit_headers`` then drops names, so the face sees a
    covered name with no field line rather than an empty one, and ``extra_headers`` adds
    field lines spelled in another case, after the base ones, so the join order matches
    the order the oracle added them.
    """
    headers = {
        "content-digest": str(vector["content_digest"]),
        "signature-input": str(vector["signature_input"]),
        "signature": str(vector["signature"]),
        "authorization": str(vector["authorization"]),
        "signature-agent": signature_agent or str(vector["signature_agent"]),
    }
    if vector.get("entitlement"):
        headers["X-Entitlement-Token"] = str(vector["entitlement"])
    for name in vector.get("omit_headers") or []:
        headers.pop(str(name).lower(), None)
    for name, value in (vector.get("extra_headers") or {}).items():
        headers[str(name)] = str(value)
    return headers


def assert_recorded_reason(detail: ErrorDetail, row: Mapping[str, Any]) -> None:
    """Exactly the row's ``reason_field`` member of ``detail`` is populated, and its
    reason is the row's ``reason_enum``."""
    populated = [f for f in REASON_FIELDS if getattr(detail, f, None) is not None]
    assert populated == [row["reason_field"]]
    got = reason(detail)
    assert got is not None
    assert got.value == row["reason_enum"]
