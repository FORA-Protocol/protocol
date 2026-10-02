"""Mint an Ed25519 identity a FORA verifier can resolve.

Three steps a caller otherwise assembles by hand: a key and its keyid, the Web Bot
Auth key directory that publishes it, and a signer that signs as it. The directory is
built from the generated ``WBAFile`` / ``JsonWebKey`` models, the types the SDK's own
WBA resolver parses, so its shape is defined once, by that schema.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from wire.models import JsonWebKey, WBAFile

from .b64 import b64url_nopad
from .signing_transport import SigningTransport
from .thumbprint import thumbprint
from .wire import to_wire

if TYPE_CHECKING:
    from collections.abc import Sequence

#: How far before "now" a published key's validity window opens, so a verifier whose
#: clock runs slightly behind still accepts it.
_NOT_BEFORE_MARGIN = timedelta(minutes=5)
#: How long a published key stays valid by default.
DEFAULT_KEY_VALIDITY = timedelta(days=365)


def generate_key() -> tuple[Ed25519PrivateKey, str]:
    """A fresh Ed25519 key and its RFC 7638 thumbprint: the keyid every FORA signature names."""
    key = Ed25519PrivateKey.generate()
    return key, thumbprint(key.public_key().public_bytes_raw())


def directory_document(
    keys: Sequence[Ed25519PublicKey],
    *,
    valid_for: timedelta = DEFAULT_KEY_VALIDITY,
    now: datetime | None = None,
) -> dict[str, Any]:
    """The Web Bot Auth key-directory JSON publishing ``keys``, in order.

    Each key carries the ``not_before`` / ``not_after`` window the resolver requires
    before it will hand the key out: it opens a few minutes in the past and lasts
    ``valid_for``. ``now`` is the instant the window is computed from; it defaults to
    the current time and is injectable for a deterministic document.
    """
    now = now if now is not None else datetime.now(UTC)
    not_before = (now - _NOT_BEFORE_MARGIN).isoformat()
    not_after = (now + valid_for).isoformat()
    # Validated rather than constructed, so revocation_url stays unset and to_wire leaves
    # it off the document instead of writing it as null.
    document = WBAFile.model_validate(
        {
            "keys": [
                JsonWebKey(
                    kty="OKP",
                    crv="Ed25519",
                    alg="EdDSA",
                    use="sig",
                    x=b64url_nopad(key.public_bytes_raw()),
                    not_before=not_before,
                    not_after=not_after,
                )
                for key in keys
            ]
        }
    )
    return to_wire(document)


def signing_transport_for(key: Ed25519PrivateKey, directory: str) -> SigningTransport:
    """A signer that signs as ``key``: keyid is its thumbprint, Signature-Agent is ``directory``."""
    return SigningTransport(
        signer_seed=key.private_bytes_raw(),
        keyid=thumbprint(key.public_key().public_bytes_raw()),
        signature_agent=directory,
    )
