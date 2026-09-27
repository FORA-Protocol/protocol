"""The typed view of the fora-music-v1 extension profile — Python mirror of the
sdk/go type (profiles/music/music.go). The profile is one nested JSON object at
``Offer.ext.music``.

``Music`` is a type, not a validator: a dict from ``json.loads`` is not checked.
The profile's JSON Schema, ``music-v1.schema.json``, defines the valid shape
(label format, ISRC pattern, bpm and duration bounds). It is published at
https://fora-protocol.org/protocol/ext-music/. Validate against it when the input
is untrusted. The label pattern uses ``\\p{...}`` classes that Python's ``re`` does
not support, so plain ``jsonschema.validate()`` fails on it. The "Validating in
Python" section of that page shows a validator that uses the ``regex`` package.

Presence follows the profile: an absent key means unknown (an absent ``vocals``
is never ``False``), and an empty list means known to be empty. Consumers ignore
keys they do not know.
"""

from __future__ import annotations

from typing import Literal, TypedDict

__all__ = ["PROFILE_ID", "Music"]

#: The profile identifier an Exchange lists in ExchangeManifest.supported_profiles.
PROFILE_ID = "fora-music-v1"


class Music(TypedDict, total=False):
    """The ``Offer.ext.music`` object. Every key is optional."""

    artist: str
    """Display credit. Not a matching input."""
    isrc: str
    """ISRC of the source recording, also for an excerpt. Not a matching input."""
    genre: str
    mood: list[str]
    instruments: list[str]
    suitable_for: list[str]
    """Editorial suitability. It gives no permission to use the asset."""
    energy: Literal["low", "medium", "high"]
    vocals: bool
    """True when the delivered asset contains any audible human voice."""
    bpm: int
    duration_seconds: float
    """Duration of the delivered asset, not of the source recording."""
