"""The typed view of the fora-music-v1 extension profile — Python mirror of the
sdk/go type (profiles/music/music.go). The profile is a set of flat
``music.<field>`` keys in ``Offer.ext``, for example ``music.genre``.

``Music`` is a type, not a validator: a dict from ``json.loads`` is not checked.
The keys contain a dot, so ``Music`` uses the functional ``TypedDict`` form.
The profile's JSON Schema, ``music-v1.schema.json``, defines the valid shape
(label format, ISRC pattern, bpm and duration bounds). It is published at
https://fora-protocol.org/protocol/ext-music/. Validate against it when the input
is untrusted. The label pattern uses ``\\p{...}`` classes that Python's ``re`` does
not support, so plain ``jsonschema.validate()`` fails on it. The "Validating in
Python" section of that page shows a validator that uses the ``regex`` package.

Presence follows the profile: an absent key means unknown (an absent
``music.vocals`` is never ``False``), and an empty list means known to be empty.
Consumers ignore keys they do not know. A nested ``music`` object is not part of
the profile.
"""

from __future__ import annotations

from typing import Literal, TypedDict

__all__ = ["PROFILE_ID", "Music"]

#: The profile identifier an Exchange lists in WellKnownManifest.supported_profiles.
PROFILE_ID = "fora-music-v1"

#: The ``music.<field>`` keys of ``Offer.ext``. Every key is optional.
#: ``music.artist`` is descriptive, not a matching input. Only the ``music.isrc``
#: filter matches ``music.isrc``, as an exact match.
#: ``music.duration_seconds`` is the duration of the delivered asset.
Music = TypedDict(
    "Music",
    {
        "music.artist": str,
        "music.isrc": str,
        "music.genre": str,
        "music.mood": list[str],
        "music.instruments": list[str],
        "music.suitable_for": list[str],
        "music.energy": Literal["low", "medium", "high"],
        "music.vocals": bool,
        "music.bpm": int,
        "music.duration_seconds": float,
    },
    total=False,
)
