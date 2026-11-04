"""The typed view of the fora-music-v1 extension profile — Python mirror of the
sdk/go type (profiles/music/music.go). The profile is a set of flat
``music.<field>`` keys in ``Offer.ext``, for example ``music.genre``.

``Music`` is a type, not a validator: a dict from ``json.loads`` is not checked.
The keys contain a dot, so ``Music`` uses the functional ``TypedDict`` form.
The profile's JSON Schema, ``music-v1.schema.json``, defines the valid shape
(label format, identifier patterns, the date form, the contributor object, bpm and
duration bounds). It is published at
https://fora-protocol.org/protocol/ext-music/. Validate against it when the input
is untrusted. The label pattern uses ``\\p{...}`` classes that Python's ``re`` does
not support, so plain ``jsonschema.validate()`` fails on it. The "Validating in
Python" section of that page shows a validator that uses the ``regex`` package.

Presence follows the profile: an absent key means unknown (an absent
``music.vocals`` is never ``False``), and an empty list means known to be empty.
``music.bpm`` is typed ``int``, but after ``json.loads`` it can be a ``float`` with no
fractional part, for example ``90.0``: the schema accepts that as an integer.
Consumers ignore keys they do not know. A nested ``music`` object is not part of
the profile.
"""

from __future__ import annotations

from typing import Literal, NotRequired, TypedDict

__all__ = ["PROFILE_ID", "Contributor", "Music"]

#: The profile identifier an Exchange lists in WellKnownManifest.supported_profiles.
PROFILE_ID = "fora-music-v1"


#: One entry of ``music.contributors``: one credit. The schema requires ``name`` and
#: ``role``. ``role`` and ``instrument`` are labels. ``isni`` is the 16-character ISNI
#: of the person or group. The functional form is used on purpose: under
#: ``from __future__ import annotations`` a class body stores its annotations as
#: strings, and ``NotRequired`` is then not seen, so ``__required_keys__`` would list
#: every key.
Contributor = TypedDict(  # noqa: UP013
    "Contributor",
    {
        "name": str,
        "role": str,
        "instrument": NotRequired[str],
        "isni": NotRequired[str],
    },
)


#: The ``music.<field>`` keys of ``Offer.ext``. Every key is optional.
#: ``music.artist``, ``music.title`` and ``music.version`` are descriptive, not
#: matching inputs. Only the ``music.isrc`` filter matches ``music.isrc``, as an exact
#: match, and ``music.upc``, ``music.grid`` and ``music.iswc`` work the same way.
#: ``music.duration_seconds`` is the duration of the delivered asset.
#: ``music.language`` is a BCP 47 tag, not a label.
Music = TypedDict(
    "Music",
    {
        "music.artist": str,
        "music.title": str,
        "music.isrc": str,
        "music.genre": str,
        "music.subgenres": list[str],
        "music.themes": list[str],
        "music.mood": list[str],
        "music.instruments": list[str],
        "music.suitable_for": list[str],
        "music.energy": Literal["low", "medium", "high"],
        "music.vocals": bool,
        "music.bpm": int,
        "music.duration_seconds": float,
        "music.version": str,
        "music.language": str,
        "music.parental_warning": Literal["explicit", "explicit_edited", "not_explicit"],
        "music.contains_ai": bool,
        "music.release_title": str,
        "music.release_date": str,
        "music.label": str,
        "music.catalog_number": str,
        "music.upc": str,
        "music.grid": str,
        "music.iswc": str,
        "music.proprietary_ids": list[str],
        "music.p_line": str,
        "music.c_line": str,
        "music.contributors": list[Contributor],
        "music.artwork_url": str,
    },
    total=False,
)
