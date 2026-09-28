"""Music profile type (Python side).

Mirrors the sdk/ts sibling sdk/ts/tests/music.parity.test.ts. The sdk/go type is
the oracle, and the shared cases at
sdk/go/profiles/music/testdata/music-cases.json name every field in their
all_fields case. A TypedDict is not checked at runtime, so the check here is on
its declared keys: a field added to or removed from one side fails this test.
"""

from __future__ import annotations

from conftest import _REPO_ROOT, load_json

from fora_sdk.music import PROFILE_ID, Music

_CASES = load_json(
    _REPO_ROOT / "sdk" / "go" / "profiles" / "music" / "testdata" / "music-cases.json"
)["cases"]


def test_music_keys_match_the_shared_all_fields_case() -> None:
    (all_fields,) = [c for c in _CASES if c["name"] == "all_fields"]
    assert set(Music.__annotations__) == set(all_fields["input"])


def test_music_keys_are_all_optional() -> None:
    assert Music.__required_keys__ == frozenset()


def test_profile_id() -> None:
    assert PROFILE_ID == "fora-music-v1"
