"""Music profile type (Python side).

Mirrors the sdk/ts sibling sdk/ts/tests/music.parity.test.ts. The sdk/go type is
the oracle, and the shared cases at
sdk/go/profiles/music/testdata/music-cases.json name every field in their
all_fields case. A TypedDict is not checked at runtime, so the check here is on
its declared keys: a field added to or removed from one side fails this test.
"""

from __future__ import annotations

from conftest import _REPO_ROOT, load_json

from fora_sdk.music import PROFILE_ID, Contributor, Music, Publisher

_CASES = load_json(
    _REPO_ROOT / "sdk" / "go" / "profiles" / "music" / "testdata" / "music-cases.json"
)["cases"]
(_ALL_FIELDS,) = [c for c in _CASES if c["name"] == "all_fields"]


def test_music_keys_match_the_shared_all_fields_case() -> None:
    assert set(Music.__annotations__) == set(_ALL_FIELDS["input"])


def test_music_keys_are_all_optional() -> None:
    assert Music.__required_keys__ == frozenset()


def test_contributor_keys_match_the_shared_all_fields_contributor() -> None:
    # The one contributor of the all_fields case names every key of a contributor.
    (contributor,) = _ALL_FIELDS["input"]["music.contributors"]
    assert set(Contributor.__annotations__) == set(contributor)


def test_contributor_requires_only_name_and_role() -> None:
    assert Contributor.__required_keys__ == frozenset({"name", "role"})


def test_publisher_keys_match_the_shared_all_fields_publisher() -> None:
    # The one publisher of the all_fields case names every key of a publisher.
    (publisher,) = _ALL_FIELDS["input"]["music.publishers"]
    assert set(Publisher.__annotations__) == set(publisher)


def test_publisher_requires_only_name() -> None:
    assert Publisher.__required_keys__ == frozenset({"name"})


def test_profile_id() -> None:
    assert PROFILE_ID == "fora-music-v1"
