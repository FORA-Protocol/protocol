"""Shared pytest fixtures/paths for the sdk/python parity suites.

The parity suites assert sdk/python's `fora_sdk` L1 helpers against the SHARED
Go-oracle vectors (never against copied app fixtures — Core Invariant). This
module centralizes the on-disk locations of those shared corpora so every suite
resolves them the same way, mirroring the sdk/ts sibling's relative-path imports
(`../../go/helpers/testdata/*.json`, `../../../conformance/corpus/crossfield.json`).

It also holds the replay fixtures several suites share, so each one exists once: the
base64url decoder for the oracle's keys, the recording key resolver and the in-memory
replay store a server face is driven with, the header bag a verify vector describes, and
the ``wba01`` fixture through which a test over a Web Bot Auth -01 row reports its
outcome (wba01_pending.py). It creates no package state and imports nothing from
`fora_sdk`, so it never masks the module-missing red the suites are meant to surface.
"""

from __future__ import annotations

import base64
import json
import pathlib
from typing import TYPE_CHECKING, Any

import pytest
from wba01_pending import Wba01Observer, check_marked_items_request_the_fixture

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

# sdk/python/tests/conftest.py -> repo root is parents[3]
# (tests -> python -> sdk -> <repo root>).
_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]

GO_TESTDATA = _REPO_ROOT / "sdk" / "go" / "helpers" / "testdata"
# The fetching resolvers (WBA / well-known / endpoint) and their SSRF + revocation
# corpora live in the sdk/go/resolvers L2 package (the I/O layer, extracted from
# helpers). GO_TESTDATA stays the L1 crypto-vector home; this is its L2 sibling.
GO_RESOLVERS_TESTDATA = _REPO_ROOT / "sdk" / "go" / "resolvers" / "testdata"
# The transport tier's corpus home. A corpus lives with the tier that can produce it,
# and the Connect error envelope can only be captured from a real connect-go handler —
# which neither helpers nor resolvers may import, since both are Connect-free by
# contract. Third home, same rules: emitted by Go, replayed by all three.
GO_CONNECT_TESTDATA = _REPO_ROOT / "sdk" / "go" / "connect" / "testdata"
CONFORMANCE_CORPUS = _REPO_ROOT / "conformance" / "corpus"


def load_json(path: pathlib.Path) -> Any:
    """Read+parse a shared corpus/vector file. Fails the test if it is absent.

    A missing vector file is a legitimate TDD-red signal for the two vectors the
    Go emitter has not yet produced (sign-request-vectors.json,
    acceptance-vectors.json); pytest surfaces the FileNotFoundError as a failure.
    """
    return json.loads(path.read_text())


def b64url_nopad_decode(s: str) -> bytes:
    """Decode the unpadded base64url a corpus carries a key or a signature in."""
    pad = "" if len(s) % 4 == 0 else "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


class RecordingResolver:
    """A KeyResolver that records every (directory, keyid) it was asked to resolve.

    The injected-boundary probe: the server face MUST resolve keys ONLY through this
    holder, so the recorded calls prove no key was read out-of-band, and the recorded
    directory proves the key was looked up where the signature's member points.
    """

    def __init__(self, keys: dict[str, bytes]) -> None:
        self._keys = dict(keys)
        self.calls: list[tuple[str, str | None]] = []

    def resolve(self, keyid: str | None, directory: str) -> bytes | None:
        self.calls.append((directory, keyid))
        if keyid is None:
            return None
        return self._keys.get(keyid)


class MemoryReplayStore:
    """An in-test replay store the SDK orchestrates over (seen / seen_or_add).

    The SDK ships NO default store, so replay state lives entirely here, the state
    boundary the Core Invariant requires. ``seen`` maps each nonce to the TTL it was
    added with, so a test can check the TTL the verifier asked for.
    """

    def __init__(self) -> None:
        self.seen: dict[str, int] = {}

    def seen_nonce(self, nonce: str) -> bool:
        return nonce in self.seen

    def seen_or_add(self, nonce: str, ttl_seconds: int) -> bool:
        if nonce in self.seen:
            return True
        self.seen[nonce] = ttl_seconds
        return False


def verify_vector_headers(v: Mapping[str, Any]) -> dict[str, str]:
    """The header bag a single-signature verify vector describes.

    The base five come from the scalar columns; a name in ``omit_headers`` is dropped,
    so the face sees a covered name with no field line rather than an empty one; and
    each ``extra_headers`` line is added AFTER the base ones, spelled in another case so
    the mapping holds both, which makes the join order the order the oracle added them.
    The ``repeated_field_lines_*`` rows test exactly that order, so every replay builds
    the bag here.
    """
    headers = {
        "content-digest": str(v["content_digest"]),
        "signature-input": str(v["signature_input"]),
        "signature": str(v["signature"]),
        "authorization": str(v["authorization"]),
        "signature-agent": str(v["signature_agent"]),
    }
    for name in v.get("omit_headers") or []:
        headers.pop(str(name).lower(), None)
    for name, value in (v.get("extra_headers") or {}).items():
        headers[str(name)] = str(value)
    return headers


@pytest.fixture
def wba01(request: pytest.FixtureRequest) -> Iterator[Wba01Observer]:
    """The observer a test over a Web Bot Auth -01 row reports its outcome to."""
    observer = Wba01Observer.for_node(request.node)
    yield observer
    observer.check_observed()


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "wba01(key): a test over a pending Web Bot Auth -01 row")


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    check_marked_items_request_the_fixture(items)
