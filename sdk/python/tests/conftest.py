"""Shared pytest fixtures/paths for the sdk/python parity suites.

The parity suites assert sdk/python's `fora_sdk` L1 helpers against the SHARED
Go-oracle vectors (never against copied app fixtures — Core Invariant). This
module centralizes the on-disk locations of those shared corpora so every suite
resolves them the same way, mirroring the sdk/ts sibling's relative-path imports
(`../../go/helpers/testdata/*.json`, `../../../conformance/corpus/crossfield.json`).

Besides the corpus paths and a JSON loader it holds one helper the signing suites
share, ``ed25519_identity``: the keyid and public key of a test seed. It creates no
package state.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fora_sdk.thumbprint import thumbprint

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
# The signing transport's corpus home. The signing window is a core face (core.Window,
# core.NewSigningTransport), and helpers may not import core, so its corpus is emitted
# from sdk/go/core. Fourth home, same rules.
GO_CORE_TESTDATA = _REPO_ROOT / "sdk" / "go" / "core" / "testdata"
CONFORMANCE_CORPUS = _REPO_ROOT / "conformance" / "corpus"


def load_json(path: pathlib.Path) -> Any:
    """Read+parse a shared corpus/vector file. Fails the test if it is absent.

    A missing vector file is a legitimate TDD-red signal for the two vectors the
    Go emitter has not yet produced (sign-request-vectors.json,
    acceptance-vectors.json); pytest surfaces the FileNotFoundError as a failure.
    """
    return json.loads(path.read_text())


def ed25519_identity(seed: bytes) -> tuple[str, bytes]:
    """The RFC 7638 thumbprint keyid and the raw public key of a 32-byte Ed25519 seed."""
    pub = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    return thumbprint(pub), pub
