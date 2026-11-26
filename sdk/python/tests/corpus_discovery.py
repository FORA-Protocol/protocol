"""Where the shared Go-oracle corpora are: one glob, read by every consumer.

A shared corpus is any ``*-vectors.json`` in a ``testdata`` directory of a Go SDK package,
at any depth under ``sdk/go``. The corpus-completeness gate and
``scripts/gen-parity-matrix.py`` both call :func:`corpus_files`, so a corpus committed to
a package that has never held one before is gated and listed the day it lands, with no
list of homes to edit.

The parity-matrix script runs on a bare ``python3``, so this module imports only the
standard library.
"""

from __future__ import annotations

import pathlib

# sdk/python/tests/corpus_discovery.py -> repo root is parents[3].
REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
GO_SDK = REPO_ROOT / "sdk" / "go"


def corpus_files() -> list[pathlib.Path]:
    """Every committed shared corpus under ``sdk/go``, sorted by path."""
    return sorted(GO_SDK.glob("**/testdata/*-vectors.json"))
