"""Structural guard for the "forked signature-base builder" disease.

DISEASE: the RFC 9421 request signature base is rendered by hardcoding its component
lines (``"content-digest": {..}``, ``"authorization": {..}``,
``"signature-agent": {..}``) instead of being built from the signature's covered set.
A hardcoded template is how a covered-component change silently drifts one path out of
byte-parity with the Go oracle — and under the Web Bot Auth profile the covered set is
no longer fixed at all: the Signature-Agent line is a keyed member, and a signature that
covers an earlier one adds that one's components.

This guard pins the invariant class-level: NO module under ``fora_sdk`` renders the
request base from a template. Every face that signs or verifies a request signature —
the signer and the appender in ``httpsig.py``, the shared verification core in
``_sigverify.py`` that the server faces use, and the delivery proof in ``pop.py`` —
calls the one generic builder, ``_sigbase.build_signature_base``, which renders one
line per covered component in the signature's own order. The key directory's response
signature (``directory_signature.py``) is a DISTINCT byte contract over
``"@authority";req`` and ``content-digest`` and never matches the fingerprint.

The detector is REGEX-based and whitespace-tolerant on purpose; the
"would-be-missed" meta-test feeds a reformatted fork and asserts it is still
caught.
"""

from __future__ import annotations

import pathlib
import re

_FORA_SDK = pathlib.Path(__file__).resolve().parents[1] / "fora_sdk"
_BUILDER = "build_signature_base"

# The three signature-base lines a hardcoded request-base template carries.
_FINGERPRINT: tuple[re.Pattern[str], ...] = (
    re.compile(r'"content-digest":\s*\{'),
    re.compile(r'"authorization":\s*\{'),
    re.compile(r'"signature-agent":\s*\{'),
)


def _renders_request_base(source: str) -> bool:
    """Pure predicate: does this source render the request base from a template?"""
    return all(pat.search(source) for pat in _FINGERPRINT)


def _request_base_renderers() -> list[str]:
    return [
        path.name
        for path in sorted(_FORA_SDK.glob("*.py"))
        if _renders_request_base(path.read_text(encoding="utf8"))
    ]


class TestNoForkedRequestSignatureBase:
    def test_no_module_renders_the_request_base_from_a_template(self) -> None:
        assert _request_base_renderers() == []

    def test_the_generic_builder_is_defined_once(self) -> None:
        defining = [
            path.name
            for path in sorted(_FORA_SDK.glob("*.py"))
            if f"def {_BUILDER}(" in path.read_text(encoding="utf8")
        ]
        assert defining == ["_sigbase.py"]

    def test_multisig_verify_reuses_shared_base(self) -> None:
        # The server faces verify through the shared core, which builds the base with
        # the generic builder rather than re-rendering lines.
        server = (_FORA_SDK / "server_verify.py").read_text(encoding="utf8")
        assert not _renders_request_base(server)
        assert "_sigverify" in server
        core = (_FORA_SDK / "_sigverify.py").read_text(encoding="utf8")
        assert _BUILDER in core

    def test_append_face_reuses_shared_base(self) -> None:
        src = (_FORA_SDK / "httpsig.py").read_text(encoding="utf8")
        assert "def append_signature" in src
        # Both the fresh and the appended signature go through _sign, the one place
        # the generic builder is called on the signing side.
        assert "_sign(" in src[src.index("def append_signature") :]
        assert "_sign(" in src[src.index("def sign_request") : src.index("def append_signature")]
        assert _BUILDER in src[src.index("def _sign(") :]

    def test_delivery_proof_reuses_shared_base(self) -> None:
        src = (_FORA_SDK / "pop.py").read_text(encoding="utf8")
        assert src.count(_BUILDER) >= 2  # the sign face and the verify face

    # --- meta-tests: exercise the detector against synthetic source ----------
    def test_meta_positive_catches_forked_template(self) -> None:
        fork = "\n".join(
            [
                "lines = [",
                '    f\'"@method": {m}\',',
                '    f\'"@target-uri": {u}\',',
                '    f\'"content-digest": {d}\',',
                '    f\'"authorization": {a}\',',
                '    f\'"signature-agent": {s}\',',
                "]",
            ]
        )
        assert _renders_request_base(fork)

    def test_meta_negative_ignores_pop_base(self) -> None:
        pop_base = "\n".join(
            [
                "lines = [",
                '    f\'"@method": {method}\',',
                '    f\'"@target-uri": {url}\',',
                '    f\'"@signature-params": {raw_params}\',',
                "]",
            ]
        )
        assert not _renders_request_base(pop_base)

    def test_meta_would_be_missed_catches_reformatted_fork(self) -> None:
        reformatted = "\n".join(
            [
                "lines = [",
                '    f\'"content-digest":   {digest_header}\',',
                '    f\'"authorization":\t{authorization}\',',
                '    f\'"signature-agent":  {signature_agent}\',',
                "]",
            ]
        )
        assert _renders_request_base(reformatted)
