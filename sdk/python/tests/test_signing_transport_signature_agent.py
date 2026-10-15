"""SigningTransport.signature_agent — the signer's key-directory origin, required.

Every Web Bot Auth signature names its signer's key directory: the transport writes
the member ``sig1="<origin>"`` into Signature-Agent and the signature covers it as
``"signature-agent";key="sig1"``. A verifier rebuilds the base from the request it
RECEIVED, so the header has to arrive carrying exactly the member that was signed.

(a) signature_agent="https://agent.example" → the header carries the one-member
    dictionary, and the keyed member appears in the Signature-Input covered list.

(b) no directory, or one that is not an https origin → nothing is signed. The old
    static-bootstrap case signed an EMPTY directory; the profile has no such form,
    and a verifier would have nowhere to resolve the key.

The whole emitted set is pinned against the Go oracle by the shared corpus, in
test_signrequest_parity.py; this file covers the signature_agent shapes directly.
"""

from __future__ import annotations

import pytest

from fora_sdk.signing_transport import SigningTransport
from fora_sdk.wba import SignatureAgentNotOriginError, SignatureAgentRequiredError


def _make_transport(*, signature_agent: str = "") -> SigningTransport:
    """Construct a SigningTransport with a fixed seed and optional signature_agent."""
    return SigningTransport(
        signer_seed=bytes(range(1, 33)),
        keyid="agent.test.v1",
        now=lambda: 1_700_000_000.0,
        signature_agent=signature_agent,
    )


# ---- (a) signature_agent configured → header present + covered ------------


def test_signature_agent_header_present_when_configured() -> None:
    """When signature_agent is set, signed.headers carries 'Signature-Agent'."""
    transport = _make_transport(signature_agent="https://agent.example")
    signed = transport.sign_outbound(
        method="POST",
        url="https://broker.example/fora.v1/Discover",
        body=b'{"query":"x"}',
        authorization="",
    )
    header_keys_lower = {k.lower() for k in signed.headers}
    assert "signature-agent" in header_keys_lower, (
        f"Expected 'Signature-Agent' header; got headers: {list(signed.headers.keys())}"
    )


def test_signature_agent_covered_in_signature_input_when_configured() -> None:
    """When signature_agent is set, the Signature-Input covered list includes it."""
    transport = _make_transport(signature_agent="https://agent.example")
    signed = transport.sign_outbound(
        method="POST",
        url="https://broker.example/fora.v1/Discover",
        body=b'{"query":"x"}',
        authorization="",
    )
    sig_input = signed.headers.get("signature-input") or signed.headers.get("Signature-Input") or ""
    assert '"signature-agent";key="sig1"' in sig_input, (
        f"Expected 'signature-agent' in Signature-Input covered set; got: {sig_input!r}"
    )


# ---- (b) no directory, or not an origin → refused before signing -----------


@pytest.mark.parametrize(
    ("signature_agent", "error"),
    [
        ("", SignatureAgentRequiredError),
        ("agent.example", SignatureAgentNotOriginError),
        ("https://agent.example/keys", SignatureAgentNotOriginError),
        ("https://agent.example:443", SignatureAgentNotOriginError),
    ],
    ids=["empty", "bare_host", "with_path", "default_port"],
)
def test_a_transport_without_an_origin_signs_nothing(
    signature_agent: str, error: type[Exception]
) -> None:
    transport = _make_transport(signature_agent=signature_agent)
    with pytest.raises(error):
        transport.sign_outbound(
            method="POST",
            url="https://broker.example/fora.v1/Discover",
            body=b'{"query":"x"}',
            authorization="",
        )


def test_the_emitted_member_is_the_one_the_signature_covers() -> None:
    """The header is the one-member dictionary, and Authorization is carried empty."""
    transport = _make_transport(signature_agent="https://agent.example")
    signed = transport.sign_outbound(
        method="POST",
        url="https://broker.example/fora.v1/Discover",
        body=b'{"query":"x"}',
        authorization="",
    )
    assert signed.headers["signature-agent"] == 'sig1="https://agent.example"'
    assert signed.headers["authorization"] == ""
