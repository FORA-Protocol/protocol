"""Delivery URLs are checked by the delivery edge, not by the agent's client.

An Exchange answers a purchase with one signed retrieval URL per item. The edge in front
of the content verifies it: the URL signature, and the agent binding against the proof of
possession the agent presents. An edge that cannot check the binding (CloudFront with its
pre-arranged RSA key pair) checks its own signature and treats the URL as a bearer token.

So ``execute`` hands the URLs back exactly as the Exchange issued them, and ``fetch``
dials one as given with the agent's proof attached. Neither refuses a URL the client
cannot read: by the time the answer arrives the Exchange has already charged, and a
local refusal would lose the purchase answer.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_broker_execute import _broker_config, _offer
from test_client import FACES, Face, Recorder, _config, _signed_offer, _verified

import fora_sdk.sync as sync_client
from fora_sdk.client import Client
from fora_sdk.pop import AGENT_KEY_HEADER
from fora_sdk.signedurl import sign_ed25519_signed_url

_IDS = [f.name for f in FACES]

#: Signed by a key no directory publishes, bound to an agent that is not this one, and
#: long expired. The edge would refuse it; the client hands it back regardless.
_UNVERIFIABLE = sign_ed25519_signed_url(
    "https://edge.example/content/asset-1",
    seed=Ed25519PrivateKey.generate().private_bytes_raw(),
    kid="unknown-key",
    agent_id="someone-else",
    exp=1,
)
#: A CloudFront RSA signed URL: no kid, no agent_id, a signature no Ed25519 check reads.
_CLOUDFRONT = (
    "https://d111111abcdef8.cloudfront.net/content/asset-2"
    "?Expires=4102444800&Signature=c2lnbmF0dXJl&Key-Pair-Id=K2JCJMDEHXQW5F"
)


def _answer(*urls: str) -> dict[str, Any]:
    return {
        "ver": "1.0",
        "agent_identity_hash": "agent-thumbprint",
        "items": [
            {"offer_id": f"offer-{i}", "transaction_id": f"tx-{i}", "retrieval_endpoint": url}
            for i, url in enumerate(urls)
        ],
    }


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_execute_hands_back_every_url_as_issued(face: Face) -> None:
    offer, public = _signed_offer()
    rec = Recorder(_answer(_UNVERIFIABLE, _CLOUDFRONT))
    client = face.client(_config(), rec)

    result = face.run(client.execute(_verified(public, offer)))

    assert [i.retrieval_endpoint for i in result.items] == [_UNVERIFIABLE, _CLOUDFRONT]
    # One request: the purchase. No key directory is read.
    assert len(rec.seen) == 1


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_the_broker_purchase_hands_back_every_url_as_issued(face: Face) -> None:
    answer = {
        **_answer(_UNVERIFIABLE, _CLOUDFRONT),
        "exchanges": [
            {"exchange": "exchange-a.test", "offer_ids": ["offer-0"]},
            {"exchange": "exchange-b.test", "offer_ids": ["offer-1"]},
        ],
    }
    rec = Recorder(answer)
    broker = face.broker(_broker_config(), rec)
    offers = [_offer("offer-0", "exchange-a.test"), _offer("offer-1", "exchange-b.test")]

    result = face.run(broker.execute(offers))

    assert [i.retrieval_endpoint for i in result.items] == [_UNVERIFIABLE, _CLOUDFRONT]
    assert len(rec.seen) == 1


@pytest.mark.parametrize("face", FACES, ids=_IDS)
@pytest.mark.parametrize("url", [_UNVERIFIABLE, _CLOUDFRONT], ids=["ed25519", "cloudfront"])
def test_fetch_dials_the_url_as_given_with_the_agent_proof(face: Face, url: str) -> None:
    seen: list[httpx.Request] = []

    def edge(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=b"bytes", headers={"content-type": "text/plain"})

    transport = httpx.MockTransport(edge)
    client: Any = (
        Client(_config(), http=httpx.AsyncClient(transport=transport))
        if face.name == "async"
        else sync_client.Client(_config(), http=httpx.Client(transport=transport))
    )

    content = face.run(client.fetch(url))

    assert content.body == b"bytes"
    (request,) = seen
    assert str(request.url) == url
    # The proof of possession goes out whatever the URL looks like; the edge decides.
    assert request.headers[AGENT_KEY_HEADER]
    assert request.headers["signature"]
