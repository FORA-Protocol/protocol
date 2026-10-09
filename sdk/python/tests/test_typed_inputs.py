"""Typed request inputs: every dict-taking verb also accepts the generated request model.

A caller holding a generated model (``wire.models.UsageReport`` and the rest) should not
have to hand-convert it to a dict, and two conversions written in two places are two
dialects of the same wire. ``fora_sdk.to_wire`` is the ONE serializer: it renders a model
to the proto-JSON object with proto field names, leaving out every field the caller did
not set, and every verb runs a model through it before the envelope is stamped.

The property this suite pins is byte-identity: a verb given the model sends exactly the
bytes it sends for the equivalent dict. That is captured at the injected transport, on
both faces, for every verb that takes a request message.

``execute`` is outside this clause: it takes a ``VerifiedOffer`` (a token only the offer
verifier can mint) and builds the whole TransactionRequest itself, so there is no request
message for a caller to pass. ``fetch`` takes a signed delivery URL, not a message.
"""

from __future__ import annotations

import copy
import inspect
from dataclasses import dataclass
from typing import Any

import pytest
from test_account import _account_config
from test_client import _IDS, FACES, Face, Recorder
from wire.models import (
    DiscoveryRequest,
    DisputeRequest,
    GetAccountStatusRequest,
    PushResourcesRequest,
    RefreshCatalogRequest,
    RegisterRequest,
    RemoveResourcesRequest,
    ResourceQuery,
    UsageReport,
)

import fora_sdk
import fora_sdk.sync as sync_client
from fora_sdk.client import BrokerClient, CallError, CallErrorKind, CatalogClient, Client

#: The verbs that take a VerifiedOffer or a URL instead of a request message.
_OUTSIDE_THE_CLAUSE = {
    "execute": "takes a VerifiedOffer and builds the TransactionRequest itself",
    "fetch": "takes a signed delivery URL",
}


@dataclass(frozen=True)
class _Case:
    """One verb, the face class that carries it, its request model, and a message.

    The message is written in the model's field order, which is the order the generated
    model renders in, so the dict and the model can be compared byte for byte. Each one
    leaves at least one optional field unset, so a conversion that emitted declared
    defaults would put a member on the wire the dict never had.
    """

    verb: str
    face_class: str
    model: Any
    message: dict[str, Any]


_DIGEST = "sha256:" + "ab" * 32
# A query and a discovery name their requester: the message is required. Its keys are
# in the order the model renders them, so the dict and the model send the same bytes.
_REQUESTER = {"domain": "agent.test", "id": "agent", "type": "REQUESTER_TYPE_AGENT"}
_CASES = [
    _Case("discover", "Client", ResourceQuery,
          {"exchange": "exchange.test", "requester": _REQUESTER, "uris": ["https://site.test/a"]}),
    _Case("discover", "Client", ResourceQuery,
          {"exchange": "exchange.test", "requester": _REQUESTER, "uris": ["https://site.test/a"],
           "ver": "9.9"}),
    _Case("resolve", "BrokerClient", DiscoveryRequest,
          {"query": "jazz", "requester": _REQUESTER, "uris": ["https://site.test/a"]}),
    _Case("report_usage", "Client", UsageReport,
          {"billing_id": "bill-1", "exchange": "exchange.test", "idempotency_key": "idem-1",
           "transaction_id": "t-1"}),
    _Case("dispute", "Client", DisputeRequest,
          {"description": "never arrived", "exchange": "exchange.test",
           "idempotency_key": "idem-2", "reason": "DISPUTE_REASON_DELIVERY_FAILED",
           "report_id": "r-1", "transaction_id": "t-1"}),
    _Case("register", "Client", RegisterRequest,
          {"exchange": "exchange.test", "registration_data": {"legal_entity": "Acme"},
           "terms_digest": _DIGEST}),
    _Case("get_account_status", "Client", GetAccountStatusRequest,
          {"exchange": "exchange.test"}),
    _Case("push_resources", "CatalogClient", PushResourcesRequest,
          {"entries": [{"domain": "publisher.test", "path": "/x",
                        "terms": [{"pricing": {"model": "PRICING_MODEL_FREE", "rate": "0"},
                                   "semantics": "TERM_SEMANTICS_ENUMERATED"}]}],
           "exchange": "exchange.test", "tenant_id": "tenant-1"}),
    _Case("remove_resources", "CatalogClient", RemoveResourcesRequest,
          {"exchange": "exchange.test", "paths": ["/x"]}),
    _Case("refresh_catalog", "CatalogClient", RefreshCatalogRequest,
          {"exchange": "exchange.test"}),
]
_CASE_IDS = [f"{c.verb}-{i}" for i, c in enumerate(_CASES)]

_ASYNC = {"Client": Client, "BrokerClient": BrokerClient, "CatalogClient": CatalogClient}
_SYNC = {"Client": sync_client.Client, "BrokerClient": sync_client.BrokerClient,
         "CatalogClient": sync_client.CatalogClient}


def _answer() -> dict[str, Any]:
    # One body every verb's response model accepts: unknown members are ignored.
    return {"ver": "1.0", "exchange": "exchange.test", "billing_ref": "acct-1",
            "report_id": "r-1"}


def _send_into(face: Face, case: _Case, message: Any, rec: Recorder) -> None:
    config = _account_config()
    if face.name == "async":
        client = _ASYNC[case.face_class](config, http=rec.async_())
    else:
        client = _SYNC[case.face_class](config, http=rec.sync())
    face.run(getattr(client, case.verb)(message))


def _send(face: Face, case: _Case, message: Any) -> Recorder:
    rec = Recorder(_answer())
    _send_into(face, case, message, rec)
    return rec


@pytest.mark.parametrize("face", FACES, ids=_IDS)
@pytest.mark.parametrize("case", _CASES, ids=_CASE_IDS)
def test_the_model_and_the_equivalent_dict_send_the_same_bytes(face: Face, case: _Case) -> None:
    from_dict = _send(face, case, copy.deepcopy(case.message))
    model = case.model.model_validate(case.message)
    before = model.model_copy(deep=True)

    from_model = _send(face, case, model)

    assert len(from_dict.seen) == 1
    assert len(from_model.seen) == 1
    assert from_model.seen[0].url == from_dict.seen[0].url
    assert from_model.seen[0].content == from_dict.seen[0].content
    # The caller's model crossed a boundary as an argument, not as a buffer to stamp.
    assert model == before
    assert model.model_fields_set == before.model_fields_set


@pytest.mark.parametrize("case", _CASES, ids=_CASE_IDS)
def test_to_wire_renders_only_the_fields_the_caller_set_under_proto_names(case: _Case) -> None:
    model = case.model.model_validate(case.message)

    assert fora_sdk.to_wire(model) == case.message


def test_to_wire_leaves_declared_defaults_off_the_wire() -> None:
    """A model built with only ``exchange`` set renders only ``exchange``. Its declared
    defaults (``ver`` is ``""``, the extension members are ``None``) stay off the wire,
    so the SDK still stamps ``ver`` the way it does for a dict."""
    assert fora_sdk.to_wire(GetAccountStatusRequest(exchange="exchange.test")) == {
        "exchange": "exchange.test"
    }


@pytest.mark.parametrize("face", FACES, ids=_IDS)
@pytest.mark.parametrize(
    ("case", "kind"),
    [
        (_Case("get_account_status", "Client", GetAccountStatusRequest, {}),
         CallErrorKind.NOT_SENT),
        (_Case("discover", "Client", ResourceQuery, {"uris": ["https://site.test/a"]}),
         CallErrorKind.MALFORMED),
        (_Case("refresh_catalog", "CatalogClient", RefreshCatalogRequest,
               {"tenant_id": "tenant-1"}),
         CallErrorKind.NOT_SENT),
    ],
    ids=["account-no-recipient", "discover-no-recipient", "catalog-no-recipient"],
)
def test_a_model_is_refused_exactly_where_its_dict_is_and_nothing_is_sent(
    face: Face, case: _Case, kind: CallErrorKind
) -> None:
    """``model_construct`` builds a model that skips validation, so the required
    recipient can be missing. The verb refuses it with the same class it gives the
    equivalent dict, before anything is signed."""
    refusals = []
    for message in (dict(case.message), case.model.model_construct(**case.message)):
        rec = Recorder(_answer())
        with pytest.raises(CallError) as caught:
            _send_into(face, case, message, rec)
        assert rec.seen == []
        refusals.append((caught.value.kind, caught.value.op))

    assert refusals[0] == refusals[1]
    assert refusals[0][0] is kind


@pytest.mark.parametrize("faces", [_ASYNC, _SYNC], ids=["async", "sync"])
def test_every_verb_that_takes_a_request_message_is_covered(faces: dict[str, Any]) -> None:
    """A verb added to a client face without a case here would accept a model untested.
    Every public verb is either covered above or named as outside the clause."""
    public = {
        name
        for cls in faces.values()
        for name, member in vars(cls).items()
        if not name.startswith("_") and inspect.isfunction(member)
    }
    covered = {case.verb for case in _CASES}

    assert covered | set(_OUTSIDE_THE_CLAUSE) == public
    assert covered.isdisjoint(_OUTSIDE_THE_CLAUSE)
