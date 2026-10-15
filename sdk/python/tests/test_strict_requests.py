"""``ClientConfig.strict_requests``: refuse a request the contract does not describe, before
it is signed.

The generated models ignore a member they do not declare, so a plain dict carrying a
misspelled key passes the field-level check, is signed and sent, and the server drops the
member. A negative test whose mutation is that key then passes while testing nothing.
Under the switch a verb takes only its own generated model, or a RawBody that is sent
exactly as given, and the message as stamped must pass the published strict JSON Schema of
the request and the SDK's cross-field rules.

Pinned on both faces, for every verb that takes a request message: a plain dict, or a model
of another message, is refused before anything is resolved, signed or sent; the verb's
model sends the same bytes with the switch on as with it off; a RawBody is sent unchecked.
Then what only the stamped message shows: a member the client adds itself (the configured
requester, a reflected offer), a cross-field rule the model does not check, and
``validation="off"``, which leaves the switch in force.
"""

from __future__ import annotations

import inspect
import json
from typing import TYPE_CHECKING, Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_account import _account_config
from test_client import _IDS, FACES, REQUESTER, Face, Recorder, _config, _verified
from test_typed_inputs import _ASYNC, _CASES, _OUTSIDE_THE_CLAUSE, _SYNC, _answer, _Case
from wire.models import (
    DiscoveryRequest,
    DisputeRequest,
    DomainVerificationConfirmation,
    DomainVerificationRequest,
    GetAccountStatusRequest,
    PushResourcesRequest,
    RefreshCatalogRequest,
    ResourceQuery,
    SetReportingPolicyRequest,
    SetTenantFeeRateRequest,
)

import fora_sdk.sync as sync_client
from fora_sdk.client import AdminClient, CallError, CallErrorKind, ClientConfig, RawBody
from fora_sdk.core import sign_offer_jcs
from fora_sdk.resolvers import RegistrationRequirements

if TYPE_CHECKING:
    import httpx
    from pydantic import BaseModel

_FEE = {"tenant_id": "tenant-1", "fee_rate_bps": 250, "notes": "launch rate"}
_POLICY = {
    "tenant_id": "tenant-1",
    "required_fields": ["consumed_quantity"],
    "window_seconds": 3600,
}
_ADMIN_CASES = [
    _Case("set_tenant_fee_rate", "AdminClient", SetTenantFeeRateRequest, {"rate": _FEE}),
    _Case("set_reporting_policy", "AdminClient", SetReportingPolicyRequest, {"policy": _POLICY}),
    _Case("request_domain_verification", "AdminClient", DomainVerificationRequest,
          {"exchange": "exchange.test", "domain": "publisher.example"}),
    _Case("confirm_domain_verification", "AdminClient", DomainVerificationConfirmation,
          {"exchange": "exchange.test", "domain": "publisher.example", "token": "tok-1"}),
]
_ALL = [*_CASES, *_ADMIN_CASES]
_ALL_IDS = [f"{c.verb}-{i}" for i, c in enumerate(_ALL)]

#: The admin setters answer the setting they stored, which their responses require. Every
#: other verb reads the shared answer.
_ANSWERS = {
    "set_tenant_fee_rate": {"ver": "1.0", "rate": _FEE},
    "set_reporting_policy": {"ver": "1.0", "policy": _POLICY},
}

_ASYNC_FACES = {**_ASYNC, "AdminClient": AdminClient}
_SYNC_FACES = {**_SYNC, "AdminClient": sync_client.AdminClient}

_URIS = ["https://site.test/a"]
#: The configured requester with a misspelled key, and how the refusal names it.
_MISSPELLED = {**REQUESTER, "domian": "agent.test"}
_NAMED = (
    "strict_requests refused the request at /requester: "
    "Additional properties are not allowed ('domian' was unexpected)"
)


class _Probe:
    """An endpoint resolver, a requirements reader and a pre-signing hook in one, each of
    which records that it was reached. A refusal made before all of them leaves
    ``reached`` empty: nothing was resolved, read or signed."""

    def __init__(self) -> None:
        self.reached: list[str] = []

    def resolve_endpoint(self, host: str) -> str:
        self.reached.append(f"resolve {host}")
        return "https://exchange.test"

    def resolve_registration_requirements(self, exchange: str) -> RegistrationRequirements:
        self.reached.append(f"read {exchange}")
        return RegistrationRequirements()

    def before_sign(self, request: httpx.Request) -> httpx.Request:
        self.reached.append("sign")
        return request

    def config(self, **overrides: Any) -> ClientConfig:
        return _config(
            endpoint_resolver=self,
            registration_requirements=self,
            before_sign=self.before_sign,
            **overrides,
        )


def _client(face: Face, face_class: str, config: ClientConfig, rec: Recorder) -> Any:
    if face.name == "async":
        return _ASYNC_FACES[face_class](config, http=rec.async_())
    return _SYNC_FACES[face_class](config, http=rec.sync())


def _recorder(verb: str) -> Recorder:
    return Recorder(_ANSWERS.get(verb) or _answer())


def _send(face: Face, case: _Case, message: Any, config: ClientConfig) -> Recorder:
    rec = _recorder(case.verb)
    face.run(getattr(_client(face, case.face_class, config, rec), case.verb)(message))
    return rec


def _refused(face: Face, case: _Case, message: Any, config: ClientConfig) -> str:
    """The refusal's text, after checking it is MALFORMED and that nothing was sent."""
    rec = _recorder(case.verb)
    with pytest.raises(CallError) as caught:
        face.run(getattr(_client(face, case.face_class, config, rec), case.verb)(message))
    assert caught.value.kind is CallErrorKind.MALFORMED
    assert rec.seen == []
    return str(caught.value)


def _another(model: type[BaseModel]) -> BaseModel:
    """A valid model of some other request message than ``model``."""
    other = RefreshCatalogRequest if model is GetAccountStatusRequest else GetAccountStatusRequest
    return other(exchange="exchange.test")


@pytest.mark.parametrize("face", FACES, ids=_IDS)
@pytest.mark.parametrize("case", _ALL, ids=_ALL_IDS)
def test_a_plain_dict_is_refused_before_anything_is_resolved_signed_or_sent(
    face: Face, case: _Case
) -> None:
    probe = _Probe()
    refusal = _refused(face, case, dict(case.message), probe.config(strict_requests=True))

    assert refusal.endswith(
        f"strict_requests refuses a plain dict; pass wire.models.{case.model.__name__}, "
        "or RawBody to send a body exactly as given"
    )
    assert probe.reached == []
    # The same dict with the switch off is signed and sent, so the probe's silence above
    # is the refusal's doing.
    control = _Probe()
    assert len(_send(face, case, dict(case.message), control.config()).seen) == 1
    assert "sign" in control.reached


@pytest.mark.parametrize("face", FACES, ids=_IDS)
@pytest.mark.parametrize("case", _ALL, ids=_ALL_IDS)
def test_a_model_of_another_message_is_refused_the_same_way(face: Face, case: _Case) -> None:
    other = _another(case.model)
    probe = _Probe()
    refusal = _refused(face, case, other, probe.config(strict_requests=True))

    assert refusal.endswith(
        f"strict_requests refuses a value of type {type(other).__name__}; "
        f"pass wire.models.{case.model.__name__}, or RawBody to send a body exactly as given"
    )
    assert probe.reached == []


@pytest.mark.parametrize("face", FACES, ids=_IDS)
@pytest.mark.parametrize("case", _ALL, ids=_ALL_IDS)
def test_the_model_sends_the_same_bytes_with_the_switch_on_as_off(
    face: Face, case: _Case
) -> None:
    model = case.model.model_validate(case.message)

    on = _send(face, case, model, _account_config(strict_requests=True))
    off = _send(face, case, model, _account_config())

    assert len(on.seen) == len(off.seen) == 1
    assert on.seen[0].url == off.seen[0].url
    assert on.seen[0].content == off.seen[0].content


@pytest.mark.parametrize("face", FACES, ids=_IDS)
@pytest.mark.parametrize("case", _ALL, ids=_ALL_IDS)
def test_a_raw_body_is_sent_exactly_as_given(face: Face, case: _Case) -> None:
    """Raw mode is how a test puts a message the SDK would never build on the wire, so the
    switch does not reach it: no member is checked and none is added."""
    body = json.dumps({**case.message, "not_a_member": True}).encode()

    rec = _send(face, case, RawBody(body), _account_config(strict_requests=True))

    assert [r.content for r in rec.seen] == [body]


def _call_naming_the_requester(face: Face, verb: str, config: ClientConfig, rec: Recorder) -> None:
    """Run a verb that stamps the configured requester onto what it sends. A purchase
    always does. A query does when its message names none, which a model can only leave
    unset when it is built with ``model_construct``, skipping validation."""
    if verb == "discover":
        query = ResourceQuery.model_construct(exchange="exchange.test", uris=_URIS)
        face.run(face.client(config, rec).discover(query))
    elif verb == "resolve":
        request = DiscoveryRequest.model_construct(query="jazz", uris=_URIS)
        face.run(face.broker(config, rec).resolve(request))
    else:
        offer, public = _offer()
        face.run(face.client(config, rec).execute(_verified(public, offer), idempotency_key="i"))


@pytest.mark.parametrize("face", FACES, ids=_IDS)
@pytest.mark.parametrize("verb", ["discover", "resolve", "execute"])
def test_an_unknown_member_of_the_configured_requester_is_refused_and_named(
    face: Face, verb: str
) -> None:
    """The requester is configuration the client stamps, not a model the caller built, so
    only the check of the stamped message can see a key misspelled in it."""
    rec = Recorder(_answer())
    with pytest.raises(CallError) as caught:
        _call_naming_the_requester(
            face, verb, _config(requester=_MISSPELLED, strict_requests=True), rec
        )
    assert caught.value.kind is CallErrorKind.MALFORMED
    assert str(caught.value).endswith(_NAMED)
    assert rec.seen == []
    # With the switch off the model ignores the key, and it goes out on the wire.
    rec = Recorder(_answer())
    _call_naming_the_requester(face, verb, _config(requester=_MISSPELLED), rec)
    assert rec.body()["requester"]["domian"] == "agent.test"


def _offer(**extra: Any) -> tuple[dict[str, Any], bytes]:
    """A signed offer, with any extra members inside the signature, and its public key."""
    seed = bytes([7]) * 32
    offer: dict[str, Any] = {
        "offer_id": "offer-1",
        "exchange": "exchange.test",
        "expires_at": "2099-01-01T00:00:00Z",
        **extra,
    }
    signature, algorithm = sign_offer_jcs(seed=seed, offer=offer)
    public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    return {**offer, "signature": signature, "signature_algorithm": algorithm}, public


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_reflected_offer_carrying_a_member_this_sdk_does_not_know_is_refused(
    face: Face,
) -> None:
    """A purchase reflects each offer exactly as discovery returned it, so an offer from a
    newer minor version carries its new member into the request. Its signature verifies;
    the switch refuses the message all the same, naming where the member sits."""
    offer, public = _offer(future_member="x")
    verified = _verified(public, offer)

    rec = Recorder(_answer())
    with pytest.raises(CallError) as caught:
        face.run(
            face.client(_config(strict_requests=True), rec).execute(verified, idempotency_key="i")
        )
    assert caught.value.kind is CallErrorKind.MALFORMED
    assert str(caught.value).endswith(
        "strict_requests refused the request at /items/0/offer: "
        "Additional properties are not allowed ('future_member' was unexpected)"
    )
    assert rec.seen == []
    # With the switch off it is reflected as received, which is what a purchase does.
    rec = Recorder(_answer())
    face.run(face.client(_config(), rec).execute(verified, idempotency_key="i"))
    assert rec.body()["items"][0]["offer"]["future_member"] == "x"


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_cross_field_rule_the_model_does_not_check_is_refused(face: Face) -> None:
    """A catalog term carries its price (``resource_entry.terms.pricing_required``). The
    generated model checks each field, not rules across them, so without the switch the
    push is sent and only the server can refuse it."""
    case = _Case("push_resources", "CatalogClient", PushResourcesRequest, {})
    message = PushResourcesRequest.model_validate({
        "entries": [{"domain": "publisher.test", "path": "/x",
                     "terms": [{"semantics": "TERM_SEMANTICS_ENUMERATED"}]}],
        "exchange": "exchange.test",
        "tenant_id": "tenant-1",
    })

    refusal = _refused(face, case, message, _account_config(strict_requests=True))

    assert refusal.endswith(
        "strict_requests refused the request: cross-field rule(s) "
        "resource_entry.terms.pricing_required"
    )
    assert len(_send(face, case, message, _account_config()).seen) == 1


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_validation_off_leaves_the_switch_in_force(face: Face) -> None:
    """``validation`` governs the generated model's check and nothing else: turning it off
    neither lets a plain dict through nor skips the check of the stamped message."""
    case = _CASES[0]
    assert case.verb == "discover"

    refusal = _refused(
        face, case, dict(case.message), _account_config(strict_requests=True, validation="off")
    )
    assert "strict_requests refuses a plain dict" in refusal

    query = ResourceQuery.model_construct(exchange="exchange.test", uris=_URIS)
    config = _account_config(strict_requests=True, validation="off", requester=_MISSPELLED)
    assert _refused(face, case, query, config).endswith(_NAMED)


def test_the_switch_is_off_by_default() -> None:
    assert ClientConfig(base_url="https://exchange.test").strict_requests is False


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_keyword_the_model_does_not_declare_is_dropped_before_the_switch_sees_it(
    face: Face,
) -> None:
    """The generated models ignore an undeclared member, the forward-compatible choice for
    an answer, so a misspelled keyword never reaches the SDK and the request goes out
    without it. A type checker reports the keyword, because the models are dataclass
    transforms; that is where this mistake is caught. Pinned so the documented gap stays
    the one described."""
    case = _Case("dispute", "Client", DisputeRequest, {})
    misspelled: dict[str, Any] = {
        "descripton": "never arrived",
        "exchange": "exchange.test",
        "idempotency_key": "idem-2",
        "reason": "DISPUTE_REASON_DELIVERY_FAILED",
        "report_id": "r-1",
        "transaction_id": "t-1",
    }

    sent = _send(face, case, DisputeRequest(**misspelled), _account_config(strict_requests=True))

    assert "descripton" not in sent.body()
    assert "description" not in sent.body()


@pytest.mark.parametrize("faces", [_ASYNC_FACES, _SYNC_FACES], ids=["async", "sync"])
def test_every_verb_that_takes_a_request_message_is_covered(faces: dict[str, Any]) -> None:
    """A verb added to a client face without a case here would take a plain dict under the
    switch untested. Every public verb is covered above or named as taking no message."""
    public = {
        name
        for cls in faces.values()
        for name, member in vars(cls).items()
        if not name.startswith("_") and inspect.isfunction(member)
    }

    assert {case.verb for case in _ALL} | set(_OUTSIDE_THE_CLAUSE) == public
