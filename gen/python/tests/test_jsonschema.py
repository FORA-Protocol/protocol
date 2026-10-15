"""The published JSON Schemas (gen/jsonschema/), read through the package loader.

wire.schemas.load is how a Python consumer reaches the schemas at the pinned version, so
every assertion here goes through it. The validator is jsonschema's draft 2020-12 engine,
the dialect the schemas declare.

What is pinned:
  - the loader resolves every contract message in both variants, and refuses a name it
    does not ship;
  - the strict variant refuses an unknown field at the top level and nested, and refuses
    a camelCase alias, while the default variant accepts both (forward compatibility);
  - google.protobuf.Struct (`ext`) stays open in the strict variant, at any depth;
  - buf.validate constraints fail the schema: an empty required string, an omitted
    required field, a numeric bound in either 64-bit integer form;
  - both variants reach Go protovalidate's verdict on every case of the conformance
    corpus, the same oracle the generated Pydantic and Zod models are held to.

Run:  PYTHONPATH=gen/python python3 -m pytest gen/python/tests/test_jsonschema.py -q
"""
import copy
import json
import pathlib

import pytest
from jsonschema import Draft202012Validator

from wire import schemas

ROOT = pathlib.Path(__file__).resolve().parents[3]
CASES = json.loads((ROOT / "conformance" / "corpus" / "cases.json").read_text())
BY_BARE = {n.rsplit(".", 1)[1]: n for n in schemas.names()}

OFFER = next(c["json"] for c in CASES if c["id"] == "Offer/valid")
RESPONSE = {"exchange": "exchange.example", "offers": [OFFER]}


def accepts(name, instance, strict):
    schema = schemas.load(name, strict=strict)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema).is_valid(instance)


def with_offer(**extra):
    body = copy.deepcopy(RESPONSE)
    body["offers"][0].update(extra)
    return body


def test_loader_resolves_every_message_in_both_variants():
    names = schemas.names()
    assert "fora.v1.ResourceResponse" in names
    assert "fora.admin.v1.ReportingPolicy" in names
    for name in names:
        assert schemas.load(name)["$id"] == f"{name}.schema.json"
        assert schemas.load(name, strict=True)["$id"] == f"{name}.schema.strict.json"


def test_loader_refuses_an_unknown_name():
    with pytest.raises(KeyError):
        schemas.load("fora.v1.NoSuchMessage")
    with pytest.raises(KeyError):
        schemas.load("../jsonschema/fora.v1.ResourceResponse")


def test_loader_returns_a_fresh_copy():
    schemas.load("fora.v1.ResourceResponse")["properties"].clear()
    assert "exchange" in schemas.load("fora.v1.ResourceResponse")["properties"]


def test_valid_message_passes_both_variants():
    assert accepts("fora.v1.ResourceResponse", RESPONSE, strict=False)
    assert accepts("fora.v1.ResourceResponse", RESPONSE, strict=True)


@pytest.mark.parametrize(
    "body",
    [
        {**RESPONSE, "unknown_field": 1},  # top level
        with_offer(unknown_field=1),  # inside a nested message
        {**RESPONSE, "offerGroups": []},  # the camelCase alias of offer_groups
    ],
    ids=["top-level", "nested", "camelCase-alias"],
)
def test_strict_refuses_an_unknown_field_and_default_accepts_it(body):
    assert not accepts("fora.v1.ResourceResponse", body, strict=True)
    assert accepts("fora.v1.ResourceResponse", body, strict=False)


def test_strict_keeps_struct_open_at_any_depth():
    ext = {"vendor": {"nested": {"deeper": [1, "two"]}}, "flag": True}
    body = with_offer(ext=ext)
    body["ext"] = ext
    assert accepts("fora.v1.ResourceResponse", body, strict=True)


@pytest.mark.parametrize("strict", [False, True], ids=["default", "strict"])
def test_empty_required_string_fails(strict):
    # exchange carries a non-empty pattern: Go protovalidate rejects "".
    assert not accepts("fora.v1.ResourceResponse", {"exchange": ""}, strict)
    # proto-JSON omits a zero value, so omission is the same "" and fails too.
    assert not accepts("fora.v1.ResourceResponse", {}, strict)


@pytest.mark.parametrize("strict", [False, True], ids=["default", "strict"])
@pytest.mark.parametrize(
    "limit,valid",
    [("1", True), (1, True), ("9007199254740993", True), ("0", False), (0, False),
     ("-1", False), ("1.5", False), ("one", False)],
)
def test_int64_accepts_both_forms_and_enforces_the_bound_on_each(limit, valid, strict):
    # Quota.limit is int64 with gte 1. Canonical proto-JSON emits it as a decimal string;
    # the SDKs send a JSON number.
    quota = {"limit": limit, "metric": "accesses", "window": "QUOTA_WINDOW_DAILY"}
    assert accepts("fora.v1.Quota", quota, strict) is valid


@pytest.mark.parametrize("strict", [False, True], ids=["default", "strict"])
def test_bounded_double_has_no_string_bypass(strict):
    # quantity_tolerance is a double bounded to [0, 1]; the string form is not accepted,
    # so "1000" cannot get past the bound.
    base = {"tenant_id": "t"}
    assert accepts("fora.admin.v1.ReportingPolicy", {**base, "quantity_tolerance": 0.5}, strict)
    assert not accepts("fora.admin.v1.ReportingPolicy", {**base, "quantity_tolerance": 2}, strict)
    assert not accepts("fora.admin.v1.ReportingPolicy", {**base, "quantity_tolerance": "1000"}, strict)


@pytest.mark.parametrize("strict", [False, True], ids=["default", "strict"])
@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_schema_matches_go_verdict(case, strict):
    name = BY_BARE[case["message"]]
    accepted = accepts(name, case["json"], strict)
    assert accepted == case["valid"], (
        f"{case['id']}: {name} ({'strict' if strict else 'default'}) accepted={accepted} "
        f"but Go verdict valid={case['valid']} (rules={case.get('rules')})"
    )
