"""The public document readers, driven against a real in-process origin.

Each reader fetches through the SDK's guarded client, so the suite relaxes the guards the
way a sandbox does (``SKIP_SSRF`` and ``ALLOW_INSECURE``) rather than injecting a plain
client: the path under test is the default one. One test leaves the guards on and shows
the loopback origin refused.

The verdicts on the bytes themselves are pinned across the three languages by the
document-check and license-digest corpora; this suite proves the readers reach those
checks over HTTP, and that each failure leaves as its typed error rather than as None.
"""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from resolvers_harness import (
    ANCHOR,
    LICENSE_PATH,
    MANIFEST_PATH,
    REVOCATION_PATH,
    WBA_DIR_PATH,
    Origin,
    active_jwk,
    make_key,
    manifest_json,
    revocation_json,
    rfc3339,
    wba_file_json,
)
from wire.models import License

from fora_sdk import StrictViolationError, check_strict
from fora_sdk.b64 import b64url_nopad
from fora_sdk.resolvers import (
    MANIFEST_MEDIA_TYPE,
    WBA_DIRECTORY_MEDIA_TYPE,
    DigestMismatchError,
    DirectoryResponseUnsignedError,
    DirectoryUnavailableError,
    ManifestVersionRefusedError,
    MediaTypeRefusedError,
    read_license_document,
    read_manifest,
    read_revocation_list,
    read_wba_directory,
)
from fora_sdk.resolvers._ssrf import SsrfError

if TYPE_CHECKING:
    from collections.abc import Iterator

LICENSE_TEXT = b"Licensed for retrieval-augmented answers, attribution required.\n"


@pytest.fixture
def origin(monkeypatch: pytest.MonkeyPatch) -> Iterator[Origin]:
    monkeypatch.setenv("SKIP_SSRF", "true")
    monkeypatch.setenv("ALLOW_INSECURE", "true")
    served = Origin()
    try:
        yield served
    finally:
        served.close()


@pytest.fixture
def other() -> Iterator[Origin]:
    """A second origin, the target of a redirect."""
    served = Origin()
    try:
        yield served
    finally:
        served.close()


def _license(origin: Origin, body: bytes = LICENSE_TEXT, method: str = "sha256") -> License:
    digest = hashlib.new(method, body).hexdigest()
    return License(uri=origin.license_url(), uri_digest=f"{method}:{digest}")


# --- manifest ---------------------------------------------------------------------------


def test_read_manifest_returns_the_parsed_manifest_and_its_media_type(origin: Origin) -> None:
    origin.set_manifest(manifest_json("https://" + origin.host + "/rpc"))
    doc = read_manifest(origin.host, scheme="http")
    assert doc.message.role is not None
    assert doc.message.role.value == "ROLE_EXCHANGE"
    assert doc.message.endpoint == "https://" + origin.host + "/rpc"
    assert doc.media_type == MANIFEST_MEDIA_TYPE
    assert doc.url == origin.url + MANIFEST_PATH


def test_read_manifest_accepts_media_type_parameters(origin: Origin) -> None:
    origin.set_manifest(manifest_json())
    origin.set_content_type(MANIFEST_PATH, "Application/JSON; charset=utf-8")
    assert read_manifest(origin.host, scheme="http").media_type == MANIFEST_MEDIA_TYPE


def test_read_manifest_refuses_an_unknown_member(origin: Origin) -> None:
    doc = json.loads(manifest_json())
    doc["endpoints"] = ["https://exchange.example/rpc"]  # misspelled endpoint
    origin.set_manifest(json.dumps(doc))
    with pytest.raises(StrictViolationError) as caught:
        read_manifest(origin.host, scheme="http")
    assert caught.value.message_name == "fora.v1.WellKnownManifest"
    assert "endpoints" in caught.value.violation


def test_read_manifest_refuses_a_broken_cross_field_rule(origin: Origin) -> None:
    doc = json.loads(manifest_json())
    doc["terms_digest"] = "sha256:" + "0" * 64  # a digest with no terms_uri
    origin.set_manifest(json.dumps(doc))
    with pytest.raises(StrictViolationError, match="cross-field"):
        read_manifest(origin.host, scheme="http")


def test_read_manifest_refuses_the_wrong_media_type(origin: Origin) -> None:
    origin.set_manifest(manifest_json())
    origin.set_content_type(MANIFEST_PATH, "text/plain")
    with pytest.raises(MediaTypeRefusedError, match="text/plain"):
        read_manifest(origin.host, scheme="http")


def test_read_manifest_refuses_a_missing_media_type(origin: Origin) -> None:
    origin.set_manifest(manifest_json())
    origin.set_content_type(MANIFEST_PATH, None)
    with pytest.raises(MediaTypeRefusedError, match="no media type"):
        read_manifest(origin.host, scheme="http")


def test_read_manifest_reads_the_version_before_anything_else(origin: Origin) -> None:
    doc = json.loads(manifest_json(ver="2.0"))
    doc["not_a_member"] = True  # would be a strict violation, but ver is read first
    origin.set_manifest(json.dumps(doc))
    with pytest.raises(ManifestVersionRefusedError):
        read_manifest(origin.host, scheme="http")


def test_read_manifest_reports_a_missing_document_as_unavailable(origin: Origin) -> None:
    origin.set_manifest_status(404)
    with pytest.raises(DirectoryUnavailableError):
        read_manifest(origin.host, scheme="http")


def test_read_manifest_refuses_a_value_that_is_not_a_bare_host(origin: Origin) -> None:
    with pytest.raises(ValueError, match="not a bare host"):
        read_manifest(origin.host + "/elsewhere", scheme="http")
    assert origin.manifest_hits() == 0


def test_read_manifest_dials_through_the_ssrf_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    """With the guards on, the default client refuses the loopback origin."""
    monkeypatch.delenv("SKIP_SSRF", raising=False)
    monkeypatch.setenv("ALLOW_INSECURE", "true")
    served = Origin()
    try:
        served.set_manifest(manifest_json())
        with pytest.raises(DirectoryUnavailableError) as caught:
            read_manifest(served.host, scheme="http")
        assert _caused_by(caught.value, SsrfError)
        assert served.manifest_hits() == 0
    finally:
        served.close()


def test_read_manifest_refuses_plaintext_without_the_relax(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SKIP_SSRF", "true")
    monkeypatch.delenv("ALLOW_INSECURE", raising=False)
    served = Origin()
    try:
        served.set_manifest(manifest_json())
        with pytest.raises(DirectoryUnavailableError) as caught:
            read_manifest(served.host, scheme="http")
        assert _caused_by(caught.value, SsrfError)
        assert served.manifest_hits() == 0
    finally:
        served.close()


# --- WBA directory ----------------------------------------------------------------------


def test_read_wba_directory_by_domain_and_by_url(origin: Origin) -> None:
    key = make_key()
    origin.set_wba(wba_file_json([active_jwk(key.x)], origin.revocation_url()))
    origin.set_content_type(WBA_DIR_PATH, WBA_DIRECTORY_MEDIA_TYPE)
    by_domain = read_wba_directory(origin.host, scheme="http")
    by_url = read_wba_directory(origin.url + WBA_DIR_PATH)
    for doc in (by_domain, by_url):
        assert [k.x for k in doc.message.keys or []] == [key.x]
        assert doc.message.revocation_url == origin.revocation_url()
        assert doc.media_type == WBA_DIRECTORY_MEDIA_TYPE
        assert doc.url == origin.url + WBA_DIR_PATH


@pytest.mark.parametrize("served", ["application/json", "application/jwk-set+json", None])
def test_read_wba_directory_refuses_any_other_media_type(
    origin: Origin, served: str | None
) -> None:
    origin.set_wba(wba_file_json([active_jwk(make_key().x)]))
    origin.set_content_type(WBA_DIR_PATH, served)
    with pytest.raises(MediaTypeRefusedError, match="http-message-signatures-directory"):
        read_wba_directory(origin.host, scheme="http")


def test_read_wba_directory_refuses_a_key_that_did_not_sign_the_response(
    origin: Origin,
) -> None:
    # One listed key signed, the other was minted outside the harness and did not: the
    # public reader requires every listed key to have signed.
    signed = make_key()
    unsigned = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    origin.set_wba(wba_file_json([active_jwk(signed.x), active_jwk(b64url_nopad(unsigned))]))
    with pytest.raises(DirectoryResponseUnsignedError, match="1 of 2"):
        read_wba_directory(origin.host, scheme="http")


def test_read_wba_directory_refuses_a_redirect(origin: Origin, other: Origin) -> None:
    # The directory's address is the origin its signer committed to: a redirect would
    # hand key lookup to another one, so the reader never follows it.
    other.set_wba(wba_file_json([active_jwk(make_key().x)]))
    origin.set_redirect(WBA_DIR_PATH, other.url + WBA_DIR_PATH)
    with pytest.raises(DirectoryUnavailableError):
        read_wba_directory(origin.host, scheme="http")


def test_read_wba_directory_refuses_a_key_carrying_a_kid(origin: Origin) -> None:
    jwk = active_jwk(make_key().x)
    jwk["kid"] = "k1"  # the directory identifies keys by thumbprint, never by kid
    origin.set_wba(wba_file_json([jwk]))
    origin.set_content_type(WBA_DIR_PATH, WBA_DIRECTORY_MEDIA_TYPE)
    with pytest.raises(StrictViolationError, match="kid"):
        read_wba_directory(origin.host, scheme="http")


def test_read_wba_directory_reports_an_unpublished_directory(origin: Origin) -> None:
    with pytest.raises(DirectoryUnavailableError):
        read_wba_directory(origin.host, scheme="http")


# --- revocation list --------------------------------------------------------------------


def test_read_revocation_list_returns_the_snapshot(origin: Origin) -> None:
    tp = make_key().tp
    origin.set_revocation(revocation_json(ANCHOR, [tp]))
    doc = read_revocation_list(origin.revocation_url())
    assert doc.message.revoked == [tp]
    assert doc.message.as_of == ANCHOR
    assert doc.url == origin.url + REVOCATION_PATH


def test_read_revocation_list_follows_a_redirect(origin: Origin, other: Origin) -> None:
    # Unlike a key directory, a revocation list may move: the reader follows the
    # redirect to the document.
    tp = make_key().tp
    other.set_revocation(revocation_json(ANCHOR, [tp]))
    origin.set_redirect(REVOCATION_PATH, other.revocation_url())
    assert read_revocation_list(origin.revocation_url()).message.revoked == [tp]


def test_read_revocation_list_refuses_an_unknown_member(origin: Origin) -> None:
    origin.set_revocation(json.dumps({"as_of": rfc3339(ANCHOR), "revoked": [], "next": "x"}))
    with pytest.raises(StrictViolationError, match="next"):
        read_revocation_list(origin.revocation_url())


def test_read_revocation_list_refuses_a_timestamp_that_is_not_rfc3339(origin: Origin) -> None:
    origin.set_revocation(json.dumps({"as_of": "yesterday", "revoked": []}))
    with pytest.raises(StrictViolationError, match="as_of"):
        read_revocation_list(origin.revocation_url())


# --- license document -------------------------------------------------------------------


@pytest.mark.parametrize("method", ["sha256", "sha384", "sha512"])
def test_read_license_document_verifies_the_digest(origin: Origin, method: str) -> None:
    origin.set_license(LICENSE_TEXT)
    origin.set_content_type(LICENSE_PATH, "text/plain; charset=utf-8")
    lic = _license(origin, method=method)
    doc = read_license_document(lic)
    assert doc.body == LICENSE_TEXT
    assert doc.digest == lic.uri_digest
    assert doc.media_type == "text/plain"
    assert doc.url == origin.license_url()


def test_read_license_document_refuses_a_digest_mismatch(origin: Origin) -> None:
    lic = _license(origin)
    origin.set_license(LICENSE_TEXT + b"Amended after the offer was signed.\n")
    with pytest.raises(DigestMismatchError):
        read_license_document(lic)


def test_read_license_document_refuses_a_uri_without_a_digest(origin: Origin) -> None:
    origin.set_license(LICENSE_TEXT)
    with pytest.raises(StrictViolationError, match=r"license\.digest_required_with_uri"):
        read_license_document(License(uri=origin.license_url()))


def test_read_license_document_refuses_a_license_with_no_uri() -> None:
    with pytest.raises(ValueError, match="no uri"):
        read_license_document(License(id="CC-BY-4.0"))


def test_read_license_document_reports_a_scheme_it_will_not_dial() -> None:
    lic = License(uri="tdl:ai-terms/2026", uri_digest="sha256:" + "0" * 64)
    with pytest.raises(DirectoryUnavailableError):
        read_license_document(lic)


# --- the public strict check ------------------------------------------------------------


def test_check_strict_accepts_a_valid_message_and_names_a_violation() -> None:
    check_strict("fora.v1.KeyRevocationList", {"as_of": rfc3339(ANCHOR), "revoked": []})
    with pytest.raises(StrictViolationError) as caught:
        check_strict("fora.v1.KeyRevocationList", {"revokedd": []})
    assert caught.value.message_name == "fora.v1.KeyRevocationList"
    assert "revokedd" in caught.value.violation


def test_check_strict_refuses_the_lower_camel_spelling() -> None:
    with pytest.raises(StrictViolationError, match="termsUri"):
        check_strict("fora.v1.WellKnownManifest", {"role": "ROLE_EXCHANGE", "termsUri": "x"})


def test_check_strict_reads_null_as_absent() -> None:
    check_strict("fora.v1.WellKnownManifest", {"role": "ROLE_EXCHANGE", "endpoint": None})


def test_check_strict_raises_for_a_message_with_no_schema() -> None:
    with pytest.raises(KeyError):
        check_strict("fora.v1.NoSuchMessage", {})


def _caused_by(exc: BaseException, kind: type[BaseException]) -> bool:
    seen: BaseException | None = exc
    while seen is not None:
        if isinstance(seen, kind):
            return True
        seen = seen.__cause__ or seen.__context__
    return False
