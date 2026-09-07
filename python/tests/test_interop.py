"""Cross-language canonicalisation contract.

The fixture is generated and verified by the Go implementation, and the
TypeScript SDK asserts against the same bytes. If this suite fails, the
Python canonicaliser has diverged — and divergence presents as a signature
failure indistinguishable from tampering, which is why the canonical bytes
are compared directly rather than only via signature success.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from lyntway import canonicalize, signing_input, verify
from lyntway.receipt import TRUNCATED_WARNING
from lyntway.canonical import CanonicalizationError


def _find_fixture() -> Path:
    """Locate the shared fixture by walking up from this file.

    A fixed relative path would break the moment the layout changed, and the
    failure would look like a missing fixture rather than a path bug.
    """
    directory = Path(__file__).resolve().parent
    for _ in range(8):
        candidate = directory / "testdata" / "interop" / "receipts.json"
        if candidate.exists():
            return candidate
        directory = directory.parent
    raise FileNotFoundError("could not locate testdata/interop/receipts.json")


FIXTURE = json.loads(_find_fixture().read_text())
KEYS = {FIXTURE["keyId"]: FIXTURE["publicKey"]}
RECEIPTS = FIXTURE["receipts"]


def test_canonical_bytes_are_byte_identical_to_go() -> None:
    for receipt, expected in zip(RECEIPTS, FIXTURE["signingInputs"]):
        actual = signing_input(receipt).decode("utf-8")
        assert actual == expected, (
            f"receipt {receipt['id']}: Python canonicalisation diverged from Go"
        )


def test_every_go_signed_receipt_verifies() -> None:
    for receipt in RECEIPTS:
        result = verify(receipt, KEYS)
        assert result.valid, f"receipt {receipt['id']} failed: {result.error}"


def test_degraded_receipt_verifies_but_is_not_full_strength() -> None:
    degraded = next(r for r in RECEIPTS if r["governance"]["mode"] == "degraded")
    result = verify(degraded, KEYS)

    assert result.valid, "a degraded receipt must still verify"
    assert not result.full_strength, "a degraded receipt reported full strength"
    assert any("ml-sidecar" in w for w in result.warnings), (
        f"warnings do not name the failed component: {result.warnings}"
    )


def test_tampering_is_detected() -> None:
    tampered = json.loads(json.dumps(RECEIPTS[0]))
    tampered["governance"]["findings"] = []
    assert not verify(tampered, KEYS).valid


def test_wrong_public_key_is_rejected() -> None:
    wrong = {FIXTURE["keyId"]: base64.b64encode(bytes(32)).decode()}
    assert not verify(RECEIPTS[0], wrong).valid


def test_unknown_key_id_is_reported() -> None:
    result = verify(RECEIPTS[0], {})
    assert not result.valid
    assert "not known to this verifier" in (result.error or "")


def test_require_full_strength_rejects_degraded() -> None:
    degraded = next(r for r in RECEIPTS if r["governance"]["mode"] == "degraded")
    assert not verify(degraded, KEYS, require_full_strength=True).valid


def test_max_age_is_enforced() -> None:
    result = verify(RECEIPTS[0], KEYS, max_age=timedelta(microseconds=1))
    assert not result.valid
    assert "older than" in (result.error or "")


def test_result_is_falsy_when_invalid() -> None:
    assert not bool(verify(RECEIPTS[0], {}))
    assert bool(verify(RECEIPTS[0], KEYS))


# --- Canonicalisation edge cases -------------------------------------------


def test_rejects_non_integral_numbers() -> None:
    with pytest.raises(CanonicalizationError, match="floating-point"):
        canonicalize({"x": 1.5})
    # Integral values expressed as floats are fine: one unambiguous form.
    assert canonicalize({"x": 42.0}) == '{"x":42}'


def test_does_not_escape_html_characters() -> None:
    # Many encoders escape these for HTML safety; RFC 8785 does not, and
    # escaping them would break interoperability.
    assert canonicalize('<a href="x">&') == '"<a href=\\"x\\">&"'


def test_sorts_keys_by_utf16_code_unit() -> None:
    assert canonicalize({"b": 1, "a": 2, "C": 3, "A": 5}) == '{"A":5,"C":3,"a":2,"b":1}'


def test_utf16_ordering_differs_from_code_point_ordering() -> None:
    # U+1F600 is supplementary and encodes as a surrogate pair starting at
    # 0xD800, so by UTF-16 code unit it sorts BEFORE U+FB00 — the opposite of
    # a naive code-point sort.
    assert canonicalize({"\U0001F600": 1, "ﬀ": 2}) == '{"\U0001F600":1,"ﬀ":2}'


def test_booleans_are_not_serialised_as_integers() -> None:
    # bool subclasses int in Python; without an explicit check True would
    # serialise as 1 and silently change the signed bytes.
    assert canonicalize({"a": True, "b": False}) == '{"a":true,"b":false}'


def test_control_characters_use_lowercase_hex_escapes() -> None:
    assert canonicalize("\x00\x1f") == '"\\u0000\\u001f"'


def _attested():
    """The per-tenant signing block of the shared fixture."""
    block = FIXTURE.get("attested")
    assert block, "fixture holds no attested receipts; the SDK is not held to this contract"
    return block


def test_attested_receipts_verify_with_the_root_key_alone() -> None:
    """A per-tenant receipt must verify against the deployment key only.

    No tenant key is ever published, so a verifier holding one receipt must
    be able to check it without learning that any other customer exists.
    """
    block = _attested()
    roots = {block["rootKeyId"]: block["rootPublicKey"]}
    now = datetime(2026, 8, 14, 12, 0, 0, tzinfo=timezone.utc)

    for receipt_json in block["receipts"]:
        assert receipt_json["issuer"].get("key_attestation"), "receipt carries no attestation"
        assert receipt_json["signature"]["key_id"] != block["rootKeyId"], (
            "receipt is signed by the root key, so it does not exercise attestation"
        )
        result = verify(receipt_json, roots, now=now)
        assert result.valid, f"attested receipt did not verify: {result.error}"
        assert result.key_id == block["tenantKeyId"]


def test_attested_receipt_cannot_move_to_another_chain() -> None:
    """The property that separates one customer from another."""
    block = _attested()
    roots = {block["rootKeyId"]: block["rootPublicKey"]}
    now = datetime(2026, 8, 14, 12, 0, 0, tzinfo=timezone.utc)

    moved = json.loads(json.dumps(block["receipts"][0]))
    moved["chain"]["id"] = "northbay/ws_elsewhere"

    result = verify(moved, roots, now=now)
    assert not result.valid, "a receipt moved onto another customer's chain verified"


def test_stripped_attestation_is_rejected() -> None:
    """Removing the attestation must not fall back to trusting the key ID."""
    block = _attested()
    roots = {block["rootKeyId"]: block["rootPublicKey"]}
    now = datetime(2026, 8, 14, 12, 0, 0, tzinfo=timezone.utc)

    stripped = json.loads(json.dumps(block["receipts"][0]))
    stripped["issuer"].pop("key_attestation")

    result = verify(stripped, roots, now=now)
    assert not result.valid, "a receipt with its attestation removed verified"


def _es256():
    """The ECDSA P-256 block of the shared fixture."""
    block = FIXTURE.get("es256")
    assert block, "fixture holds no ES256 receipts; this SDK is not held to the contract"
    return block


def test_es256_receipts_verify() -> None:
    """Algorithm agility is only real if every SDK can check the second one.

    A deployment whose signing key lives in an HSM will use P-256, and its
    customers' SDKs must not then reject every receipt it issues.
    """
    block = _es256()
    keys = {block["keyId"]: block["publicKey"]}
    now = datetime(2026, 8, 14, 12, 0, 0, tzinfo=timezone.utc)

    for receipt_json in block["receipts"]:
        assert receipt_json["signature"]["algorithm"] == "es256"
        result = verify(receipt_json, keys, now=now)
        assert result.valid, f"ES256 receipt did not verify: {result.error}"
        assert result.algorithm == "es256"


def test_es256_canonical_bytes_match_go() -> None:
    """ECDSA is randomised, so a signature match alone would not prove the
    two implementations agree on what was signed."""
    block = _es256()
    for receipt_json, expected in zip(block["receipts"], block["signingInputs"]):
        assert signing_input(receipt_json).decode("utf-8") == expected


def test_es256_tampered_signature_is_rejected() -> None:
    block = _es256()
    keys = {block["keyId"]: block["publicKey"]}
    now = datetime(2026, 8, 14, 12, 0, 0, tzinfo=timezone.utc)

    tampered = json.loads(json.dumps(block["receipts"][0]))
    raw = bytearray(base64.b64decode(tampered["signature"]["value"]))
    raw[0] ^= 0x01
    tampered["signature"]["value"] = base64.b64encode(bytes(raw)).decode()

    assert not verify(tampered, keys, now=now).valid


SUBJECT_PHRASE = "a record about the traffic, not the traffic itself"


def _signed_receipt(shape) -> tuple[dict, dict[str, str]]:
    """A receipt whose digests cover a record about the traffic.

    Signed here rather than taken from the fixture so the shape is visible: a
    tunnel receipt is first-hand about the connection, carries no findings
    and no transform, and never read the bytes.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    key_id = "key-test-subject"

    receipt = json.loads(json.dumps(RECEIPTS[0]))
    receipt.pop("signature", None)
    receipt.pop("anchors", None)
    receipt["issuer"]["key_id"] = key_id
    receipt["governance"]["decision"] = "allow"
    receipt["governance"]["findings"] = []
    receipt["evidence"] = {"provenance": "observed", "vantage": "proxy"}
    shape(receipt)

    signature = private.sign(signing_input(receipt))
    receipt["signature"] = {
        "key_id": key_id,
        "algorithm": "ed25519",
        "canonicalization": "jcs",
        "value": base64.b64encode(signature).decode("ascii"),
    }
    return receipt, {key_id: base64.b64encode(raw).decode("ascii")}


def test_metadata_receipt_is_reported_as_a_record_about_the_traffic() -> None:
    receipt, keys = _signed_receipt(lambda r: r["content"].update(subject="metadata"))
    result = verify(receipt, keys)
    assert result.valid, f"metadata receipt did not verify: {result.error}"
    qualified = [w for w in result.warnings if SUBJECT_PHRASE in w]
    assert qualified, f"no warning qualifies the digest: {result.warnings!r}"
    assert "without reading them" in qualified[0]
    assert result.subject == "metadata"
    # Observed stays: the issuer did handle the connection. The warning is
    # what stops "observed" beside a digest from reading as a hash of content.
    assert result.provenance == "observed"


def test_unknown_subject_reads_as_not_the_data() -> None:
    receipt, keys = _signed_receipt(lambda r: r["content"].update(subject="headers"))
    result = verify(receipt, keys)
    assert result.valid, f"receipt with an unknown subject did not verify: {result.error}"
    qualified = [w for w in result.warnings if SUBJECT_PHRASE in w]
    assert qualified, (
        f"an unknown subject was shown as if it were the data: {result.warnings!r}"
    )
    assert "'headers'" in qualified[0]
    assert result.subject == "headers"


def test_payload_receipt_is_not_qualified() -> None:
    for receipt in RECEIPTS:
        result = verify(receipt, KEYS)
        assert result.valid
        assert not any(SUBJECT_PHRASE in w for w in result.warnings), (
            f"a payload receipt was qualified as if it were not the data: {result.warnings!r}"
        )
        assert result.subject == "payload"


def test_truncated_stream_is_reported_as_cut() -> None:
    """The one receipt that carries "block" beside an output digest.

    The prefix was released before the refused class appeared, so its digest
    is exactly what the receipt must show, and the reader must be told why.
    """

    def cut(r: dict) -> None:
        r["governance"]["decision"] = "block"
        r["content"]["truncated"] = True

    receipt, keys = _signed_receipt(cut)
    assert receipt["content"].get("output_digest"), "the fixture carries no output digest to keep"
    result = verify(receipt, keys)
    assert result.valid, f"truncated receipt did not verify: {result.error}"
    assert TRUNCATED_WARNING in result.warnings, (
        f"the cut stream was not reported: {result.warnings!r}"
    )
    assert result.truncated is True

    for complete in RECEIPTS:
        outcome = verify(complete, KEYS)
        assert TRUNCATED_WARNING not in outcome.warnings, "a complete receipt was reported as cut"
        assert outcome.truncated is False
