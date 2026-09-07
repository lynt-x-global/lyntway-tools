"""Receipt verification.

Verification uses ``cryptography``'s Ed25519 rather than a bundled curve
implementation. Python's standard library has no Ed25519, and this code
decides whether evidence is genuine — an SDK other people embed is the wrong
place to save a dependency on hand-rolled elliptic curve arithmetic.

That is the only runtime dependency. HTTP uses ``urllib`` from the standard
library.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonical_bytes

__all__ = [
    "SCHEMA_VERSION",
    "VerificationResult",
    "verify",
    "signing_input",
    "is_full_strength",
]

#: Receipt schema version this SDK understands.
SCHEMA_VERSION = "lyntway-receipt/1"

#: Default tolerance for receipts issued slightly in the future, matching the
#: compliance profile's 300-second limit.
DEFAULT_CLOCK_SKEW = timedelta(seconds=300)


@dataclass
class VerificationResult:
    """The outcome of verifying a receipt."""

    #: The signature verified and the schema is sound.
    valid: bool

    #: Governance ran at full strength with a healthy detector.
    #:
    #: Any interface showing a "verified" badge must consult this rather than
    #: :attr:`valid`. A receipt can be cryptographically perfect and still
    #: attest that governance was bypassed; a badge driven by ``valid`` alone
    #: claims more than the receipt does.
    full_strength: bool = False

    mode: str | None = None
    decision: str | None = None
    key_id: str | None = None
    provenance: str | None = None
    vantage: str | None = None
    algorithm: str | None = None
    issued_at: datetime | None = None

    #: SHA-256 of the signing input, lowercase hex.
    digest: str | None = None

    #: What the receipt's own digests cover. Anything but ``payload`` means a
    #: record about the traffic, and :attr:`provenance` then describes how
    #: the issuer knew of the connection, not that it read the content.
    subject: str | None = None

    #: The stream was cut by policy; the digests cover the delivered prefix
    #: only. Such a receipt carries ``block`` beside an output digest, which
    #: on any other receipt would be a contradiction.
    truncated: bool = False

    #: Conditions that do not invalidate the receipt but must be surfaced.
    warnings: list[str] = field(default_factory=list)

    #: Why verification failed, when it did.
    error: str | None = None

    def __bool__(self) -> bool:
        return self.valid


def signing_input(receipt: Mapping[str, Any]) -> bytes:
    """Return the exact bytes a receipt's signature covers.

    Signature and anchors are excluded. A signature cannot cover itself, and
    anchors are obtained after signing — an anchor commits to the signed
    receipt, so if the receipt also committed to the anchor neither could be
    produced first.
    """
    unsigned = {k: v for k, v in receipt.items() if k not in ("signature", "anchors")}
    return canonical_bytes(unsigned)


def is_full_strength(receipt: Mapping[str, Any]) -> bool:
    """Report whether a receipt attests complete governance."""
    governance = receipt.get("governance") or {}
    detector = governance.get("detector") or {}
    return governance.get("mode") == "full" and detector.get("health") == "healthy"


def verify(
    receipt: Mapping[str, Any],
    keys: Mapping[str, str],
    *,
    max_age: timedelta | None = None,
    max_clock_skew: timedelta = DEFAULT_CLOCK_SKEW,
    require_full_strength: bool = False,
    now: datetime | None = None,
) -> VerificationResult:
    """Verify a receipt offline.

    Makes no network requests and requires no Lyntway account. Supply the
    issuer's public key — published at ``/.well-known/lyntway-keys.json``, or
    pinned however you prefer — and this checks the signature against the
    canonical signing input.

    :param receipt: The receipt, as decoded JSON.
    :param keys: Public keys by key ID, base64 or hex.
    :param max_age: Reject receipts issued longer ago than this.
    :param max_clock_skew: Tolerance for receipts issued in the future.
    :param require_full_strength: Treat degraded or bypassed governance as a
        failure. Off by default: a degraded receipt is honest evidence that
        partial governance ran, and discarding it would leave a hole in the
        record exactly where scrutiny is most warranted.
    :param now: Override the clock, for tests and historical verification.
    """

    def fail(error: str) -> VerificationResult:
        return VerificationResult(valid=False, error=error)

    if not isinstance(receipt, Mapping):
        return fail("not a receipt")
    if receipt.get("version") != SCHEMA_VERSION:
        return fail(f"unsupported receipt version {receipt.get('version')!r}")

    signature = receipt.get("signature")
    if not signature:
        return fail("no signature present")
    if signature.get("canonicalization") != "jcs":
        return fail(f"unsupported canonicalization {signature.get('canonicalization')!r}")

    algorithm = signature.get("algorithm")
    if algorithm not in SUPPORTED_ALGORITHMS:
        # Refusing an unrecognised algorithm is the only safe response:
        # treating it as valid, or as one that is implemented, would accept
        # signatures this code cannot actually check.
        return fail(f"unsupported signature algorithm {algorithm!r}")

    key_id = signature.get("key_id")
    issuer_key_id = (receipt.get("issuer") or {}).get("key_id")
    # A receipt that disagrees with itself about which key signed it must not
    # be accepted, even if one of the two IDs resolves to a key that verifies.
    if key_id != issuer_key_id:
        return fail(
            f"signature key_id {key_id!r} does not match issuer key_id {issuer_key_id!r}"
        )

    issued_at = _parse_time(receipt.get("issued_at"))
    if issued_at is None:
        return fail("issued_at is not a valid timestamp")

    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)

    if issued_at > current + max_clock_skew:
        return fail("receipt was issued in the future, beyond the permitted clock skew")
    if max_age is not None and current - issued_at > max_age:
        return fail("receipt is older than the maximum accepted age")

    # Two ways to obtain the signing key, and the difference is the whole
    # security of per-customer keys.
    #
    # Without an attestation the key ID must resolve against keys the
    # verifier already trusts. With one, the receipt supplies its own public
    # key and the only reason to believe it is the issuer's signature over
    # the statement carrying it. A verifier that took the embedded key on
    # faith would accept a receipt from anyone able to generate a keypair.
    attestation = (receipt.get("issuer") or {}).get("key_attestation")
    if attestation:
        attested, error = _verify_attestation(
            attestation, keys, (receipt.get("chain") or {}).get("id"), current
        )
        if error:
            return fail(error)
        if attestation.get("key_id") != key_id:
            return fail(
                f"attestation authorises key {attestation.get('key_id')!r} "
                f"but the receipt is signed by {key_id!r}"
            )
        if attestation.get("algorithm") != algorithm:
            return fail(
                f"attestation names algorithm {attestation.get('algorithm')!r} "
                f"but the receipt declares {algorithm!r}"
            )
        public_bytes = attested
    else:
        encoded = keys.get(key_id)
        if not encoded:
            return fail(f"signing key {key_id!r} is not known to this verifier")

        try:
            public_bytes = _decode_key(encoded, algorithm)
        except ValueError as exc:
            return fail(f"public key for {key_id!r} is malformed: {exc}")

    try:
        signature_bytes = _decode_base64(signature.get("value", ""))
    except ValueError:
        return fail("signature is not valid base64")

    message = signing_input(receipt)

    try:
        _verify_signature(algorithm, public_bytes, message, signature_bytes)
    except InvalidSignature:
        return fail("signature verification failed")
    except Exception as exc:  # noqa: BLE001 - surfaced verbatim, never swallowed
        return fail(f"verification failed: {exc}")

    governance = receipt.get("governance") or {}
    result = VerificationResult(
        valid=True,
        full_strength=is_full_strength(receipt),
        mode=governance.get("mode"),
        decision=governance.get("decision"),
        key_id=key_id,
        algorithm=algorithm,
        provenance=effective_provenance(receipt),
        vantage=(receipt.get("evidence") or {}).get("vantage"),
        subject=effective_subject(receipt),
        truncated=(receipt.get("content") or {}).get("truncated") is True,
        issued_at=issued_at,
        digest=hashlib.sha256(message).hexdigest(),
        warnings=_collect_warnings(receipt),
    )

    if require_full_strength and not result.full_strength:
        result.valid = False
        result.error = (
            f"governance mode is {governance.get('mode')} but full strength was required"
        )

    return result


#: Algorithms this build can actually check.
SUPPORTED_ALGORITHMS = ("ed25519", "es256")

#: An ES256 signature in a receipt is the fixed-width 64-byte r-then-s form
#: rather than DER. Fixed width is what every other implementation here
#: emits, and it removes an ASN.1 parser from the trust path.
_ES256_SIGNATURE_SIZE = 64


def _verify_signature(
    algorithm: str, public_bytes: bytes, message: bytes, signature: bytes
) -> None:
    """Check a signature, raising InvalidSignature when it does not hold."""
    if algorithm == "es256":
        if len(signature) != _ES256_SIGNATURE_SIZE:
            # A DER-wrapped signature of the same key would be a different
            # length. It is rejected rather than unwrapped: accepting two
            # encodings of one signature invites a malleability argument
            # that has no upside here.
            raise InvalidSignature("es256 signature must be 64 bytes of r followed by s")
        half = _ES256_SIGNATURE_SIZE // 2
        r = int.from_bytes(signature[:half], "big")
        s = int.from_bytes(signature[half:], "big")
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_bytes)
        key.verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
        return

    Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature, message)


#: Separates an attestation signature from a receipt signature made by the
#: same key. The two structures can never canonicalize alike, but relying on
#: that is relying on an accident of the schemas rather than a stated rule.
_ATTESTATION_DOMAIN = b"lyntway-key-attestation-v1\x00"
_ATTESTATION_VERSION = "lyntway-key-attestation/1"


def _verify_attestation(
    attestation: Mapping[str, Any],
    keys: Mapping[str, str],
    chain_id: Any,
    now: datetime,
) -> tuple[bytes, str | None]:
    """Check the issuer's signed statement that a key may sign for a chain.

    Returns the attested public key, or an error. The caller must not use
    the embedded key when an error is returned.
    """
    if attestation.get("version") != _ATTESTATION_VERSION:
        return b"", f"unsupported key attestation version {attestation.get('version')!r}"

    scope = attestation.get("scope")
    if not scope:
        return b"", "key attestation has no scope, so it would authorise this key for any chain"

    root_algorithm = attestation.get("root_algorithm")
    if root_algorithm not in SUPPORTED_ALGORITHMS:
        return b"", f"unsupported attestation algorithm {root_algorithm!r}"

    root_key_id = attestation.get("root_key_id")
    encoded_root = keys.get(root_key_id)
    if not encoded_root:
        return b"", (
            f"issuer key {root_key_id!r} is not known to this verifier, so the "
            "authority for this receipt's key cannot be checked"
        )

    # Everything but the signature is covered, since it cannot cover itself.
    unsigned = {k: v for k, v in attestation.items() if k != "signature"}
    message = _ATTESTATION_DOMAIN + canonical_bytes(unsigned)

    try:
        root_bytes = _decode_key(encoded_root, root_algorithm)
        signature_bytes = _decode_base64(attestation.get("signature", ""))
    except ValueError as exc:
        return b"", f"key attestation is malformed: {exc}"

    try:
        _verify_signature(root_algorithm, root_bytes, message, signature_bytes)
    except InvalidSignature:
        return b"", "the issuer did not sign this key attestation"
    except Exception as exc:  # noqa: BLE001
        return b"", f"key attestation could not be checked: {exc}"

    # Dates mean something only once the signature holds; before that they
    # are values an attacker chose.
    not_before = attestation.get("not_before")
    if not_before:
        parsed = _parse_time(not_before)
        if parsed is None:
            return b"", "attestation not_before is not a valid timestamp"
        if now < parsed:
            return b"", f"this key is not authorised until {not_before}"
    not_after = attestation.get("not_after")
    if not_after:
        parsed = _parse_time(not_after)
        if parsed is None:
            return b"", "attestation not_after is not a valid timestamp"
        if now > parsed:
            return b"", f"this key's authorisation expired at {not_after}"

    # Scope is what separates one customer from another. A valid attestation
    # proves the key is legitimate; only this proves it is legitimate for
    # this chain.
    if not isinstance(chain_id, str) or not chain_id.startswith(scope):
        return b"", (
            f"key is authorised for {scope!r} but the receipt is on chain {chain_id!r}"
        )

    try:
        return _decode_base64(attestation.get("public_key", "")), None
    except ValueError:
        return b"", "attested public key is not valid base64"


#: How the issuer came to know what a receipt describes. Absent evidence
#: reads as "asserted": an old receipt may well have been observed, but
#: nothing in it says so, and promoting it would be an unearned upgrade.
def effective_provenance(receipt: Mapping[str, Any]) -> str:
    """Return the receipt's provenance, defaulting to the weakest claim."""
    evidence = receipt.get("evidence")
    if not evidence:
        return "asserted"
    return evidence.get("provenance", "asserted")


#: Subjects this build understands. ``payload`` is the data itself and the
#: only form that can say what it contained; ``telemetry`` is a record
#: another system produced about the action; ``metadata`` is what the issuer
#: saw of a connection it carried but never read. Any other string is
#: tolerated so a receipt from a newer issuer still verifies, and is treated
#: as "not the data".
KNOWN_SUBJECTS = ("payload", "telemetry", "metadata")

#: Shared word for word with the CLI, the TypeScript SDK and the verify page.
TRUNCATED_WARNING = "stream cut by policy — digests cover the delivered prefix only"


def effective_subject(receipt: Mapping[str, Any]) -> str:
    """What a receipt's digests actually cover.

    Absent means the payload, which is what every receipt meant before the
    field existed.
    """
    return (receipt.get("content") or {}).get("subject") or "payload"


def subject_warning(subject: str) -> str | None:
    """State what a digest covers when it is not the data.

    One phrase, shared with every other Lyntway verifier, so a reader
    comparing tools sees the same qualification in each. An unknown subject
    must read weak, never as a stronger claim than the values this build
    understands.
    """
    head = "the digests cover a record about the traffic, not the traffic itself: "
    if subject == "payload":
        return None
    if subject == "metadata":
        return head + (
            "the issuer carried the bytes without reading them, so nothing here "
            "attests to what they contained"
        )
    if subject == "telemetry":
        return head + (
            "another system reported the action, so nothing here attests to what "
            "it carried"
        )
    return head + (
        f"subject {subject!r} is not one this verifier knows, so nothing here "
        "attests to what the traffic contained"
    )


def _collect_warnings(receipt: Mapping[str, Any]) -> list[str]:
    warnings: list[str] = []
    governance = receipt.get("governance") or {}
    detector = governance.get("detector") or {}
    mode = governance.get("mode")

    if mode == "degraded":
        message = "governance ran in degraded mode"
        for component in detector.get("components") or []:
            if component.get("health") != "healthy":
                message += f"; {component.get('name')} was {component.get('health')}"
        warnings.append(message)
    elif mode == "bypassed":
        warnings.append("governance was bypassed: this content passed unexamined")

    if not (receipt.get("actor") or {}).get("verified"):
        warnings.append(
            "actor identity was asserted but not cryptographically verified"
        )
    provenance = effective_provenance(receipt)
    vantage = (receipt.get("evidence") or {}).get("vantage", "")
    if provenance == "attested":
        warnings.append(
            f"this record is second-hand: {vantage} reported the action and the "
            "issuer recorded it, so the receipt is only as complete as that report"
        )
    elif provenance == "asserted":
        if receipt.get("evidence"):
            warnings.append(
                "the caller described its own action: this proves the description "
                "was governed, not that it was accurate"
            )
        else:
            warnings.append(
                "the receipt does not state how the issuer knew what it recorded, "
                "so it cannot be relied on as first-hand"
            )

    subject = subject_warning(effective_subject(receipt))
    if subject:
        warnings.append(subject)
    if (receipt.get("content") or {}).get("truncated") is True:
        warnings.append(TRUNCATED_WARNING)

    if not receipt.get("anchors"):
        warnings.append(
            "no external timestamp anchor: issuance time rests on the issuer's clock alone"
        )
    if governance.get("decision") == "log_only" and governance.get("findings"):
        warnings.append("findings were recorded but not enforced (log_only)")

    return warnings


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    # datetime.fromisoformat accepts "Z" only from Python 3.11 onward.
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


#: Expected raw public key sizes. Ed25519 keys are 32 bytes; a P-256 key is
#: an uncompressed point, one leading 0x04 tag byte followed by two 32-byte
#: coordinates.
_KEY_SIZES = {"ed25519": 32, "es256": 65}


def _decode_key(encoded: str, algorithm: str = "ed25519") -> bytes:
    """Accept a public key as base64 (any variant) or hex.

    The expected length depends on the algorithm, so it has to be passed in.
    Checking against a single size silently rejected every P-256 key as
    malformed, which reads as a corrupt key rather than as a verifier that
    only knows one algorithm.
    """
    text = encoded.strip()
    expected = _KEY_SIZES.get(algorithm)
    if expected is None:
        raise ValueError(f"unsupported algorithm {algorithm!r}")

    # A hex-encoded key is exactly twice as long as its bytes. Attempted
    # first only when the length is right, so a base64 string of the same
    # length is not mistaken for hex.
    if len(text) == expected * 2:
        try:
            return bytes.fromhex(text)
        except ValueError:
            pass
    raw = _decode_base64(text)
    if len(raw) != expected:
        raise ValueError(f"expected {expected} bytes for {algorithm}, got {len(raw)}")
    return raw


def _decode_base64(text: str) -> bytes:
    """Decode base64 in either alphabet, padded or not."""
    normalized = text.strip().replace("-", "+").replace("_", "/")
    normalized += "=" * (-len(normalized) % 4)
    try:
        return base64.b64decode(normalized, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(str(exc)) from exc
