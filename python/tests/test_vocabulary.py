"""What this build does when a receipt uses a word it does not know.

Two failures are possible and they point in opposite directions.

Refusing a receipt because it names a surface added after this SDK shipped
reports a perfectly good signature as invalid, and a caller takes that to
mean tampered. Every installed verifier did exactly that the day the email
surface was added.

Accepting a governance mode or a provenance this build cannot read is worse,
because the SDK then reports a strength the receipt may never have claimed.
This SDK had that bug: a provenance outside the three matched neither branch
in ``_collect_warnings``, produced no warning, and so read exactly like
``observed`` -- the strongest of the three.
"""

from __future__ import annotations

import pytest

from lyntway.receipt import (
    KNOWN_PROVENANCE,
    KNOWN_SURFACES,
    unreadable_honesty_field,
)

DIGEST = "a" * 64


def base() -> dict:
    """A receipt this build reads completely."""
    return {
        "version": "lyntway-receipt/1",
        "id": "rcpt_vocab",
        "issued_at": "2026-09-25T12:00:00Z",
        "issuer": {"key_id": "k1"},
        "chain": {"id": "c1", "seq": 0},
        "action": {"surface": "model", "direction": "request", "method": "POST /v1/x"},
        "actor": {"type": "service", "id": "svc", "source": "none", "verified": False},
        "content": {
            "algorithm": "sha-256",
            "input_digest": DIGEST,
            "output_digest": DIGEST,
        },
        "governance": {
            "mode": "full",
            "decision": "allow",
            "policy": {"id": "p", "version": "1"},
            "detector": {
                "engine": "e",
                "engine_version": "1",
                "ruleset_version": "r",
                "health": "healthy",
            },
        },
    }


def test_a_readable_receipt_has_no_unreadable_field():
    """The guard on every test below: a refusal elsewhere is about the field
    under test, not about the receipt being malformed."""
    assert unreadable_honesty_field(base()) is None


@pytest.mark.parametrize(
    "field,mutate",
    [
        ("governance.mode", lambda r: r["governance"].update(mode="excellent")),
        ("governance.decision", lambda r: r["governance"].update(decision="vibes")),
        (
            "evidence.provenance",
            lambda r: r.update(evidence={"provenance": "overheard", "vantage": "v"}),
        ),
    ],
)
def test_each_honesty_field_refuses_on_its_own(field, mutate):
    receipt = base()
    mutate(receipt)

    why = unreadable_honesty_field(receipt)
    assert why is not None, f"an unreadable {field} was accepted"
    assert field in why, f"the refusal did not name the field: {why}"
    # The words that would be a lie. The signature is checked before this
    # runs, so the bytes are known to be unaltered.
    assert "unaltered" in why, f"the refusal left a caller to suspect tampering: {why}"


@pytest.mark.parametrize("bad", ["overheard", "observed-ish", "OBSERVED", "", "1"])
def test_a_provenance_outside_the_three_is_never_read_as_observed(bad):
    """The bug this file exists for. Before the fix, anything that was not
    ``attested`` or ``asserted`` fell through and read as first-hand."""
    receipt = base()
    receipt["evidence"] = {"provenance": bad, "vantage": "v"}
    assert unreadable_honesty_field(receipt) is not None, (
        f"provenance {bad!r} was read as evidence this build can rely on"
    )


def test_absent_evidence_is_weak_not_unreadable():
    """Refusing here would reject the majority of honest receipts. Absent
    evidence reads as ``asserted`` and is warned about separately."""
    receipt = base()
    assert "evidence" not in receipt
    assert unreadable_honesty_field(receipt) is None


@pytest.mark.parametrize("provenance", KNOWN_PROVENANCE)
def test_the_three_real_provenance_values_stay_readable(provenance):
    receipt = base()
    receipt["evidence"] = {"provenance": provenance, "vantage": "v"}
    assert unreadable_honesty_field(receipt) is None


@pytest.mark.parametrize(
    "surface", ["model", "mcp", "database", "http", "primitive", "email"]
)
def test_every_surface_this_service_issues_is_readable_here(surface):
    """The literals are written out rather than taken from a constant: a
    receipt already signed carries the string, so a rename is a silent break
    of every receipt in the field, and a test using the constant would rename
    along with it and stay green."""
    assert surface in KNOWN_SURFACES
