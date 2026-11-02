"""The SDK's vocabularies against the Go module that defines them.

A receipt's vocabulary is one contract with two authors: receipt/receipt.go
emits the values and this SDK decides what to tell a reader about them. The
two drifted and nothing failed -- KNOWN_DECISIONS carried ``transform`` and
``hold``, which nothing has ever emitted, and was missing ``redact`` and
``require_approval``, which the engine does emit. The cost is not a crash.
It is a reader being warned about a perfectly good receipt, and a reader
who is warned hears "tampered".

So the Go source is read and compared. The two cannot import each other --
one is Go and one is Python, and this package is published on its own -- so
reading the source is the only thing that holds them together. The same
arrangement guards the database gateway's upstream file and the device
report's fields.

Skipped rather than failed when the Go source is not beside us, because
this package is installed from PyPI by people who will never have it.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from lyntway.receipt import (
    KNOWN_DECISIONS,
    KNOWN_MODES,
    KNOWN_PROVENANCE,
    KNOWN_SURFACES,
)

# tests -> lyntway-py -> packages -> the repository root.
GO_RECEIPT_PKG = Path(__file__).resolve().parents[3] / "receipt"


def _go_values(kind: str) -> set[str]:
    """Every string constant of one Go type in the receipt package.

    The whole package rather than receipt.go: Provenance is declared in
    evidence.go, and a test that read one file reported the one vocabulary
    it could not see as unverifiable and skipped. A skipped assertion
    proves nothing, which is the failure mode this test was written to
    avoid in the first place.
    """
    found: set[str] = set()
    for path in sorted(GO_RECEIPT_PKG.glob("*.go")):
        if path.name.endswith("_test.go"):
            continue
        found |= set(
            re.findall(rf"\b\w+\s+{kind}\s*=\s*\"([a-z_]+)\"", path.read_text(encoding="utf-8"))
        )
    return found


@pytest.mark.parametrize(
    ("kind", "known"),
    [
        ("Decision", KNOWN_DECISIONS),
        ("Mode", KNOWN_MODES),
        ("Provenance", KNOWN_PROVENANCE),
        ("Surface", KNOWN_SURFACES),
    ],
)
def test_the_sdk_knows_exactly_what_go_emits(kind: str, known: tuple[str, ...]) -> None:
    if not GO_RECEIPT_PKG.is_dir():
        pytest.skip("the Go module is not beside this package")
    go = _go_values(kind)
    if not go:
        pytest.skip(f"no {kind} constants were found; this test is reading the wrong files")

    missing = go - set(known)
    assert not missing, (
        f"the engine emits {kind} {sorted(missing)} and this SDK does not know them, "
        "so a genuine receipt would be reported with a warning"
    )

    invented = set(known) - go
    assert not invented, (
        f"this SDK accepts {kind} {sorted(invented)} which the engine never emits, "
        "so a value no receipt should carry would be read as a known one"
    )
