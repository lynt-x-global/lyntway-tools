"""Govern content and verify signed action receipts.

Verification is offline and requires no Lyntway account: a receipt is only
evidence if a third party can check it without asking the issuer for
permission.

Verify a receipt::

    from lyntway import verify

    result = verify(receipt, {"lyntway-core-1": "TyjVG4H0..."})

    # Check full_strength, not valid, before showing a verified badge: a
    # receipt can be cryptographically perfect and still attest that
    # governance was bypassed.
    if result.valid and result.full_strength:
        print("governed:", result.decision)

Govern content::

    from lyntway import Lyntway

    client = Lyntway(base_url, api_key)
    response = client.govern(
        chain_id="ws_acme",
        content="Customer priya@acme.com paid with 4111111111111111.",
        actor_id="agent_support",
    )
    print(response.content)
"""

from .canonical import CanonicalizationError, canonical_bytes, canonicalize
from .client import GovernResponse, Lyntway, LyntwayError
from .receipt import (
    SCHEMA_VERSION,
    VerificationResult,
    is_full_strength,
    signing_input,
    verify,
)

__version__ = "0.1.0"

__all__ = [
    "canonicalize",
    "canonical_bytes",
    "CanonicalizationError",
    "verify",
    "signing_input",
    "is_full_strength",
    "VerificationResult",
    "SCHEMA_VERSION",
    "Lyntway",
    "LyntwayError",
    "GovernResponse",
    "__version__",
]
