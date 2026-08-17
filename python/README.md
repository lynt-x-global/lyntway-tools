# lyntway

Govern content and verify signed action receipts.

```bash
pip install lyntway
```

## Verify a receipt offline

No network, no Lyntway account. A receipt is only evidence if a third party
can check it without asking the issuer for permission.

```python
from lyntway import verify

result = verify(receipt, {
    "lyntway-core-1": "TyjVG4H0Md9f4TJqWkTFXKDm1iHUPT5A80U1V0H+omM=",
})

if result.valid and result.full_strength:
    print("governed:", result.decision)
```

**Check `full_strength`, not `valid`, before showing a verified badge.** A
receipt can be cryptographically perfect and still attest that governance was
bypassed — a badge driven by `valid` alone claims more than the receipt does.
`result.warnings` explains what was degraded and why.

## Govern content

```python
from lyntway import Lyntway

client = Lyntway(base_url, api_key)

response = client.govern(
    chain_id="ws_acme",
    content="Customer priya@acme.com paid with 4111111111111111.",
    actor_id="agent_support",
    destination="api.anthropic.com",
)

print(response.content)
# Customer lynt-m2i5r72j2b5ve@tokenized.invalid paid with 9999482578971289.
```

Tokens preserve format: the email is still a valid address, the card still
passes Luhn, and both land in reserved ranges that cannot route. Downstream
validation keeps working instead of rejecting governed content.

Tokens are stable within a `chain_id`, so an agent can correlate the same
value across separate responses.

## Dependencies

One: `cryptography`, for Ed25519. Python has no Ed25519 in its standard
library, and this code decides whether evidence is genuine — an SDK is the
wrong place to save a dependency on hand-rolled elliptic curve arithmetic.
HTTP uses `urllib` from the standard library.

## Interoperability

Receipts are canonicalised with RFC 8785 JCS. This implementation is tested
byte-for-byte against the Go reference on every commit, alongside the
TypeScript SDK — a single byte of divergence would make every signature fail
in a way that looks exactly like tampering.

## License

Apache-2.0
