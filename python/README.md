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

## Record what LiteLLM sends, including Bedrock and Vertex

AWS Bedrock and Google Vertex sign every request in a way that breaks the
moment a proxy sits in the path, so neither can be routed through a gateway.
A callback running inside LiteLLM is the only place those calls are visible.

In `config.yaml`:

```yaml
litellm_settings:
  callbacks: [lyntway.litellm.handler]

environment_variables:
  LYNTWAY_URL: https://your-lyntway
  LYNTWAY_KEY: sk-...
```

Every call is inspected and signed. Attribution comes from the virtual key,
so a finding lands on the person who caused it rather than on the proxy, and
the destination recorded is the model — `bedrock/anthropic.claude-3-sonnet`,
not `litellm`.

It never blocks and never raises. The hook runs after the response returns,
so there is nothing left to change, and a recorder that can fail somebody's
traffic is a recorder they remove. If Lyntway is unreachable the call still
succeeds and the receipt is simply missing, which the coverage report shows.

The receipt records that your gateway made the call rather than that we
watched it leave — `asserted` rather than `observed`. Weaker evidence than
routing through the gateway, and stronger than the alternative for Bedrock
and Vertex, which is no record at all.

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

## Links

- [lyntway.com](https://lyntway.com) — the service, and a receipt verifier
  that needs no account
- [Documentation](https://lyntway.com/docs) — including how to check a
  receipt from scratch, with no tool of ours
- [Source](https://github.com/lynt-x-global/lyntway-tools/tree/main/python)

## License

Apache-2.0
