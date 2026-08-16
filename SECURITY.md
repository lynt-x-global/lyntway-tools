# Security policy

Lyntway issues signed attestations about how other people's data was
handled. A defect here does not just break software — it can cause a false
statement to be made to an auditor, a customer, or an underwriter. We treat
that accordingly.

## Reporting a vulnerability

Report privately through GitHub's [Report a
vulnerability](https://github.com/lynt-x-global/lyntway-core/security/advisories/new)
flow, or email **security@lyntway.com**.

Please do not open a public issue for a security defect.

We will acknowledge within 2 business days and aim to give an initial
assessment within 5.

## What we consider a vulnerability here

Beyond the usual categories, the following are security defects in this
project even when no memory-safety or injection bug is involved:

**A receipt that overstates governance.** Any path that produces a receipt
reporting `mode: full` when detection was partial or absent. This is the
central invariant of the design.

**A tampered receipt that verifies.** Any mutation to a signed field that
survives `Verify`.

**A chain break that goes undetected.** Any deletion, substitution, or
reordering of receipts within a chain that `VerifyChain` accepts.

**Canonicalisation divergence.** Any input for which two conforming
implementations produce different canonical bytes, since that silently
breaks cross-implementation verification.

**Content leakage into a receipt.** Receipts carry digests only. Any path
that lets governed content reach a receipt field is a data-exposure defect,
because receipts are designed to be shared.

**Signature acceptance under a weaker algorithm than declared**, or any
confusion between the declared algorithm and the resolved key type.

## Scope

In scope: everything in this repository.

Out of scope: findings that require an attacker who already holds the
signing key. Key custody is a deployment concern — production keys are
expected to live in a key management service and never enter the
application process. `Ed25519Signer` holds a key in memory by design and is
intended for development, tests, and air-gapped builds.

## Key rotation

Signing keys rotate by issuing under a **new** key ID. A key ID is never
reused for new key material: a verifier holding the old public key would
otherwise report genuine receipts as forged. Retired public keys stay
published so historical receipts remain verifiable indefinitely.
