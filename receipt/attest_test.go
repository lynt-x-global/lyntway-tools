package receipt

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

// tenantSetup is one deployment root key and one customer key attested by
// it — the arrangement the whole design exists to support.
type tenantSetup struct {
	root      *Ed25519Signer
	tenant    *Ed25519Signer
	att       *KeyAttestation
	rootsOnly StaticKeyResolver
}

func newTenantSetup(t *testing.T, tenantKeyID, scope string) tenantSetup {
	t.Helper()

	root, err := GenerateEd25519Signer("lyntway-root-1")
	if err != nil {
		t.Fatalf("root signer: %v", err)
	}
	tenant, err := GenerateEd25519Signer(tenantKeyID)
	if err != nil {
		t.Fatalf("tenant signer: %v", err)
	}

	pub, err := RawPublicKey(tenant)
	if err != nil {
		t.Fatalf("tenant public key: %v", err)
	}
	att, err := AttestKey(root, tenant.KeyID(), tenant.Algorithm(), pub, scope)
	if err != nil {
		t.Fatalf("attest: %v", err)
	}

	// Deliberately holds the deployment key and nothing else. Every test
	// below verifies against this, which is the claim being made: one
	// long-lived public key checks any customer's receipt.
	return tenantSetup{
		root: root, tenant: tenant, att: att,
		rootsOnly: StaticKeyResolver{root.KeyID(): root.Public()},
	}
}

// receiptFor builds a receipt on a chain, signed by the tenant key and
// carrying its attestation.
func (s tenantSetup) receiptFor(t *testing.T, chainID string) *Receipt {
	t.Helper()
	r := validReceipt()
	r.Chain = Chain{ID: chainID, Seq: 0}
	r.Issuer = Issuer{KeyID: s.tenant.KeyID(), Name: "Lyntway", KeyAttestation: s.att}
	if err := Sign(r, s.tenant); err != nil {
		t.Fatalf("signing: %v", err)
	}
	return r
}

// The property the design is for: a verifier holding only the deployment's
// published key can check a receipt signed by a key it has never seen, with
// no directory lookup and no knowledge of any other customer.
func TestAttestedReceiptVerifiesWithOnlyTheRootKey(t *testing.T) {
	s := newTenantSetup(t, "lyntway-t-9f3a2b", "acme/")
	r := s.receiptFor(t, "acme/ws_support")

	res, err := Verify(r, s.rootsOnly, VerifyOptions{Now: time.Date(2026, 8, 13, 10, 0, 5, 0, time.UTC)})
	if err != nil {
		t.Fatalf("an attested receipt did not verify against the root key alone: %v", err)
	}
	if !res.Valid {
		t.Error("result is not valid")
	}
	if res.KeyID != s.tenant.KeyID() {
		t.Errorf("attributed to %q, want the tenant key %q", res.KeyID, s.tenant.KeyID())
	}
}

// The single most valuable property commercially: one customer cannot issue
// a receipt that appears to belong to another. Their key is genuine and
// their attestation is genuine — only the scope stops them.
func TestOneCustomerCannotSignForAnothersChain(t *testing.T) {
	acme := newTenantSetup(t, "lyntway-t-acme", "acme/")

	r := acme.receiptFor(t, "northbay/ws_production")

	_, err := Verify(r, acme.rootsOnly, VerifyOptions{Now: time.Date(2026, 8, 13, 10, 0, 5, 0, time.UTC)})
	if !errors.Is(err, ErrAttestationScope) {
		t.Fatalf("a customer signed a receipt on another customer's chain and it verified: err = %v", err)
	}
}

// An attacker can always generate a keypair and an attestation. What they
// cannot do is make the deployment sign it.
func TestSelfSignedAttestationIsRejected(t *testing.T) {
	genuine := newTenantSetup(t, "lyntway-t-real", "acme/")

	attacker, err := GenerateEd25519Signer("lyntway-root-1") // same ID as the real root
	if err != nil {
		t.Fatalf("attacker root: %v", err)
	}
	forgedKey, err := GenerateEd25519Signer("lyntway-t-forged")
	if err != nil {
		t.Fatalf("forged key: %v", err)
	}
	pub, err := RawPublicKey(forgedKey)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	forgedAtt, err := AttestKey(attacker, forgedKey.KeyID(), forgedKey.Algorithm(), pub, "acme/")
	if err != nil {
		t.Fatalf("attest: %v", err)
	}

	r := validReceipt()
	r.Chain = Chain{ID: "acme/ws_support", Seq: 0}
	r.Issuer = Issuer{KeyID: forgedKey.KeyID(), Name: "Lyntway", KeyAttestation: forgedAtt}
	if err := Sign(r, forgedKey); err != nil {
		t.Fatalf("signing: %v", err)
	}

	// Everything is internally consistent. Only the deployment's signature
	// over the attestation is missing, and that is the whole point.
	if _, err := Verify(r, genuine.rootsOnly, VerifyOptions{Now: time.Date(2026, 8, 13, 10, 0, 5, 0, time.UTC)}); !errors.Is(err, ErrAttestationInvalid) {
		t.Fatalf("a self-signed attestation was accepted: err = %v", err)
	}
}

// Every field of an attestation is load-bearing, so every field must be
// covered by its signature.
func TestTamperingWithAnAttestationBreaksIt(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*KeyAttestation)
	}{
		{"scope widened to another customer", func(a *KeyAttestation) { a.Scope = "northbay/" }},
		{"public key swapped", func(a *KeyAttestation) {
			other, _ := GenerateEd25519Signer("other")
			raw, _ := RawPublicKey(other)
			a.PublicKey = base64.StdEncoding.EncodeToString(raw)
		}},
		{"key id changed", func(a *KeyAttestation) { a.KeyID = "lyntway-t-someone-else" }},
		{"algorithm downgraded", func(a *KeyAttestation) { a.Algorithm = "none" }},
		{"root key id repointed", func(a *KeyAttestation) { a.RootKeyID = "lyntway-root-2" }},
		{"version changed", func(a *KeyAttestation) { a.Version = "lyntway-key-attestation/0" }},
		{"expiry extended", func(a *KeyAttestation) { a.NotAfter = "2099-01-01T00:00:00Z" }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newTenantSetup(t, "lyntway-t-acme", "acme/")

			tampered := *s.att
			tc.mutate(&tampered)

			if _, err := tampered.Verify(s.rootsOnly, time.Now()); err == nil {
				t.Fatal("a tampered attestation verified")
			}
		})
	}
}

// The attestation says which key it authorises. A receipt signed by a
// different key must not ride on it.
func TestAttestationMustNameTheSigningKey(t *testing.T) {
	s := newTenantSetup(t, "lyntway-t-acme", "acme/")

	other, err := GenerateEd25519Signer("lyntway-t-other")
	if err != nil {
		t.Fatalf("other signer: %v", err)
	}

	r := validReceipt()
	r.Chain = Chain{ID: "acme/ws_support", Seq: 0}
	r.Issuer = Issuer{KeyID: other.KeyID(), Name: "Lyntway", KeyAttestation: s.att}
	if err := Sign(r, other); err != nil {
		t.Fatalf("signing: %v", err)
	}

	if _, err := Verify(r, s.rootsOnly, VerifyOptions{Now: time.Date(2026, 8, 13, 10, 0, 5, 0, time.UTC)}); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("a receipt rode on an attestation for a different key: err = %v", err)
	}
}

// The attestation lives inside the signed portion of the receipt, so it
// cannot be exchanged after issuance.
func TestSwappingTheAttestationBreaksTheReceiptSignature(t *testing.T) {
	acme := newTenantSetup(t, "lyntway-t-acme", "acme/")
	r := acme.receiptFor(t, "acme/ws_support")

	// A second, entirely valid attestation for the same key but a wider
	// scope, minted by the same root.
	pub, err := RawPublicKey(acme.tenant)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	wider, err := AttestKey(acme.root, acme.tenant.KeyID(), acme.tenant.Algorithm(), pub, "northbay/")
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	r.Issuer.KeyAttestation = wider

	if _, err := Verify(r, acme.rootsOnly, VerifyOptions{Now: time.Date(2026, 8, 13, 10, 0, 5, 0, time.UTC)}); err == nil {
		t.Fatal("the attestation was exchanged after signing and the receipt still verified")
	}
}

func TestExpiredAttestationIsRejected(t *testing.T) {
	s := newTenantSetup(t, "lyntway-t-acme", "acme/")

	expired := *s.att
	expired.NotAfter = "2026-01-01T00:00:00Z"
	// Re-signed, so this is a genuine attestation that has simply run out
	// rather than a tampered one.
	resigned, err := attestWithDates(s.root, &expired)
	if err != nil {
		t.Fatalf("re-attest: %v", err)
	}

	if _, err := resigned.Verify(s.rootsOnly, time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)); !errors.Is(err, ErrAttestationInvalid) {
		t.Fatalf("an expired attestation verified: err = %v", err)
	}
	// And before its expiry it is fine, so the test above is about the date
	// rather than about the re-signing.
	if _, err := resigned.Verify(s.rootsOnly, time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("a valid attestation was rejected before its expiry: %v", err)
	}
}

// attestWithDates re-signs an attestation whose validity window was edited.
func attestWithDates(root Signer, a *KeyAttestation) (*KeyAttestation, error) {
	out := *a
	out.Signature = ""
	input, err := out.signingInput()
	if err != nil {
		return nil, err
	}
	sig, err := root.Sign(input)
	if err != nil {
		return nil, err
	}
	out.Signature = base64.StdEncoding.EncodeToString(sig)
	return &out, nil
}

// An attestation with no scope would authorise a key for every chain, so it
// must be impossible to mint one.
func TestUnscopedAttestationIsRefused(t *testing.T) {
	root, err := GenerateEd25519Signer("lyntway-root-1")
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	tenant, err := GenerateEd25519Signer("lyntway-t-acme")
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	pub, err := RawPublicKey(tenant)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}

	if _, err := AttestKey(root, tenant.KeyID(), tenant.Algorithm(), pub, ""); err == nil {
		t.Fatal("an unscoped attestation was minted")
	} else if !strings.Contains(err.Error(), "scope") {
		t.Errorf("error does not mention the scope: %v", err)
	}
}

// Receipts issued before per-customer keys existed carry no attestation and
// are signed by the deployment key directly. They must keep verifying, or
// the change would invalidate every receipt already in customers' hands.
func TestReceiptsWithoutAnAttestationStillVerify(t *testing.T) {
	root, err := GenerateEd25519Signer("lyntway-root-1")
	if err != nil {
		t.Fatalf("root: %v", err)
	}

	r := validReceipt()
	r.Issuer = Issuer{KeyID: root.KeyID(), Name: "Lyntway"}
	if err := Sign(r, root); err != nil {
		t.Fatalf("signing: %v", err)
	}

	keys := StaticKeyResolver{root.KeyID(): root.Public()}
	if _, err := Verify(r, keys, VerifyOptions{Now: time.Date(2026, 8, 13, 10, 0, 5, 0, time.UTC)}); err != nil {
		t.Fatalf("a receipt issued before attestations existed no longer verifies: %v", err)
	}
}

// The scope is a prefix, so it must not match a chain that merely starts
// with the same characters as a different customer's name.
func TestScopePrefixDoesNotLeakAcrossSimilarNames(t *testing.T) {
	s := newTenantSetup(t, "lyntway-t-acme", "acme/")

	if s.att.CoversChain("acme-holdings/ws_x") {
		t.Error("scope \"acme/\" matched chain \"acme-holdings/ws_x\"")
	}
	if !s.att.CoversChain("acme/ws_x") {
		t.Error("scope \"acme/\" did not match its own chain")
	}
}
