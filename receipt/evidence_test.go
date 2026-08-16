package receipt

import (
	"strings"
	"testing"
	"time"
)

// The point of the field: three receipts that are otherwise identical are
// not equally strong, and a reader must be able to tell them apart.
func TestProvenanceDistinguishesOtherwiseIdenticalReceipts(t *testing.T) {
	signer, err := GenerateEd25519Signer("k1")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	keys := StaticKeyResolver{signer.KeyID(): signer.Public()}
	at := VerifyOptions{Now: time.Date(2026, 8, 13, 10, 0, 5, 0, time.UTC)}

	cases := map[string]*Evidence{
		"observed": {Provenance: ProvenanceObserved, Vantage: "gw/anthropic"},
		"attested": {Provenance: ProvenanceAttested, Vantage: "databricks/unity-ai-gateway"},
		"asserted": {Provenance: ProvenanceAsserted},
	}

	for name, ev := range cases {
		t.Run(name, func(t *testing.T) {
			r := validReceipt()
			r.Issuer = Issuer{KeyID: signer.KeyID(), Name: "Lyntway"}
			r.Evidence = ev
			if err := Sign(r, signer); err != nil {
				t.Fatalf("signing: %v", err)
			}
			res, err := Verify(r, keys, at)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if res.Provenance != ev.Provenance {
				t.Errorf("provenance = %q, want %q", res.Provenance, ev.Provenance)
			}
			if res.Vantage != ev.Vantage {
				t.Errorf("vantage = %q, want %q", res.Vantage, ev.Vantage)
			}

			// Only first-hand evidence passes without a caveat about how
			// it was obtained.
			hasCaveat := false
			for _, warn := range res.Warnings {
				if strings.Contains(warn, "second-hand") || strings.Contains(warn, "described its own action") {
					hasCaveat = true
				}
			}
			if name == "observed" && hasCaveat {
				t.Error("a first-hand receipt was caveated")
			}
			if name != "observed" && !hasCaveat {
				t.Errorf("a %s receipt carried no caveat about how it was obtained", name)
			}
		})
	}
}

// Provenance is covered by the signature, so the field describing how much
// to trust the receipt cannot be the one field anybody may rewrite.
func TestProvenanceCannotBeUpgradedAfterSigning(t *testing.T) {
	signer, err := GenerateEd25519Signer("k1")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	keys := StaticKeyResolver{signer.KeyID(): signer.Public()}

	r := validReceipt()
	r.Issuer = Issuer{KeyID: signer.KeyID(), Name: "Lyntway"}
	r.Evidence = &Evidence{Provenance: ProvenanceAttested, Vantage: "some-integration"}
	if err := Sign(r, signer); err != nil {
		t.Fatalf("signing: %v", err)
	}

	// Promote second-hand evidence to first-hand.
	r.Evidence = &Evidence{Provenance: ProvenanceObserved, Vantage: "gw/anthropic"}

	if _, err := Verify(r, keys, VerifyOptions{Now: time.Date(2026, 8, 13, 10, 0, 5, 0, time.UTC)}); err == nil {
		t.Fatal("provenance was upgraded after signing and the receipt still verified")
	}
}

// A receipt issued before the field existed must not be read as first-hand.
// Silently promoting old receipts to the strongest claim is exactly the
// unearned upgrade this field exists to prevent.
func TestAbsentEvidenceIsReadAsTheWeakestClaim(t *testing.T) {
	r := validReceipt()
	r.Evidence = nil

	if got := r.EffectiveProvenance(); got != ProvenanceAsserted {
		t.Errorf("absent evidence read as %q, want asserted", got)
	}
	if r.FirstHand() {
		t.Error("a receipt with no evidence block claimed to be first-hand")
	}
}

// A claim about where the issuer stood is what makes the claim assessable,
// so it cannot be omitted where it matters or invented where it does not.
func TestVantageRules(t *testing.T) {
	tests := []struct {
		name     string
		evidence Evidence
		valid    bool
	}{
		{"observed with vantage", Evidence{Provenance: ProvenanceObserved, Vantage: "gw/anthropic"}, true},
		{"observed without vantage", Evidence{Provenance: ProvenanceObserved}, false},
		{"attested with vantage", Evidence{Provenance: ProvenanceAttested, Vantage: "litellm"}, true},
		{"attested without vantage", Evidence{Provenance: ProvenanceAttested}, false},
		{"asserted without vantage", Evidence{Provenance: ProvenanceAsserted}, true},
		{
			// A vantage here would suggest a position the issuer never held.
			name:     "asserted with vantage",
			evidence: Evidence{Provenance: ProvenanceAsserted, Vantage: "gw/anthropic"},
			valid:    false,
		},
		{"unknown provenance", Evidence{Provenance: "witnessed"}, false},
		{"vantage with free text", Evidence{Provenance: ProvenanceObserved, Vantage: "our gateway, probably"}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := validReceipt()
			r.Evidence = &tc.evidence
			err := r.Validate()
			if tc.valid && err != nil {
				t.Errorf("valid evidence was rejected: %v", err)
			}
			if !tc.valid && err == nil {
				t.Error("invalid evidence was accepted")
			}
		})
	}
}

// Signing validates first, so a receipt that misdescribes its own evidence
// never gets a signature at all.
func TestSigningRefusesInconsistentEvidence(t *testing.T) {
	signer, err := GenerateEd25519Signer("k1")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	r := validReceipt()
	r.Issuer = Issuer{KeyID: signer.KeyID(), Name: "Lyntway"}
	r.Evidence = &Evidence{Provenance: ProvenanceObserved} // no vantage

	if err := Sign(r, signer); err == nil {
		t.Fatal("a receipt claiming first-hand evidence from nowhere was signed")
	}
}

// A receipt built from a telemetry record never held the data, so it must
// not describe work nothing performed. Governing cannot happen after the
// fact, and neither can observation.
func TestATelemetryReceiptCannotClaimItHandledTheData(t *testing.T) {
	telemetry := func() *Receipt {
		r := validReceipt()
		r.Content.Subject = SubjectTelemetry
		return r
	}

	t.Run("cannot claim tokenisation", func(t *testing.T) {
		r := telemetry()
		r.Governance.Decision = DecisionTokenize
		if err := r.Validate(); err == nil {
			t.Error("a telemetry receipt claimed it tokenised content it never held")
		}
	})

	t.Run("cannot claim redaction", func(t *testing.T) {
		r := telemetry()
		r.Governance.Decision = DecisionRedact
		if err := r.Validate(); err == nil {
			t.Error("a telemetry receipt claimed it redacted content it never held")
		}
	})

	t.Run("cannot claim first-hand observation", func(t *testing.T) {
		r := telemetry()
		r.Governance.Decision = DecisionLogOnly
		r.Evidence = &Evidence{Provenance: ProvenanceObserved, Vantage: "gw/anthropic"}
		if err := r.Validate(); err == nil {
			t.Error("a receipt derived from someone else's telemetry claimed to have been observed")
		}
	})

	t.Run("recording and attesting is honest", func(t *testing.T) {
		r := telemetry()
		r.Governance.Decision = DecisionLogOnly
		r.Evidence = &Evidence{Provenance: ProvenanceAttested, Vantage: "otel/checkout"}
		if err := r.Validate(); err != nil {
			t.Errorf("an honest telemetry receipt was rejected: %v", err)
		}
	})
}

// Receipts issued before the field existed described payloads, and must
// keep meaning that.
func TestAnAbsentSubjectMeansThePayload(t *testing.T) {
	r := validReceipt()
	r.Content.Subject = ""

	if got := r.EffectiveSubject(); got != SubjectPayload {
		t.Errorf("absent subject read as %q, want payload", got)
	}
	if err := r.Validate(); err != nil {
		t.Errorf("a receipt without the field no longer validates: %v", err)
	}
}

// The subject is inside the signature, so a telemetry receipt cannot be
// presented later as one that covered the data.
func TestTheSubjectCannotBeChangedAfterSigning(t *testing.T) {
	signer, err := GenerateEd25519Signer("k1")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	keys := StaticKeyResolver{signer.KeyID(): signer.Public()}

	r := validReceipt()
	r.Issuer = Issuer{KeyID: signer.KeyID(), Name: "Lyntway"}
	r.Content.Subject = SubjectTelemetry
	r.Governance.Decision = DecisionLogOnly
	if err := Sign(r, signer); err != nil {
		t.Fatalf("signing: %v", err)
	}

	// Promote a record about telemetry into one about the data itself.
	r.Content.Subject = SubjectPayload

	if _, err := Verify(r, keys, VerifyOptions{Now: time.Date(2026, 8, 13, 10, 0, 5, 0, time.UTC)}); err == nil {
		t.Fatal("the content subject was changed after signing and the receipt still verified")
	}
}
