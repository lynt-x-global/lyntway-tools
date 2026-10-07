package receipt

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// A verifier is a long-lived thing in somebody else's hands.
//
// When the schema gained the email surface, every verifier already
// installed reported NOT VERIFIED on a receipt whose signature was
// perfectly good — which a reader takes to mean tampered. These tests fix
// the line between "I do not recognise this" and "this was altered",
// because getting it wrong in either direction is a receipt lying about
// itself.

func signedBase(t *testing.T) (*Receipt, KeyResolver) {
	t.Helper()
	signer, err := GenerateEd25519Signer("k1")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	r := validBase()
	if err := Sign(r, signer); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return r, StaticKeyResolver{"k1": signer.Public()}
}

// The case that started this: a surface added after the verifier shipped.
func TestAReceiptNewerThanTheVerifierStillVerifies(t *testing.T) {
	// A receipt signed by an issuer that knew a surface this build does not.
	// The signature covers the canonical bytes including the unfamiliar
	// value, which is exactly what an older verifier meets in the field.
	future, keys := signedWithFutureSurface(t)
	res, err := Verify(future, keys, VerifyOptions{})
	if err != nil {
		t.Fatalf("a receipt with an unknown surface failed verification: %v", err)
	}
	if !res.Valid {
		t.Error("Valid is false for an intact signature")
	}
	// It verified, but this build cannot say what it read, so it must not
	// vouch for the whole of it.
	if res.FullStrength {
		t.Error("FullStrength is true despite a value this build cannot interpret")
	}
	var found bool
	for _, w := range res.Warnings {
		if strings.Contains(w, "action.surface") && strings.Contains(w, "does not recognise") {
			found = true
		}
	}
	if !found {
		t.Errorf("no warning named the unrecognised surface; warnings were %q", res.Warnings)
	}
}

// signedWithFutureSurface signs a receipt and then rewrites the surface in
// the canonical bytes, which is how a receipt from a newer issuer actually
// reaches an older verifier.
func signedWithFutureSurface(t *testing.T) (*Receipt, KeyResolver) {
	t.Helper()
	signer, err := GenerateEd25519Signer("k1")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	// Sign() validates strictly, so this build cannot sign a surface it does
	// not know — which is the point of TestSigningStillRefuses below. To get
	// the bytes a future issuer would produce, sign the canonical input
	// directly, with the unfamiliar value already in place.
	r := validBase()
	r.Action.Surface = Surface("teleport")
	input, err := SigningInput(r)
	if err != nil {
		t.Fatalf("signing input: %v", err)
	}
	raw, err := signer.Sign(input)
	if err != nil {
		t.Fatalf("sign raw: %v", err)
	}
	r.Signature = &Signature{
		Algorithm:        AlgEd25519,
		KeyID:            "k1",
		Canonicalization: CanonicalizationJCS,
		Value:            base64.StdEncoding.EncodeToString(raw),
	}
	return r, StaticKeyResolver{"k1": signer.Public()}
}

// The other half, and the more important one: tolerance must not extend to
// a receipt that was actually altered.
func TestATamperedReceiptIsStillRefused(t *testing.T) {
	r, keys := signedBase(t)
	r.Action.Surface = Surface("teleport") // changed after signing, not re-signed
	if _, err := Verify(r, keys, VerifyOptions{}); err == nil {
		t.Fatal("a receipt altered after signing verified; unknown-vocabulary tolerance must never cover tampering")
	}
}

// An issuer must not sign what it cannot name. Tolerance is a property of
// reading an old receipt, never of writing a new one.
func TestSigningStillRefusesAnUnknownSurface(t *testing.T) {
	signer, err := GenerateEd25519Signer("k1")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	r := validBase()
	r.Action.Surface = Surface("teleport")
	if err := Sign(r, signer); err == nil {
		t.Error("signed a receipt naming a surface this build does not recognise")
	}
}

// The honesty fields are outside the tolerance, and that is the whole
// design. A verifier that cannot read how strong a claim is must refuse,
// not warn: a warning leaves the reader believing a receipt whose central
// claim they cannot actually interpret.
func TestUnknownHonestyFieldsAreNotTolerated(t *testing.T) {
	// The first version of this test built a receipt that was invalid for
	// unrelated reasons, so OnlyUnrecognised() was false whatever the
	// honesty field said and the test proved nothing. It is written against
	// a receipt that validates cleanly, and asserts on the field by name.
	if err := validBase().Validate(); err != nil {
		t.Fatalf("the base receipt must be valid or this test proves nothing: %v", err)
	}

	for _, tc := range []struct {
		name   string
		field  string
		adjust func(*Receipt)
	}{
		{"mode", "governance.mode", func(r *Receipt) { r.Governance.Mode = Mode("excellent") }},
		{"decision", "governance.decision", func(r *Receipt) { r.Governance.Decision = Decision("vibes") }},
		{"provenance", "evidence.provenance", func(r *Receipt) {
			r.Evidence = &Evidence{Provenance: Provenance("overheard"), Vantage: "v"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := validBase()
			tc.adjust(r)

			err := r.Validate()
			if err == nil {
				t.Fatalf("an unrecognised %s validated", tc.name)
			}
			var errs FieldErrors
			if !errors.As(err, &errs) {
				t.Fatalf("expected FieldErrors, got %T", err)
			}
			if errs.OnlyUnrecognised() {
				t.Errorf("an unrecognised %s was tolerable; the honesty fields must fail hard", tc.name)
			}

			var seen bool
			for _, e := range errs {
				if e.Field != tc.field {
					continue
				}
				seen = true
				if e.Unrecognised {
					t.Errorf("%s was recorded as merely unrecognised; it must be a hard failure", tc.field)
				}
			}
			if !seen {
				t.Fatalf("no error named %s; the test is asserting on nothing. Errors: %v", tc.field, errs.Fields())
			}
		})
	}
}

// The counterpart, and the guard on the assertion above: a tolerable field
// on the same receipt really is marked tolerable. Without this, the test
// above would still pass if nothing were ever marked Unrecognised.
func TestATolerableFieldIsMarkedTolerable(t *testing.T) {
	r := validBase()
	r.Action.Surface = Surface("teleport")

	err := r.Validate()
	if err == nil {
		t.Fatal("an unrecognised surface validated")
	}
	var errs FieldErrors
	if !errors.As(err, &errs) {
		t.Fatalf("expected FieldErrors, got %T", err)
	}
	if !errs.OnlyUnrecognised() {
		t.Errorf("an unknown surface on an otherwise valid receipt was not tolerable: %v", errs.Fields())
	}
}

// validBase is a receipt that validates with no complaints. Every test here
// starts from it so that a failure names the thing under test rather than a
// field somebody forgot.
func validBase() *Receipt {
	return &Receipt{
		// Set explicitly: Sign() fills this in, so a helper that relies on
		// signing hides the fact that the unsigned receipt is incomplete.
		Version:  SchemaVersion,
		ID:       "r1",
		IssuedAt: Now(),
		Issuer:   Issuer{KeyID: "k1"},
		Chain:    Chain{ID: "c1", Seq: 0},
		Action:   Action{Surface: SurfaceModel, Direction: DirectionRequest, Method: "POST /x"},
		Actor:    Actor{Type: ActorService, ID: "a", Source: IdentityNone},
		// An allow means the bytes left unchanged, so the digests match.
		Content: Content{Algorithm: "sha-256", InputDigest: strings.Repeat("a", 64), OutputDigest: strings.Repeat("a", 64)},
		Governance: Governance{
			Mode:     ModeFull,
			Decision: DecisionAllow,
			Policy:   Policy{ID: "p", Version: "1"},
			Detector: Detector{Engine: "e", EngineVersion: "1", RulesetVersion: "r", Health: HealthHealthy},
		},
	}
}
