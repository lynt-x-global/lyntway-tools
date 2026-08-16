package receipt

import (
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// testSigner returns a deterministic signer and a resolver that knows its key.
func testSigner(t *testing.T) (*Ed25519Signer, StaticKeyResolver) {
	t.Helper()
	s, err := GenerateEd25519Signer("key-test-1")
	if err != nil {
		t.Fatalf("generating signer: %v", err)
	}
	return s, StaticKeyResolver{s.KeyID(): s.Public()}
}

// validReceipt returns a structurally sound, unsigned receipt suitable for
// mutation by individual tests.
func validReceipt() *Receipt {
	return &Receipt{
		Version:  SchemaVersion,
		ID:       "rcpt_01J000000000000000000000",
		IssuedAt: FormatTime(time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)),
		Issuer:   Issuer{KeyID: "key-test-1", Name: "Lyntway"},
		Chain:    Chain{ID: "ws_acme", Seq: 0},
		Action: Action{
			Surface:     SurfaceModel,
			Direction:   DirectionRequest,
			Method:      "POST /v1/chat/completions",
			Target:      "claude-opus-5",
			Destination: "api.anthropic.com",
		},
		Actor: Actor{
			Type:     ActorAgent,
			ID:       "agent_support_bot",
			Source:   IdentityEntraAgent,
			Verified: true,
			Delegation: []DelegationHop{
				{Type: ActorHuman, ID: "priya@acme.com", Source: IdentityOIDC},
			},
		},
		Content: Content{
			Algorithm:    DigestSHA256,
			InputDigest:  DigestContent([]byte("customer email is priya@acme.com")),
			OutputDigest: DigestContent([]byte("customer email is <TOKEN:email:7f3a>")),
			Bytes:        32,
		},
		Governance: Governance{
			Mode:     ModeFull,
			Decision: DecisionTokenize,
			Findings: []Finding{
				{Class: "pii.email", Count: 1, Decision: DecisionTokenize},
			},
			Detector: Detector{
				Engine:         "lyntway-detect",
				EngineVersion:  "1.4.2",
				RulesetVersion: "pii-2026.08.01",
				Health:         HealthHealthy,
			},
			Policy: Policy{
				ID:      "pol_default_pii",
				Version: "3",
			},
		},
	}
}

// degradedReceipt returns an honestly degraded receipt: the ML detector was
// unavailable and only the deterministic floor ran. Used by tamper tests
// that need to attempt an *upgrade* of the governance claim, which is the
// forgery that actually matters — nobody forges a receipt to look worse.
func degradedReceipt() *Receipt {
	r := validReceipt()
	r.Governance.Mode = ModeDegraded
	r.Governance.Detector.Health = HealthDegraded
	r.Governance.Detector.Components = []Component{
		{Name: "onnx-pii", Health: HealthUnavailable, Detail: "sidecar unreachable"},
		{Name: "regex", Health: HealthHealthy},
	}
	return r
}

func mustSign(t *testing.T, r *Receipt, s Signer) {
	t.Helper()
	if err := Sign(r, s); err != nil {
		t.Fatalf("signing: %v", err)
	}
}

// --- Round trip -------------------------------------------------------------

func TestSignAndVerifyRoundTrip(t *testing.T) {
	signer, keys := testSigner(t)
	r := validReceipt()
	mustSign(t, r, signer)

	res, err := Verify(r, keys, VerifyOptions{Now: time.Date(2026, 8, 13, 10, 5, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.Valid {
		t.Error("expected valid result")
	}
	if !res.FullStrength {
		t.Error("expected full strength for a healthy detector in full mode")
	}
	if res.Decision != DecisionTokenize {
		t.Errorf("decision = %q, want %q", res.Decision, DecisionTokenize)
	}
	if res.Digest == "" {
		t.Error("expected a digest")
	}
}

// TestVerifySurvivesJSONRoundTrip proves a receipt can be transported as
// JSON and still verify. If canonicalisation were sensitive to encoding/json
// key ordering or escaping, this is where it would fail.
func TestVerifySurvivesJSONRoundTrip(t *testing.T) {
	signer, keys := testSigner(t)
	r := validReceipt()
	mustSign(t, r, signer)

	wire, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded Receipt
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if _, err := Verify(&decoded, keys, VerifyOptions{Now: r.mustIssuedAt(t)}); err != nil {
		t.Fatalf("verify after JSON round trip: %v", err)
	}
}

func (r *Receipt) mustIssuedAt(t *testing.T) time.Time {
	t.Helper()
	ts, err := ParseTime(r.IssuedAt)
	if err != nil {
		t.Fatalf("parsing issued_at: %v", err)
	}
	return ts
}

// --- Tamper detection -------------------------------------------------------

// TestTamperDetection mutates one field at a time on a signed receipt and
// asserts that verification fails. This is the core security property: any
// change to a signed claim must be detectable by a third party.
func TestTamperDetection(t *testing.T) {
	tests := []struct {
		name string
		// base supplies the starting receipt. Nil means validReceipt.
		base   func() *Receipt
		mutate func(*Receipt)
	}{
		{name: "decision downgraded to allow", mutate: func(r *Receipt) { r.Governance.Decision = DecisionAllow }},
		{
			name:   "mode upgraded to full",
			base:   degradedReceipt,
			mutate: func(r *Receipt) { r.Governance.Mode = ModeFull },
		},
		{
			name:   "detector health upgraded",
			base:   degradedReceipt,
			mutate: func(r *Receipt) { r.Governance.Detector.Health = HealthHealthy },
		},
		{
			name:   "failed component quietly removed",
			base:   degradedReceipt,
			mutate: func(r *Receipt) { r.Governance.Detector.Components = nil },
		},
		{name: "engine version rewritten", mutate: func(r *Receipt) { r.Governance.Detector.EngineVersion = "9.9.9" }},
		{name: "ruleset version rewritten", mutate: func(r *Receipt) { r.Governance.Detector.RulesetVersion = "fake" }},
		{name: "policy version rewritten", mutate: func(r *Receipt) { r.Governance.Policy.Version = "99" }},
		{name: "input digest swapped", mutate: func(r *Receipt) { r.Content.InputDigest = DigestContent([]byte("different")) }},
		{name: "output digest swapped", mutate: func(r *Receipt) { r.Content.OutputDigest = DigestContent([]byte("different")) }},
		{name: "byte count inflated", mutate: func(r *Receipt) { r.Content.Bytes = 999999 }},
		{name: "destination rewritten", mutate: func(r *Receipt) { r.Action.Destination = "evil.example" }},
		{name: "actor swapped", mutate: func(r *Receipt) { r.Actor.ID = "agent_someone_else" }},
		{name: "delegation removed", mutate: func(r *Receipt) { r.Actor.Delegation = nil }},
		{name: "delegation appended", mutate: func(r *Receipt) {
			r.Actor.Delegation = append(r.Actor.Delegation,
				DelegationHop{Type: ActorHuman, ID: "ceo@acme.com", Source: IdentityOIDC})
		}},
		{name: "finding count reduced", mutate: func(r *Receipt) { r.Governance.Findings[0].Count = 1000 }},
		{name: "finding removed", mutate: func(r *Receipt) { r.Governance.Findings = nil }},
		{name: "issued earlier", mutate: func(r *Receipt) { r.IssuedAt = FormatTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) }},
		{name: "chain sequence moved", mutate: func(r *Receipt) { r.Chain.Seq = 42; r.Chain.PrevHash = strings.Repeat("a", 64) }},
		{name: "chain id swapped", mutate: func(r *Receipt) { r.Chain.ID = "ws_other" }},
		{name: "receipt id swapped", mutate: func(r *Receipt) { r.ID = "rcpt_forged" }},
		{name: "issuer name spoofed", mutate: func(r *Receipt) { r.Issuer.Name = "Trusted Authority" }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signer, keys := testSigner(t)
			build := tc.base
			if build == nil {
				build = validReceipt
			}
			r := build()
			mustSign(t, r, signer)

			tc.mutate(r)

			_, err := Verify(r, keys, VerifyOptions{Now: time.Date(2026, 8, 13, 10, 5, 0, 0, time.UTC)})
			if err == nil {
				t.Fatal("tampered receipt verified successfully; the signature does not cover this field")
			}
			// The mutation must be caught either by the signature or, for
			// mutations that also break schema invariants, by validation.
			// Both are correct rejections; silently accepting is not.
			var fe FieldErrors
			if !errors.Is(err, ErrBadSignature) && !errors.As(err, &fe) &&
				!strings.Contains(err.Error(), "future") {
				t.Fatalf("unexpected rejection reason: %v", err)
			}
		})
	}
}

// TestSignatureValueTamper covers mutation of the signature itself rather
// than the payload.
func TestSignatureValueTamper(t *testing.T) {
	signer, keys := testSigner(t)
	r := validReceipt()
	mustSign(t, r, signer)

	raw, err := base64.StdEncoding.DecodeString(r.Signature.Value)
	if err != nil {
		t.Fatalf("decoding signature: %v", err)
	}
	raw[0] ^= 0xFF
	r.Signature.Value = base64.StdEncoding.EncodeToString(raw)

	if _, err := Verify(r, keys, VerifyOptions{Now: r.mustIssuedAt(t)}); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
}

// TestKeySubstitution proves a receipt signed by one key cannot be passed
// off as signed by another.
func TestKeySubstitution(t *testing.T) {
	signerA, _ := testSigner(t)
	signerB, err := GenerateEd25519Signer("key-test-1") // same ID, different key
	if err != nil {
		t.Fatalf("generating second signer: %v", err)
	}

	r := validReceipt()
	mustSign(t, r, signerA)

	// A verifier holding B's public key under the same ID must reject.
	keys := StaticKeyResolver{"key-test-1": signerB.Public()}
	if _, err := Verify(r, keys, VerifyOptions{Now: r.mustIssuedAt(t)}); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
}

// TestKeyIDMismatch proves a receipt whose signature and issuer disagree
// about the key is rejected, even when the signature itself is valid.
func TestKeyIDMismatch(t *testing.T) {
	signer, keys := testSigner(t)
	r := validReceipt()
	mustSign(t, r, signer)

	r.Issuer.KeyID = "key-someone-else"

	if _, err := Verify(r, keys, VerifyOptions{Now: r.mustIssuedAt(t)}); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("err = %v, want ErrKeyMismatch", err)
	}
}

// TestAlgorithmConfusion proves a verifier will not be talked into
// accepting an algorithm it does not implement.
func TestAlgorithmConfusion(t *testing.T) {
	signer, keys := testSigner(t)
	r := validReceipt()
	mustSign(t, r, signer)

	r.Signature.Algorithm = "none"

	if _, err := Verify(r, keys, VerifyOptions{Now: r.mustIssuedAt(t)}); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("err = %v, want ErrUnsupportedAlgorithm", err)
	}
}

// TestAlgorithmPolicyRejection proves a verifier can refuse an algorithm it
// implements but no longer trusts.
func TestAlgorithmPolicyRejection(t *testing.T) {
	signer, keys := testSigner(t)
	r := validReceipt()
	mustSign(t, r, signer)

	opts := VerifyOptions{
		Now:                r.mustIssuedAt(t),
		AcceptedAlgorithms: []Algorithm{"ml-dsa-65"},
	}
	if _, err := Verify(r, keys, opts); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("err = %v, want ErrUnsupportedAlgorithm", err)
	}
}

func TestUnknownKey(t *testing.T) {
	signer, _ := testSigner(t)
	r := validReceipt()
	mustSign(t, r, signer)

	if _, err := Verify(r, StaticKeyResolver{}, VerifyOptions{Now: r.mustIssuedAt(t)}); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("err = %v, want ErrUnknownKey", err)
	}
}

func TestMissingSignature(t *testing.T) {
	_, keys := testSigner(t)
	r := validReceipt()
	if _, err := Verify(r, keys, VerifyOptions{}); !errors.Is(err, ErrNoSignature) {
		t.Fatalf("err = %v, want ErrNoSignature", err)
	}
}

// --- Honesty invariants -----------------------------------------------------

// TestHonestyInvariants covers the rules that stop a receipt from asserting
// more governance than actually ran. Each case must be refused at signing
// time, before it can reach a third party.
func TestHonestyInvariants(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*Receipt)
		wantField string
	}{
		{
			name:      "full mode with unhealthy detector",
			mutate:    func(r *Receipt) { r.Governance.Detector.Health = HealthDegraded },
			wantField: "governance.mode",
		},
		{
			name: "healthy aggregate contradicting an unavailable component",
			mutate: func(r *Receipt) {
				r.Governance.Detector.Components = []Component{
					{Name: "onnx-pii", Health: HealthUnavailable},
				}
			},
			wantField: "governance.detector.health",
		},
		{
			name: "degraded mode without naming what failed",
			mutate: func(r *Receipt) {
				r.Governance.Mode = ModeDegraded
				r.Governance.Detector.Health = HealthDegraded
			},
			wantField: "governance.detector.components",
		},
		{
			name: "degraded mode with a healthy detector",
			mutate: func(r *Receipt) {
				r.Governance.Mode = ModeDegraded
				r.Governance.Detector.Components = []Component{{Name: "regex", Health: HealthHealthy}}
			},
			wantField: "governance.mode",
		},
		{
			name:      "missing engine version",
			mutate:    func(r *Receipt) { r.Governance.Detector.EngineVersion = "" },
			wantField: "governance.detector.engine_version",
		},
		{
			name:      "missing ruleset version",
			mutate:    func(r *Receipt) { r.Governance.Detector.RulesetVersion = "" },
			wantField: "governance.detector.ruleset_version",
		},
		{
			name:      "missing policy version",
			mutate:    func(r *Receipt) { r.Governance.Policy.Version = "" },
			wantField: "governance.policy.version",
		},
		{
			name: "bypassed governance claiming findings",
			mutate: func(r *Receipt) {
				r.Governance.Mode = ModeBypassed
				r.Governance.Decision = DecisionAllow
				r.Governance.Detector.Health = HealthUnavailable
				r.Governance.Detector.Components = []Component{{Name: "all", Health: HealthUnavailable}}
				r.Content.OutputDigest = r.Content.InputDigest
			},
			wantField: "governance.findings",
		},
		{
			name: "bypassed governance claiming enforcement",
			mutate: func(r *Receipt) {
				r.Governance.Mode = ModeBypassed
				r.Governance.Findings = nil
				r.Governance.Detector.Health = HealthUnavailable
				r.Governance.Detector.Components = []Component{{Name: "all", Health: HealthUnavailable}}
			},
			wantField: "governance.decision",
		},
		{
			name: "blocked action claiming released content",
			mutate: func(r *Receipt) {
				r.Governance.Decision = DecisionBlock
			},
			wantField: "content.output_digest",
		},
		{
			name: "allow decision with mismatched digests",
			mutate: func(r *Receipt) {
				r.Governance.Decision = DecisionAllow
				r.Governance.Findings = nil
			},
			wantField: "content.output_digest",
		},
		{
			name: "unverified web bot auth identity",
			mutate: func(r *Receipt) {
				r.Actor.Source = IdentityWebBotAuth
				r.Actor.Verified = false
			},
			wantField: "actor.verified",
		},
		{
			name: "verified identity with no source",
			mutate: func(r *Receipt) {
				r.Actor.Source = IdentityNone
				r.Actor.Verified = true
			},
			wantField: "actor.verified",
		},
		{
			name:      "genesis receipt claiming a predecessor",
			mutate:    func(r *Receipt) { r.Chain.PrevHash = strings.Repeat("b", 64) },
			wantField: "chain.prev_hash",
		},
		{
			name:      "non-genesis receipt with no predecessor",
			mutate:    func(r *Receipt) { r.Chain.Seq = 5 },
			wantField: "chain.prev_hash",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signer, _ := testSigner(t)
			r := validReceipt()
			tc.mutate(r)

			err := Sign(r, signer)
			if err == nil {
				t.Fatal("signing succeeded; an invalid receipt must never be signed")
			}
			var fe FieldErrors
			if !errors.As(err, &fe) {
				t.Fatalf("err = %T (%v), want FieldErrors", err, err)
			}
			found := false
			for _, f := range fe.Fields() {
				if f == tc.wantField {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("errors on %v, want a violation at %q", fe.Fields(), tc.wantField)
			}
			if r.Signature != nil {
				t.Error("a rejected receipt must not carry a signature")
			}
		})
	}
}

// TestDegradedReceiptIsValidButNotFullStrength proves the intended
// behaviour: honest degradation verifies successfully and is reported as
// degraded rather than being discarded.
func TestDegradedReceiptIsValidButNotFullStrength(t *testing.T) {
	signer, keys := testSigner(t)
	r := validReceipt()
	r.Governance.Mode = ModeDegraded
	r.Governance.Detector.Health = HealthDegraded
	r.Governance.Detector.Components = []Component{
		{Name: "onnx-pii", Health: HealthUnavailable, Detail: "sidecar unreachable"},
		{Name: "regex", Health: HealthHealthy},
	}
	mustSign(t, r, signer)

	res, err := Verify(r, keys, VerifyOptions{Now: r.mustIssuedAt(t)})
	if err != nil {
		t.Fatalf("a degraded receipt must still verify: %v", err)
	}
	if !res.Valid {
		t.Error("expected Valid")
	}
	if res.FullStrength {
		t.Error("expected FullStrength false")
	}
	if len(res.Warnings) == 0 {
		t.Fatal("expected a warning describing the degradation")
	}
	if !strings.Contains(res.Warnings[0], "onnx-pii") {
		t.Errorf("warning %q does not name the failed component", res.Warnings[0])
	}
}

func TestRequireFullStrengthRejectsDegraded(t *testing.T) {
	signer, keys := testSigner(t)
	r := validReceipt()
	r.Governance.Mode = ModeDegraded
	r.Governance.Detector.Health = HealthDegraded
	r.Governance.Detector.Components = []Component{{Name: "onnx-pii", Health: HealthUnavailable}}
	mustSign(t, r, signer)

	res, err := Verify(r, keys, VerifyOptions{Now: r.mustIssuedAt(t), RequireFullStrength: true})
	if err == nil {
		t.Fatal("expected rejection under RequireFullStrength")
	}
	// The result is still returned so a caller can explain *why* it was
	// rejected rather than reporting an opaque failure.
	if res == nil || res.Mode != ModeDegraded {
		t.Error("expected the result to be returned alongside the error")
	}
}

// --- Clock handling ---------------------------------------------------------

func TestFutureReceiptRejected(t *testing.T) {
	signer, keys := testSigner(t)
	r := validReceipt()
	mustSign(t, r, signer)

	// One hour before issuance, well beyond the default five-minute skew.
	past := r.mustIssuedAt(t).Add(-time.Hour)
	if _, err := Verify(r, keys, VerifyOptions{Now: past}); err == nil {
		t.Fatal("expected rejection of a receipt issued in the future")
	}
}

func TestClockSkewTolerated(t *testing.T) {
	signer, keys := testSigner(t)
	r := validReceipt()
	mustSign(t, r, signer)

	// Two minutes of drift is inside the default tolerance.
	slightlyBehind := r.mustIssuedAt(t).Add(-2 * time.Minute)
	if _, err := Verify(r, keys, VerifyOptions{Now: slightlyBehind}); err != nil {
		t.Fatalf("expected tolerance of minor clock drift: %v", err)
	}
}

func TestMaxAgeEnforced(t *testing.T) {
	signer, keys := testSigner(t)
	r := validReceipt()
	mustSign(t, r, signer)

	opts := VerifyOptions{Now: r.mustIssuedAt(t).Add(48 * time.Hour), MaxAge: 24 * time.Hour}
	if _, err := Verify(r, keys, opts); err == nil {
		t.Fatal("expected rejection of a receipt older than MaxAge")
	}
}

// --- Canonicalisation -------------------------------------------------------

func TestCanonicalDeterminism(t *testing.T) {
	r := validReceipt()
	first, err := SigningInput(r)
	if err != nil {
		t.Fatalf("canonicalising: %v", err)
	}
	for i := 0; i < 50; i++ {
		next, err := SigningInput(r)
		if err != nil {
			t.Fatalf("canonicalising: %v", err)
		}
		if string(first) != string(next) {
			t.Fatal("canonical form is not deterministic across repeated calls")
		}
	}
}

func TestCanonicalExcludesSignatureAndAnchors(t *testing.T) {
	signer, _ := testSigner(t)
	r := validReceipt()
	mustSign(t, r, signer)

	before, err := SigningInput(r)
	if err != nil {
		t.Fatalf("canonicalising: %v", err)
	}

	// Attaching an anchor after signing must not disturb the signing input,
	// or anchoring would retroactively invalidate every receipt.
	r.Anchors = append(r.Anchors, Anchor{
		Type:       AnchorRFC3161,
		Value:      "MIIBog...",
		AnchoredAt: FormatTime(time.Date(2026, 8, 13, 10, 1, 0, 0, time.UTC)),
	})

	after, err := SigningInput(r)
	if err != nil {
		t.Fatalf("canonicalising: %v", err)
	}
	if string(before) != string(after) {
		t.Error("attaching an anchor changed the signing input")
	}
}

func TestAnchorAttachmentPreservesVerification(t *testing.T) {
	signer, keys := testSigner(t)
	r := validReceipt()
	mustSign(t, r, signer)

	r.Anchors = []Anchor{{
		Type:       AnchorOpenTimestamps,
		Value:      "AE9wZW5UaW1lc3RhbXBz",
		AnchoredAt: FormatTime(time.Date(2026, 8, 13, 10, 30, 0, 0, time.UTC)),
	}}

	if _, err := Verify(r, keys, VerifyOptions{Now: r.mustIssuedAt(t).Add(time.Hour)}); err != nil {
		t.Fatalf("verification must survive anchor attachment: %v", err)
	}
}

func TestCanonicalKeyOrdering(t *testing.T) {
	got, err := Canonicalize(map[string]any{"b": 1, "a": 2, "C": 3, "é": 4, "A": 5})
	if err != nil {
		t.Fatalf("canonicalising: %v", err)
	}
	// Uppercase sorts before lowercase by code unit; the accented character
	// sorts last.
	want := `{"A":5,"C":3,"a":2,"b":1,"é":4}`
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

// TestCanonicalUTF16Ordering covers the case where UTF-16 code unit order
// diverges from code point order: a supplementary character encodes as a
// surrogate pair starting at 0xD800, so it sorts before U+E000..U+FFFF.
func TestCanonicalUTF16Ordering(t *testing.T) {
	// U+1F600 GRINNING FACE (supplementary) vs U+FB00 LATIN SMALL LIGATURE FF.
	// By code point, U+FB00 < U+1F600. By UTF-16 code unit, the surrogate
	// pair 0xD83D... < 0xFB00, so the emoji must sort first.
	got, err := Canonicalize(map[string]any{"\U0001F600": 1, "ﬀ": 2})
	if err != nil {
		t.Fatalf("canonicalising: %v", err)
	}
	want := "{\"\U0001F600\":1,\"ﬀ\":2}"
	if string(got) != want {
		t.Errorf("UTF-16 ordering wrong\ngot  %s\nwant %s", got, want)
	}
}

// TestCanonicalStringEscaping pins the escaping rules, which differ from
// encoding/json's defaults in ways that would silently break interop.
func TestCanonicalStringEscaping(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"html characters are not escaped", `<a href="x">&`, `"<a href=\"x\">&"`},
		{"backslash and quote", "a\\b\"c", `"a\\b\"c"`},
		{"short escapes", "\b\f\n\r\t", `"\b\f\n\r\t"`},
		{"control characters use lowercase hex", "\x00\x1f", `"\u0000\u001f"`},
		{"unicode is emitted literally", "café ☕", `"café ☕"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Canonicalize(tc.in)
			if err != nil {
				t.Fatalf("canonicalising: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("got  %s\nwant %s", got, tc.want)
			}
		})
	}
}

// TestCanonicalRejectsFloats proves the schema restriction is enforced
// rather than assumed. A float reaching the signing path would produce
// signatures other implementations could not reproduce.
func TestCanonicalRejectsFloats(t *testing.T) {
	for _, v := range []any{1.5, map[string]any{"x": 0.1}, []any{2.75}} {
		if _, err := Canonicalize(v); err == nil {
			t.Errorf("Canonicalize(%v) succeeded; non-integral numbers must be refused", v)
		} else {
			var ce *CanonicalizationError
			if !errors.As(err, &ce) {
				t.Errorf("err = %T, want *CanonicalizationError", err)
			}
		}
	}
	// Integral values expressed as floats are fine: they have one
	// unambiguous representation.
	if _, err := Canonicalize(map[string]any{"x": float64(42)}); err != nil {
		t.Errorf("integral float rejected: %v", err)
	}
}

// --- Chain ------------------------------------------------------------------

func buildChain(t *testing.T, signer Signer, n int) []*Receipt {
	t.Helper()
	b, err := NewChainBuilder("ws_acme", signer)
	if err != nil {
		t.Fatalf("chain builder: %v", err)
	}
	out := make([]*Receipt, 0, n)
	base := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		r := validReceipt()
		r.ID = "rcpt_" + itoa(i)
		r.IssuedAt = FormatTime(base.Add(time.Duration(i) * time.Second))
		if err := b.Issue(r); err != nil {
			t.Fatalf("issuing receipt %d: %v", i, err)
		}
		out = append(out, r)
	}
	return out
}

func TestChainVerifies(t *testing.T) {
	signer, keys := testSigner(t)
	chain := buildChain(t, signer, 5)

	res, err := VerifyChain(chain, keys, VerifyOptions{Now: time.Date(2026, 8, 13, 11, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("verifying chain: %v", err)
	}
	if res.Length != 5 {
		t.Errorf("length = %d, want 5", res.Length)
	}
	if res.Degraded != 0 || res.Bypassed != 0 {
		t.Errorf("unexpected degraded=%d bypassed=%d", res.Degraded, res.Bypassed)
	}
	if res.Head == "" {
		t.Error("expected a head digest")
	}
}

// TestChainDetectsDeletion is the property that makes a chain worth having:
// removing a receipt from the middle must be detectable.
func TestChainDetectsDeletion(t *testing.T) {
	signer, keys := testSigner(t)
	chain := buildChain(t, signer, 5)

	withHole := append(append([]*Receipt{}, chain[:2]...), chain[3:]...)

	_, err := VerifyChain(withHole, keys, VerifyOptions{Now: time.Date(2026, 8, 13, 11, 0, 0, 0, time.UTC)})
	if !errors.Is(err, ErrChainDiscontinuous) {
		t.Fatalf("err = %v, want ErrChainDiscontinuous", err)
	}
}

// TestChainDetectsSubstitution covers replacing a receipt's contents with a
// separately valid receipt: the signature verifies, but the link does not.
func TestChainDetectsSubstitution(t *testing.T) {
	signer, keys := testSigner(t)
	chain := buildChain(t, signer, 4)

	// Re-sign position 1 with different content but its original chain
	// position, so the signature is genuine and only the link is wrong.
	forged := validReceipt()
	forged.ID = "rcpt_forged"
	forged.IssuedAt = chain[1].IssuedAt
	forged.Governance.Decision = DecisionAllow
	forged.Governance.Findings = nil
	forged.Content.OutputDigest = forged.Content.InputDigest
	forged.Chain = chain[1].Chain
	mustSign(t, forged, signer)
	chain[1] = forged

	_, err := VerifyChain(chain, keys, VerifyOptions{Now: time.Date(2026, 8, 13, 11, 0, 0, 0, time.UTC)})
	if !errors.Is(err, ErrChainBroken) {
		t.Fatalf("err = %v, want ErrChainBroken", err)
	}
}

func TestChainDetectsMixedChains(t *testing.T) {
	signer, keys := testSigner(t)
	chain := buildChain(t, signer, 3)

	other, err := NewChainBuilder("ws_other", signer)
	if err != nil {
		t.Fatalf("chain builder: %v", err)
	}
	stray := validReceipt()
	stray.IssuedAt = chain[2].IssuedAt
	if err := other.Issue(stray); err != nil {
		t.Fatalf("issuing stray: %v", err)
	}
	chain[2] = stray

	_, err = VerifyChain(chain, keys, VerifyOptions{Now: time.Date(2026, 8, 13, 11, 0, 0, 0, time.UTC)})
	if !errors.Is(err, ErrChainMixed) {
		t.Fatalf("err = %v, want ErrChainMixed", err)
	}
}

func TestChainResume(t *testing.T) {
	signer, keys := testSigner(t)
	chain := buildChain(t, signer, 3)

	head, err := Digest(chain[2])
	if err != nil {
		t.Fatalf("digesting head: %v", err)
	}

	resumed, err := ResumeChainBuilder("ws_acme", signer, 3, head)
	if err != nil {
		t.Fatalf("resuming: %v", err)
	}
	next := validReceipt()
	next.ID = "rcpt_after_restart"
	next.IssuedAt = FormatTime(time.Date(2026, 8, 13, 10, 0, 3, 0, time.UTC))
	if err := resumed.Issue(next); err != nil {
		t.Fatalf("issuing after resume: %v", err)
	}

	full := append(chain, next)
	if _, err := VerifyChain(full, keys, VerifyOptions{Now: time.Date(2026, 8, 13, 11, 0, 0, 0, time.UTC)}); err != nil {
		t.Fatalf("chain must survive a restart: %v", err)
	}
}

// TestChainDoesNotAdvanceOnFailure proves a rejected receipt leaves no gap.
// If the builder advanced on failure, the next successful receipt would skip
// a sequence number and every verifier would report a deletion that never
// happened.
func TestChainDoesNotAdvanceOnFailure(t *testing.T) {
	signer, _ := testSigner(t)
	b, err := NewChainBuilder("ws_acme", signer)
	if err != nil {
		t.Fatalf("chain builder: %v", err)
	}

	good := validReceipt()
	if err := b.Issue(good); err != nil {
		t.Fatalf("issuing: %v", err)
	}
	seqAfterGood := b.NextSeq()
	headAfterGood := b.Head()

	bad := validReceipt()
	bad.Governance.Detector.EngineVersion = "" // invalid
	if err := b.Issue(bad); err == nil {
		t.Fatal("expected the invalid receipt to be refused")
	}

	if b.NextSeq() != seqAfterGood {
		t.Errorf("sequence advanced past a failure: %d, want %d", b.NextSeq(), seqAfterGood)
	}
	if b.Head() != headAfterGood {
		t.Error("chain head moved despite a failure")
	}
}

// --- Interfaces -------------------------------------------------------------

// TestSignerInterfaceIsSatisfiable proves an external signer — a key vault
// or HSM, where the private key never enters this process — can implement
// Signer without touching the package.
func TestSignerInterfaceIsSatisfiable(t *testing.T) {
	var _ Signer = (*Ed25519Signer)(nil)

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	remote := &fakeRemoteSigner{keyID: "kv-managed-key-1", pub: pub, priv: priv}

	r := validReceipt()
	r.Issuer.KeyID = remote.KeyID()
	mustSign(t, r, remote)

	keys := StaticKeyResolver{remote.KeyID(): pub}
	if _, err := Verify(r, keys, VerifyOptions{Now: r.mustIssuedAt(t)}); err != nil {
		t.Fatalf("verifying externally signed receipt: %v", err)
	}
}

// fakeRemoteSigner stands in for a key management service.
type fakeRemoteSigner struct {
	keyID string
	pub   ed25519.PublicKey
	priv  ed25519.PrivateKey
}

func (f *fakeRemoteSigner) KeyID() string            { return f.keyID }
func (f *fakeRemoteSigner) Algorithm() Algorithm     { return AlgEd25519 }
func (f *fakeRemoteSigner) Public() crypto.PublicKey { return f.pub }
func (f *fakeRemoteSigner) Sign(input []byte) ([]byte, error) {
	return ed25519.Sign(f.priv, input), nil
}
