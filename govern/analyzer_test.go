package govern

import (
	"context"
	"strings"
	"testing"

	"github.com/lynt-x-global/lyntway-tools/detect"
	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// fakeAnalyzer returns fixed spans and a settable health.
type fakeAnalyzer struct {
	name   string
	spans  []detect.Span
	health receipt.Health
	calls  int
	err    error
}

func (f *fakeAnalyzer) Name() string { return f.name }

func (f *fakeAnalyzer) Analyze(context.Context, []byte) ([]detect.Span, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return append([]detect.Span{}, f.spans...), nil
}

func (f *fakeAnalyzer) Health() receipt.Health { return f.health }

func analyzerEngine(t *testing.T, a Analyzer) (*Engine, receipt.StaticKeyResolver) {
	t.Helper()
	signer, err := receipt.GenerateEd25519Signer("test-key-1")
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(Config{Signer: signer, Analyzers: []Analyzer{a}})
	if err != nil {
		t.Fatal(err)
	}
	return e, receipt.StaticKeyResolver{signer.KeyID(): signer.Public()}
}

// The property that keeps receipts worth anything once a model is involved:
// a reader must be able to tell a reproducible finding from a probabilistic
// one. Presenting them identically would let every receipt silently inherit
// the weaker claim.
func TestModelFindingsNameTheirDetector(t *testing.T) {
	// "Priya Raman" at bytes 6..17 of the content below.
	a := &fakeAnalyzer{
		name:   "presidio",
		health: receipt.HealthHealthy,
		spans: []detect.Span{{
			Class: "pii.person_name", Rule: "presidio/PERSON",
			Start: 6, End: 17, Value: "Priya Raman", Confidence: detect.ConfidenceHigh,
		}},
	}
	e, _ := analyzerEngine(t, a)

	res, err := e.Govern(req("rcpt_ml", "mail  Priya Raman at priya@acme.co.in", testScope(t)))
	if err != nil {
		t.Fatalf("governing: %v", err)
	}

	byClass := map[string]receipt.Finding{}
	for _, f := range res.Receipt.Governance.Findings {
		byClass[f.Class] = f
	}

	person, found := byClass["pii.person_name"]
	if !found {
		t.Fatalf("the model finding is absent: %+v", res.Receipt.Governance.Findings)
	}
	if person.Detector != "presidio" {
		t.Errorf("detector = %q, want presidio — a probabilistic finding must name its source", person.Detector)
	}

	// And the deterministic one must stay unlabelled, which is what marks
	// it as the reproducible tier.
	email, found := byClass["pii.email"]
	if !found {
		t.Fatal("the rule-based finding is absent")
	}
	if email.Detector != "" {
		t.Errorf("detector = %q on a rule finding, want empty", email.Detector)
	}
}

// One analyzer can front several models, and a receipt naming the specific
// one is more useful to whoever has to judge the finding. It is allowed
// only under the analyzer's own prefix — anything else is a claim about
// something the analyzer is not.
func TestAnAnalyzerMayNameTheModelBehindAFinding(t *testing.T) {
	a := &fakeAnalyzer{
		name:   "analyzer",
		health: receipt.HealthHealthy,
		spans: []detect.Span{{
			Class: "pii.person_name", Rule: "presidio/PERSON", Detector: "analyzer/presidio+en_core_web_md",
			Start: 6, End: 17, Value: "Priya Raman", Confidence: detect.ConfidenceHigh,
		}},
	}
	e, _ := analyzerEngine(t, a)

	res, err := e.Govern(req("rcpt_sub", "mail  Priya Raman at priya@acme.co.in", testScope(t)))
	if err != nil {
		t.Fatalf("governing: %v", err)
	}
	for _, f := range res.Receipt.Governance.Findings {
		if f.Class == "pii.person_name" && f.Detector != "analyzer/presidio+en_core_web_md" {
			t.Errorf("detector = %q, want the specific model preserved", f.Detector)
		}
	}
}

// The attribution an analyzer must never be able to make.
//
// An empty detector means the deterministic ruleset — the tier whose
// findings can be re-derived from a pinned ruleset digest months later. An
// analyzer claiming it would launder a probabilistic guess into the one
// claim this product makes that nobody else does. Naming a different
// analyzer is the same lie pointed elsewhere.
func TestAnAnalyzerCannotAttributeItsFindingsElsewhere(t *testing.T) {
	for _, claimed := range []string{"", "someone-else", "analyzer-evil", "presidio"} {
		a := &fakeAnalyzer{
			name:   "analyzer",
			health: receipt.HealthHealthy,
			spans: []detect.Span{{
				Class: "pii.person_name", Rule: "presidio/PERSON", Detector: claimed,
				Start: 6, End: 17, Value: "Priya Raman", Confidence: detect.ConfidenceHigh,
			}},
		}
		e, _ := analyzerEngine(t, a)

		res, err := e.Govern(req("rcpt_forge", "mail  Priya Raman at priya@acme.co.in", testScope(t)))
		if err != nil {
			t.Fatalf("governing: %v", err)
		}
		for _, f := range res.Receipt.Governance.Findings {
			if f.Class != "pii.person_name" {
				continue
			}
			if f.Detector != "analyzer" {
				t.Errorf("an analyzer claiming detector %q was reported as %q, want %q",
					claimed, f.Detector, "analyzer")
			}
		}
	}
}

// An analyzer that is down must make the receipt say so. This is the whole
// reason the mode field exists, and the first thing to use it.
func TestAnUnavailableAnalyzerDegradesTheReceipt(t *testing.T) {
	a := &fakeAnalyzer{name: "presidio", health: receipt.HealthUnavailable}
	e, _ := analyzerEngine(t, a)

	res, err := e.Govern(req("rcpt_down", "mail priya@acme.co.in", testScope(t)))
	if err != nil {
		t.Fatalf("governing: %v", err)
	}

	if res.Receipt.Governance.Mode != receipt.ModeDegraded {
		t.Errorf("mode = %q, want degraded — the model did not run", res.Receipt.Governance.Mode)
	}
	// The rules still ran, which is the other half: a model outage must not
	// stop governance.
	if len(res.Receipt.Governance.Findings) == 0 {
		t.Error("nothing was detected; the deterministic tier should still have run")
	}
	// And an analyzer that reported itself unavailable is not called.
	if a.calls != 0 {
		t.Errorf("an unavailable analyzer was called %d times", a.calls)
	}
}

// A failing call must not fail the request. Their outage is not the
// customer's.
func TestAFailingAnalyzerDoesNotFailTheRequest(t *testing.T) {
	a := &fakeAnalyzer{name: "presidio", health: receipt.HealthHealthy, err: context.DeadlineExceeded}
	e, _ := analyzerEngine(t, a)

	res, err := e.Govern(req("rcpt_slow", "mail priya@acme.co.in", testScope(t)))
	if err != nil {
		t.Fatalf("a failing analyzer failed the request: %v", err)
	}
	if len(res.Receipt.Governance.Findings) == 0 {
		t.Error("the deterministic tier did not run")
	}
}

// Where both tiers claim the same bytes, the rules win. A Luhn-checked card
// number is not improved by a model agreeing, and replacing it would swap a
// reproducible finding for one that is not.
func TestDeterministicFindingsWinOverlaps(t *testing.T) {
	content := "card 4111 1111 1111 1111 here"
	a := &fakeAnalyzer{
		name:   "presidio",
		health: receipt.HealthHealthy,
		spans: []detect.Span{{
			Class: "pii.person_name", Rule: "presidio/PERSON",
			Start: 5, End: 24, Value: content[5:24], Confidence: detect.ConfidenceHigh,
		}},
	}
	e, _ := analyzerEngine(t, a)

	res, err := e.Govern(req("rcpt_overlap", content, testScope(t)))
	if err != nil {
		t.Fatalf("governing: %v", err)
	}

	var sawCard, sawPerson bool
	for _, f := range res.Receipt.Governance.Findings {
		switch f.Class {
		case "pci.card_number":
			sawCard = true
		case "pii.person_name":
			sawPerson = true
		}
	}
	if !sawCard {
		t.Error("a model span displaced a checksum-validated card number")
	}
	if sawPerson {
		t.Error("an overlapping model span was kept alongside the rule finding")
	}
}

// A receipt carrying a model finding must still verify, and must still
// describe itself honestly.
func TestAReceiptWithModelFindingsVerifies(t *testing.T) {
	a := &fakeAnalyzer{
		name:   "presidio",
		health: receipt.HealthHealthy,
		spans: []detect.Span{{
			Class: "pii.person_name", Rule: "presidio/PERSON",
			Start: 0, End: 11, Value: "Priya Raman", Confidence: detect.ConfidenceHigh,
		}},
	}
	e, keys := analyzerEngine(t, a)

	res, err := e.Govern(req("rcpt_verify_ml", "Priya Raman wrote in", testScope(t)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := receipt.Verify(res.Receipt, keys, receipt.VerifyOptions{}); err != nil {
		t.Errorf("verifying: %v", err)
	}

	// The component health names the analyzer, so a reader can see which
	// detector was part of the scan.
	var named bool
	for _, c := range res.Receipt.Governance.Detector.Components {
		if strings.Contains(c.Name, "presidio") {
			named = true
		}
	}
	if !named {
		t.Errorf("the analyzer is not named in the receipt's components: %+v",
			res.Receipt.Governance.Detector.Components)
	}
}
