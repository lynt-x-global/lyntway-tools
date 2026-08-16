package govern

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/lynt-x-global/lyntway-tools/detect"
	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// The leak this prevents: a payload containing findings marked for
// different actions had only one of them applied. An email marked for
// tokenisation was released in the clear because something else in the same
// payload was marked for redaction — and the receipt said "redact", which
// was true about the strongest action taken and therefore hid the gap
// completely.
//
// Unreachable with the built-in policy, which never redacts. It became
// reachable the moment a customer could choose redact for a rule of their
// own, which is exactly the kind of latent gap a new feature exposes.
func TestMixedDecisionsAreAllApplied(t *testing.T) {
	e, _ := testEngine(t)

	// A policy that redacts one class and tokenises another, as a customer
	// mixing their own rules with the built-in ones would produce.
	policy := *DefaultPolicy()
	policy.Rules = append([]PolicyRule{
		{Class: "custom.codename", Decision: receipt.DecisionRedact},
	}, policy.Rules...)

	rules := append(detect.Default().Rules(), detect.Rule{
		ID:         "custom-codename",
		Class:      "custom.codename",
		Pattern:    mustCompile(`\bProject Voyager\b`),
		Confidence: detect.ConfidenceHigh,
		Priority:   10,
	})

	r := req("rcpt_mixed", "Project Voyager budget, cc priya.raman@acme.co.in today", testScope(t))
	r.Ruleset = detect.NewRuleset("mixed", rules)
	r.Policy = &policy

	res, err := e.Govern(r)
	if err != nil {
		t.Fatalf("governing: %v", err)
	}

	got := string(res.Content)

	// The redacted one is gone.
	if strings.Contains(got, "Project Voyager") {
		t.Errorf("the redact-marked finding survived: %q", got)
	}
	// And so is the tokenised one, which is the half that used to leak.
	if strings.Contains(got, "priya.raman@acme.co.in") {
		t.Errorf("the tokenise-marked finding was released in the clear: %q", got)
	}
	if !strings.Contains(got, "@tokenized.invalid") {
		t.Errorf("no token was substituted: %q", got)
	}
	if !strings.Contains(got, "[REDACTED:custom.codename]") {
		t.Errorf("no redaction marker was written: %q", got)
	}

	// Both findings are on the receipt, each with its own decision.
	decisions := map[string]receipt.Decision{}
	for _, f := range res.Receipt.Governance.Findings {
		decisions[f.Class] = f.Decision
	}
	if decisions["custom.codename"] != receipt.DecisionRedact {
		t.Errorf("codename decision = %q, want redact", decisions["custom.codename"])
	}
	if decisions["pii.email"] != receipt.DecisionTokenize {
		t.Errorf("email decision = %q, want tokenize", decisions["pii.email"])
	}
}

// A finding the policy only records must still pass through untouched, or
// the fix above would have traded one over-reach for another.
func TestLoggedFindingsAreStillLeftAlone(t *testing.T) {
	e, _ := testEngine(t)

	policy := *DefaultPolicy()
	policy.Rules = append([]PolicyRule{
		{Class: "custom.note", Decision: receipt.DecisionLogOnly},
		{Class: "custom.codename", Decision: receipt.DecisionRedact},
	}, policy.Rules...)

	rules := append(detect.Default().Rules(),
		detect.Rule{ID: "custom-note", Class: "custom.note",
			Pattern: mustCompile(`\bdraft\b`), Confidence: detect.ConfidenceHigh, Priority: 10},
		detect.Rule{ID: "custom-codename", Class: "custom.codename",
			Pattern: mustCompile(`\bVoyager\b`), Confidence: detect.ConfidenceHigh, Priority: 10},
	)

	r := req("rcpt_logged", "Voyager draft attached", testScope(t))
	r.Ruleset = detect.NewRuleset("mixed", rules)
	r.Policy = &policy

	res, err := e.Govern(r)
	if err != nil {
		t.Fatalf("governing: %v", err)
	}
	if !bytes.Contains(res.Content, []byte("draft")) {
		t.Errorf("a log_only finding was rewritten: %q", res.Content)
	}
	if bytes.Contains(res.Content, []byte("Voyager")) {
		t.Errorf("the redact-marked finding survived: %q", res.Content)
	}
}

func mustCompile(pattern string) *regexp.Regexp { return regexp.MustCompile(pattern) }
