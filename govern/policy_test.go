package govern

import (
	"strings"
	"testing"

	"github.com/lynt-x-global/lyntway-tools/detect"
	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// The case the upstream condition exists for: the same class treated
// differently depending on where the content is going.
func TestARuleScopedToAnUpstreamOnlyFiresThere(t *testing.T) {
	p := &Policy{
		ID: "p", Version: "1",
		Rules: []PolicyRule{
			{Class: detect.ClassEmail, Upstream: "lawmatics", Decision: receipt.DecisionAllow},
			{Family: "pii", Decision: receipt.DecisionTokenize},
		},
		Default: receipt.DecisionAllow,
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}

	if got := p.DecideFor("lawmatics", "", detect.ClassEmail, detect.ConfidenceHigh); got != receipt.DecisionAllow {
		t.Errorf("to lawmatics: %q, want allow from the scoped rule", got)
	}
	if got := p.DecideFor("openai", "", detect.ClassEmail, detect.ConfidenceHigh); got != receipt.DecisionTokenize {
		t.Errorf("to openai: %q, want tokenize from the general rule", got)
	}
	// No target means the condition could not be checked, and an unmet
	// condition must not read as met.
	if got := p.Decide(detect.ClassEmail, detect.ConfidenceHigh); got != receipt.DecisionTokenize {
		t.Errorf("with no target: %q, want tokenize; a scoped allowance must not apply everywhere", got)
	}
	// Exact, not prefix or case-folded: the gateway lower-cases names.
	if got := p.DecideFor("lawmatics-eu", "", detect.ClassEmail, detect.ConfidenceHigh); got != receipt.DecisionTokenize {
		t.Errorf("to lawmatics-eu: %q, the scoped rule matched a different upstream", got)
	}
}

// Declared order is honoured for scoped rules like every other rule, so a
// scoped rule after a general one is dead — and the policy says so rather
// than reordering it.
func TestASpecificRuleAfterAGeneralOneIsReportedUnreachable(t *testing.T) {
	general := PolicyRule{Family: "pii", Decision: receipt.DecisionTokenize}
	specific := PolicyRule{Class: detect.ClassEmail, Upstream: "lawmatics", Decision: receipt.DecisionAllow}

	shadowed := &Policy{ID: "p", Version: "1", Rules: []PolicyRule{general, specific}, Default: receipt.DecisionAllow}
	if got := shadowed.DecideFor("lawmatics", "", detect.ClassEmail, detect.ConfidenceHigh); got != receipt.DecisionTokenize {
		t.Errorf("decision = %q; the engine reordered a scoped rule to the front", got)
	}
	warnings := shadowed.Warnings()
	if len(warnings) != 1 {
		t.Fatalf("warnings = %q, want exactly one for the dead rule", warnings)
	}
	if !strings.Contains(warnings[0], "rule 1") || !strings.Contains(warnings[0], "lawmatics") {
		t.Errorf("warning does not name the dead rule: %q", warnings[0])
	}
	if err := shadowed.Validate(); err != nil {
		t.Errorf("an unreachable rule is a warning, not an invalid policy: %v", err)
	}

	ordered := &Policy{ID: "p", Version: "1", Rules: []PolicyRule{specific, general}, Default: receipt.DecisionAllow}
	if w := ordered.Warnings(); len(w) != 0 {
		t.Errorf("specific-first produced warnings: %q", w)
	}

	// A general rule with a stricter threshold leaves the weaker findings
	// for the later one, so that ordering is live.
	strict := PolicyRule{Family: "pii", MinConfidence: detect.ConfidenceHigh, Decision: receipt.DecisionTokenize}
	weak := PolicyRule{Class: detect.ClassEmail, Upstream: "lawmatics", Decision: receipt.DecisionLogOnly}
	live := &Policy{ID: "p", Version: "1", Rules: []PolicyRule{strict, weak}, Default: receipt.DecisionAllow}
	if w := live.Warnings(); len(w) != 0 {
		t.Errorf("a rule reachable below the earlier threshold was reported dead: %q", w)
	}

	// Two different upstreams never shadow each other.
	a := PolicyRule{Class: detect.ClassEmail, Upstream: "openai", Decision: receipt.DecisionTokenize}
	b := PolicyRule{Class: detect.ClassEmail, Upstream: "lawmatics", Decision: receipt.DecisionAllow}
	if w := (&Policy{ID: "p", Version: "1", Rules: []PolicyRule{a, b}, Default: receipt.DecisionAllow}).Warnings(); len(w) != 0 {
		t.Errorf("rules for different upstreams reported as shadowing: %q", w)
	}

	if w := DefaultPolicy().Warnings(); len(w) != 0 {
		t.Errorf("the shipped policy has unreachable rules: %q", w)
	}
}

// Upstream names are compared exactly against what the gateway records,
// which is lower-case. A rule that could only ever miss is refused.
func TestAPolicyRuleUpstreamMustBeLowerCase(t *testing.T) {
	p := &Policy{
		ID: "p", Version: "1",
		Rules:   []PolicyRule{{Class: detect.ClassEmail, Upstream: "Lawmatics", Decision: receipt.DecisionAllow}},
		Default: receipt.DecisionAllow,
	}
	if err := p.Validate(); err == nil {
		t.Error("a rule naming an upstream in mixed case was accepted")
	}
}

// The seam: the same payload governed for two targets gets two decisions,
// and the bytes follow the decision — a receipt that said tokenize while
// the transform decided without a target would describe a substitution
// that never happened.
func TestTheSamePayloadIsDecidedPerTarget(t *testing.T) {
	e, _ := testEngine(t)
	policy := &Policy{
		ID: "tenant-policy", Version: "1",
		Rules: []PolicyRule{
			{Class: detect.ClassEmail, Upstream: "lawmatics", Decision: receipt.DecisionAllow},
			{Family: "pci", Decision: receipt.DecisionTokenize},
			{Family: "pii", MinConfidence: detect.ConfidenceHigh, Decision: receipt.DecisionTokenize},
		},
		Default: receipt.DecisionAllow,
	}

	govern := func(target string) *Result {
		t.Helper()
		r := req("r-"+target, "Email priya@acme.com about the invoice.", testScope(t))
		r.Action.Target = target
		r.Policy = policy
		res, err := e.Govern(r)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	toCRM := govern("lawmatics")
	if toCRM.Decision != receipt.DecisionAllow {
		t.Errorf("to lawmatics: decision %q, want allow", toCRM.Decision)
	}
	if !strings.Contains(string(toCRM.Content), "priya@acme.com") {
		t.Error("to lawmatics: the address was substituted despite the allow")
	}
	if f := findingFor(toCRM.Receipt, detect.ClassEmail); f == nil || f.Decision != receipt.DecisionAllow {
		t.Errorf("to lawmatics: finding = %+v, want an email finding decided allow", f)
	}

	toModel := govern("openai")
	if toModel.Decision != receipt.DecisionTokenize {
		t.Errorf("to openai: decision %q, want tokenize", toModel.Decision)
	}
	if strings.Contains(string(toModel.Content), "priya@acme.com") {
		t.Error("to openai: the address left unsubstituted")
	}
	if f := findingFor(toModel.Receipt, detect.ClassEmail); f == nil || f.Decision != receipt.DecisionTokenize {
		t.Errorf("to openai: finding = %+v, want an email finding decided tokenize", f)
	}

	// The transform runs only when something in the payload is substituted,
	// so the seam that matters is a mixed one: a card tokenised everywhere
	// beside an address allowed here. If the transform decided without the
	// target, the address would be substituted too and the receipt would
	// still say allow for it.
	mixed := req("r-mixed", "Card 4111111111111111 for priya@acme.com.", testScope(t))
	mixed.Action.Target = "lawmatics"
	mixed.Policy = policy
	res, err := e.Govern(mixed)
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != receipt.DecisionTokenize {
		t.Errorf("mixed to lawmatics: decision %q, want tokenize for the card", res.Decision)
	}
	if strings.Contains(string(res.Content), "4111111111111111") {
		t.Error("mixed to lawmatics: the card left unsubstituted")
	}
	if !strings.Contains(string(res.Content), "priya@acme.com") {
		t.Errorf("mixed to lawmatics: the address was substituted although the receipt says allow: %s", res.Content)
	}
	if f := findingFor(res.Receipt, detect.ClassEmail); f == nil || f.Decision != receipt.DecisionAllow {
		t.Errorf("mixed to lawmatics: email finding = %+v, want allow", f)
	}
}

func findingFor(r *receipt.Receipt, class detect.Class) *receipt.Finding {
	for i := range r.Governance.Findings {
		if r.Governance.Findings[i].Class == string(class) {
			return &r.Governance.Findings[i]
		}
	}
	return nil
}
