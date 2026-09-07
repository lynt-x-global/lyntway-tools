package govern

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/lynt-x-global/lyntway-tools/detect"
	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// A policy that holds one class and tokenises another, over content that
// carries both — so the tests can see that an approval releases exactly
// the held class and leaves the rest to policy.
func holdingEngine(t *testing.T) *Engine {
	t.Helper()
	signer, err := receipt.GenerateEd25519Signer("test-key-1")
	if err != nil {
		t.Fatal(err)
	}
	rules := append([]detect.Rule{}, detect.Default().Rules()...)
	rules = append(rules, detect.Rule{
		ID: "custom-voyager", Class: "custom.project", Pattern: regexp.MustCompile(`(?i)voyager`),
		Confidence: detect.ConfidenceHigh, Priority: 10,
	})
	ruleset := detect.NewRuleset("test-hold", rules)
	policy := DefaultPolicy()
	policy.Rules = append([]PolicyRule{{Class: "custom.project", Decision: receipt.DecisionRequireApproval}}, policy.Rules...)
	e, err := New(Config{Signer: signer, Ruleset: ruleset, Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func approvedBy(who string) *receipt.Approval {
	return &receipt.Approval{
		ID: "apr_test", Outcome: receipt.ApprovalApproved, DecidedBy: who,
		DecidedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

func TestAnApprovalReleasesTheHeldClassAndNothingElse(t *testing.T) {
	e := holdingEngine(t)
	scope := testScope(t)
	content := "Project Voyager: email priya@acme.com"

	held, err := e.Govern(req("rcpt_1", content, scope))
	if err != nil {
		t.Fatal(err)
	}
	if held.Decision != receipt.DecisionRequireApproval || held.Content != nil {
		t.Fatalf("the hold released something: decision %s, content %q", held.Decision, held.Content)
	}
	if held.Receipt.Content.OutputDigest != "" {
		t.Fatal("a held receipt carries an output digest")
	}

	r := req("rcpt_2", content, scope)
	r.Approval = approvedBy("ops@acme.test")
	res, err := e.Govern(r)
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != receipt.DecisionRequireApproval {
		t.Errorf("decision = %s; an approved release keeps the decision that held it", res.Decision)
	}
	if res.Content == nil {
		t.Fatal("an approved hold released nothing")
	}
	out := string(res.Content)
	if !strings.Contains(out, "Voyager") {
		t.Errorf("the approved class was altered: %q", out)
	}
	if strings.Contains(out, "priya@acme.com") {
		t.Errorf("the class policy tokenises was released in the clear beside the approved one: %q", out)
	}
	if a := res.Receipt.Governance.Approval; a == nil || a.DecidedBy != "ops@acme.test" || a.Outcome != receipt.ApprovalApproved {
		t.Errorf("the receipt does not name who approved: %+v", a)
	}
	if res.Receipt.Content.OutputDigest != receipt.DigestContent(res.Content) {
		t.Error("the receipt does not digest what was released")
	}
	if err := res.Receipt.Validate(); err != nil {
		t.Errorf("the resolution receipt does not validate: %v", err)
	}
}

func TestADenialIsABlockThatNamesTheRefusalAndTheApprover(t *testing.T) {
	e := holdingEngine(t)
	r := req("rcpt_1", "Project Voyager", testScope(t))
	r.Approval = &receipt.Approval{
		ID: "apr_test", Outcome: receipt.ApprovalDenied, DecidedBy: "ops@acme.test",
		DecidedAt: time.Now().UTC().Format(time.RFC3339),
	}
	r.Refusal = "approval_denied"
	res, err := e.Govern(r)
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != receipt.DecisionBlock || res.Content != nil {
		t.Fatalf("a denied hold was not blocked: %s %q", res.Decision, res.Content)
	}
	if res.Receipt.Governance.Refusal != "approval_denied" {
		t.Errorf("refusal = %q", res.Receipt.Governance.Refusal)
	}
	if a := res.Receipt.Governance.Approval; a == nil || a.Outcome != receipt.ApprovalDenied {
		t.Errorf("the receipt does not record the denial: %+v", a)
	}
	if err := res.Receipt.Validate(); err != nil {
		t.Errorf("the denial receipt does not validate: %v", err)
	}
}

// If policy stopped holding the class between the park and the decision,
// the content leaves under policy, and the approval is not written onto
// a receipt that no longer needs it — that would lend the release a
// person's authority it did not use.
func TestAnApprovalWithNothingLeftToResolveIsNotRecorded(t *testing.T) {
	e, _ := testEngine(t) // the default policy holds nothing
	r := req("rcpt_1", "Project Voyager", testScope(t))
	r.Approval = approvedBy("ops@acme.test")
	res, err := e.Govern(r)
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision == receipt.DecisionRequireApproval {
		t.Fatal("the default policy held something")
	}
	if res.Receipt.Governance.Approval != nil {
		t.Errorf("an approval was recorded on a receipt nothing held: %+v", res.Receipt.Governance.Approval)
	}
	if err := res.Receipt.Validate(); err != nil {
		t.Errorf("receipt does not validate: %v", err)
	}
}

// In witness mode nothing is substituted, and an approval does not change
// that: the held content passes as it is, and so does everything beside it.
func TestAnApprovedReleaseInWitnessModeSubstitutesNothing(t *testing.T) {
	e := holdingEngine(t)
	content := "Project Voyager: email priya@acme.com"
	r := req("rcpt_1", content, testScope(t))
	r.Inspect = true
	r.Approval = approvedBy("ops@acme.test")
	res, err := e.Govern(r)
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != receipt.DecisionRequireApproval {
		t.Errorf("decision = %s", res.Decision)
	}
	if string(res.Content) != content {
		t.Errorf("witness mode altered approved content: %q", res.Content)
	}
	if err := res.Receipt.Validate(); err != nil {
		t.Errorf("receipt does not validate: %v", err)
	}
}
