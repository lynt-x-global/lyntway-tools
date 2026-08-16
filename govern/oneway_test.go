package govern

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/lynt-x-global/lyntway-tools/receipt"
	"github.com/lynt-x-global/lyntway-tools/tokenize"
)

func oneWayScope(t *testing.T) *tokenize.Scope {
	t.Helper()
	key := make([]byte, tokenize.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generating key: %v", err)
	}
	s, err := tokenize.NewScope(key, tokenize.DiscardStore{})
	if err != nil {
		t.Fatalf("creating scope: %v", err)
	}
	return s
}

// The receipt schema defines tokenisation as reversible substitution. When
// the deployment retains nothing, claiming it would promise a customer a
// recovery that cannot happen — so the receipt must say redact, which is
// what actually occurred.
func TestOneWayScopeIsReportedAsRedaction(t *testing.T) {
	e, _ := testEngine(t)

	res, err := e.Govern(req("rcpt_oneway", "mail priya@acme.co.in about it", oneWayScope(t)))
	if err != nil {
		t.Fatalf("governing: %v", err)
	}

	if res.Decision != receipt.DecisionRedact {
		t.Errorf("decision = %q, want %q — a receipt must not claim reversibility the deployment cannot deliver",
			res.Decision, receipt.DecisionRedact)
	}
	for _, f := range res.Receipt.Governance.Findings {
		if f.Decision == receipt.DecisionTokenize {
			t.Errorf("finding %q still claims tokenisation", f.Class)
		}
	}

	// The substitution itself is unchanged: still format-preserving, so
	// the workflow downstream survives. Only the claim differs.
	if !strings.Contains(string(res.Content), "@tokenized.invalid") {
		t.Errorf("content lost format-preserving substitution: %q", res.Content)
	}
	if bytes.Contains(res.Content, []byte("priya@acme.co.in")) {
		t.Error("the original value survived in the released content")
	}
}

// The reversible case must be untouched by the change above.
func TestReversibleScopeStillReportsTokenisation(t *testing.T) {
	e, _ := testEngine(t)

	res, err := e.Govern(req("rcpt_reversible", "mail priya@acme.co.in about it", testScope(t)))
	if err != nil {
		t.Fatalf("governing: %v", err)
	}
	if res.Decision != receipt.DecisionTokenize {
		t.Errorf("decision = %q, want %q", res.Decision, receipt.DecisionTokenize)
	}
}

// Whatever the receipt says, it must still verify — the downgrade happens
// before signing, not as an edit afterwards.
func TestOneWayReceiptStillVerifies(t *testing.T) {
	e, keys := testEngine(t)

	res, err := e.Govern(req("rcpt_oneway_verify", "mail priya@acme.co.in about it", oneWayScope(t)))
	if err != nil {
		t.Fatalf("governing: %v", err)
	}
	if _, err := receipt.Verify(res.Receipt, keys, receipt.VerifyOptions{}); err != nil {
		t.Errorf("verifying: %v", err)
	}
}
