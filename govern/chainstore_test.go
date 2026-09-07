package govern

import (
	"errors"
	"testing"

	"github.com/lynt-x-global/lyntway-tools/receipt"
)

type memChainStore struct {
	heads   map[string][2]any
	saveErr error
}

func (m *memChainStore) LoadChain(id string) (uint64, string, bool, error) {
	h, ok := m.heads[id]
	if !ok {
		return 0, "", false, nil
	}
	return h[0].(uint64), h[1].(string), true, nil
}

func (m *memChainStore) SaveChain(id string, seq uint64, head string) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	if m.heads == nil {
		m.heads = make(map[string][2]any)
	}
	m.heads[id] = [2]any{seq, head}
	return nil
}

func storedEngine(t *testing.T, store ChainStore) (*Engine, receipt.Signer) {
	t.Helper()
	signer, err := receipt.GenerateEd25519Signer("test-key-1")
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(Config{Signer: signer, ChainStore: store})
	if err != nil {
		t.Fatal(err)
	}
	return e, signer
}

// A restart must continue the chain, not fork it. A fork reads to a
// verifier as deletion.
func TestAChainResumesAcrossProcesses(t *testing.T) {
	store := &memChainStore{}
	scope := testScope(t)

	e1, _ := storedEngine(t, store)
	first, err := e1.Govern(req("rcpt_1", "hello", scope))
	if err != nil {
		t.Fatal(err)
	}
	second, err := e1.Govern(req("rcpt_2", "hello again", scope))
	if err != nil {
		t.Fatal(err)
	}

	// A second engine on the same store stands in for the next process.
	e2, _ := storedEngine(t, store)
	third, err := e2.Govern(req("rcpt_3", "and again", scope))
	if err != nil {
		t.Fatal(err)
	}

	if third.Receipt.Chain.Seq != 2 {
		t.Errorf("after restart seq = %d, want 2 (first %d, second %d)",
			third.Receipt.Chain.Seq, first.Receipt.Chain.Seq, second.Receipt.Chain.Seq)
	}
	wantPrev, err := receipt.Digest(second.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	if third.Receipt.Chain.PrevHash != wantPrev {
		t.Errorf("after restart prev_hash does not name the last receipt before it")
	}
}

// A store that cannot save must not cost the caller a signed receipt; it
// must warn.
func TestAChainSaveFailureWarnsButIssues(t *testing.T) {
	store := &memChainStore{saveErr: errors.New("disk on fire")}
	e, _ := storedEngine(t, store)

	res, err := e.Govern(req("rcpt_1", "hello", testScope(t)))
	if err != nil {
		t.Fatalf("a persist failure failed the request: %v", err)
	}
	if res.Receipt == nil || res.Receipt.Signature == nil {
		t.Fatal("no signed receipt returned")
	}
	if res.Warning == "" {
		t.Error("persist failure produced no warning")
	}
}

// The receipt must name the policy that decided, not the engine default.
func TestReceiptNamesTheOverridingPolicy(t *testing.T) {
	e, _ := storedEngine(t, nil)
	p := *DefaultPolicy()
	p.Version = "1+custom-abc"

	r := req("rcpt_p", "hello", testScope(t))
	r.Policy = &p
	res, err := e.Govern(r)
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Receipt.Governance.Policy.Version; got != "1+custom-abc" {
		t.Errorf("receipt policy version = %q, want the override", got)
	}
}

// A stream cut by policy delivered a prefix and withheld the rest. The
// receipt must say both: block, because something was refused, and the
// digest of what left, because something did.
func TestATruncatedStreamReceiptSaysSo(t *testing.T) {
	e, _ := storedEngine(t, nil)
	r := req("rcpt_cut", "Here is the config. ordinary text ", testScope(t))
	r.Inspect = true
	r.Irrevocable = true
	r.Truncated = true
	r.PriorFindings = []receipt.Finding{{Class: "secret.aws_access_key", Count: 1, Decision: receipt.DecisionBlock}}

	res, err := e.Govern(r)
	if err != nil {
		t.Fatalf("a truncated receipt was refused: %v", err)
	}
	rc := res.Receipt
	if rc.Governance.Decision != receipt.DecisionBlock {
		t.Errorf("decision = %q, want block: the remainder was withheld", rc.Governance.Decision)
	}
	if !rc.Content.Truncated {
		t.Error("the receipt does not say the stream was cut")
	}
	if rc.Content.OutputDigest == "" {
		t.Error("no digest of what was delivered")
	}
	var seen bool
	for _, f := range rc.Governance.Findings {
		if f.Class == "secret.aws_access_key" {
			seen = true
		}
	}
	if !seen {
		t.Error("the class that cut the stream is not on the receipt")
	}
	if err := rc.Validate(); err != nil {
		t.Errorf("the schema rejects the truncated receipt: %v", err)
	}
}

// Bytes already delivered cannot be blocked. A tenant rule that says block
// can only be recorded.
func TestABlockOnDeliveredBytesIsRecordedNotClaimed(t *testing.T) {
	e, _ := storedEngine(t, nil)
	r := req("rcpt_gone", "use AKIAIOSFODNN7EXAMPLE now", testScope(t))
	r.Inspect = true
	r.Irrevocable = true

	res, err := e.Govern(r)
	if err != nil {
		t.Fatal(err)
	}
	if res.Receipt.Governance.Decision == receipt.DecisionBlock ||
		res.Receipt.Governance.Decision == receipt.DecisionRequireApproval {
		t.Errorf("decision = %q on bytes the caller already holds", res.Receipt.Governance.Decision)
	}
	var blocked bool
	for _, f := range res.Receipt.Governance.Findings {
		if f.Decision == receipt.DecisionBlock {
			blocked = true
		}
	}
	if !blocked {
		t.Error("the finding no longer says policy would have blocked it")
	}
}

// A metadata subject describes traffic nothing read, so nothing may be
// found in it — not even in the note itself.
func TestAMetadataSubjectIsNotScanned(t *testing.T) {
	e, _ := storedEngine(t, nil)
	r := req("rcpt_meta", `{"host":"10.0.0.7","port":443,"contact":"ops@acme.co.uk"}`, testScope(t))
	r.Inspect = true
	r.Subject = receipt.SubjectMetadata

	res, err := e.Govern(r)
	if err != nil {
		t.Fatalf("a metadata receipt was refused: %v", err)
	}
	if n := len(res.Receipt.Governance.Findings); n != 0 {
		t.Errorf("%d findings on a note about traffic nothing examined", n)
	}
	if res.Receipt.Content.Subject != receipt.SubjectMetadata {
		t.Error("subject was not carried onto the receipt")
	}
}

// A gateway that refuses a statement for a reason of its own — a
// transaction already aborted — forwarded nothing, and the receipt must
// say so rather than record the policy's "allow" as though it went through.
func TestACallerRefusalIsABlockWithItsReason(t *testing.T) {
	e, _ := storedEngine(t, nil)
	r := req("rcpt_refused", "SELECT 1", testScope(t))
	r.Inspect = true
	r.Refusal = "the transaction was aborted by an earlier refusal; nothing was forwarded"

	res, err := e.Govern(r)
	if err != nil {
		t.Fatal(err)
	}
	g := res.Receipt.Governance
	if g.Decision != receipt.DecisionBlock {
		t.Errorf("decision = %q, want block", g.Decision)
	}
	if g.Refusal == "" {
		t.Error("the reason was not recorded")
	}
	if res.Receipt.Content.OutputDigest != "" {
		t.Error("a refused action has an output digest")
	}
	if err := res.Receipt.Validate(); err != nil {
		t.Errorf("schema rejects the receipt: %v", err)
	}

	bad := *res.Receipt
	bad.Governance.Decision = receipt.DecisionAllow
	if err := bad.Validate(); err == nil {
		t.Error("an allowed action was permitted to carry a refusal")
	}
}

// A caller that could not read part of what it governed says so through a
// component, and the receipt must not read as a full examination.
func TestACallerReportedComponentDegradesTheReceipt(t *testing.T) {
	e, _ := storedEngine(t, nil)
	r := req("rcpt_bind", "SELECT $1", testScope(t))
	r.Inspect = true
	r.Components = []receipt.Component{{Name: "bind-parameters", Health: receipt.HealthDegraded, Detail: "1 of 2 parameters binary"}}

	res, err := e.Govern(r)
	if err != nil {
		t.Fatal(err)
	}
	g := res.Receipt.Governance
	if g.Mode != receipt.ModeDegraded {
		t.Errorf("mode = %q, want degraded", g.Mode)
	}
	var listed bool
	for _, c := range g.Detector.Components {
		if c.Name == "bind-parameters" && c.Health == receipt.HealthDegraded && c.Detail != "" {
			listed = true
		}
	}
	if !listed {
		t.Errorf("the caller's component is not on the receipt: %+v", g.Detector.Components)
	}
	if err := res.Receipt.Validate(); err != nil {
		t.Errorf("schema rejects it: %v", err)
	}

	r2 := req("rcpt_bind2", "SELECT $1", testScope(t))
	r2.Inspect = true
	r2.Components = []receipt.Component{{Name: "bind-parameters", Health: receipt.HealthHealthy}}
	res2, _ := e.Govern(r2)
	if res2.Receipt.Governance.Mode != receipt.ModeFull {
		t.Errorf("a healthy caller component degraded the receipt: %q", res2.Receipt.Governance.Mode)
	}
}
