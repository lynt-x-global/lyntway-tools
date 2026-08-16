package govern

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/lynt-x-global/lyntway-tools/detect"
	"github.com/lynt-x-global/lyntway-tools/receipt"
	"github.com/lynt-x-global/lyntway-tools/tokenize"
)

func testEngine(t *testing.T, components ...Component) (*Engine, receipt.StaticKeyResolver) {
	t.Helper()
	signer, err := receipt.GenerateEd25519Signer("test-key-1")
	if err != nil {
		t.Fatalf("generating signer: %v", err)
	}
	e, err := New(Config{Signer: signer, Components: components})
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}
	return e, receipt.StaticKeyResolver{signer.KeyID(): signer.Public().(crypto.PublicKey)}
}

func testScope(t *testing.T) *tokenize.Scope {
	t.Helper()
	key := make([]byte, tokenize.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generating key: %v", err)
	}
	s, err := tokenize.NewScope(key, nil)
	if err != nil {
		t.Fatalf("creating scope: %v", err)
	}
	return s
}

func req(id string, content string, scope *tokenize.Scope) Request {
	return Request{
		ChainID:   "ws_test",
		ReceiptID: id,
		Content:   []byte(content),
		Action: receipt.Action{
			Surface:     receipt.SurfacePrimitive,
			Direction:   receipt.DirectionRequest,
			Method:      "POST /v1/govern",
			Destination: "api.anthropic.com",
		},
		Actor: receipt.Actor{
			Type:     receipt.ActorAgent,
			ID:       "agent_test",
			Source:   receipt.IdentityLyntwayKey,
			Verified: false,
		},
		Scope: scope,
	}
}

// TestGovernTokenizesPII is the end-to-end happy path: detection finds
// personal data, policy tokenises it, and the receipt verifies.
func TestGovernTokenizesPII(t *testing.T) {
	e, keys := testEngine(t)
	scope := testScope(t)

	res, err := e.Govern(req("r1", "Email priya@acme.com about the invoice.", scope))
	if err != nil {
		t.Fatalf("govern: %v", err)
	}

	if res.Decision != receipt.DecisionTokenize {
		t.Errorf("decision = %q, want tokenize", res.Decision)
	}
	if bytes.Contains(res.Content, []byte("priya@acme.com")) {
		t.Error("the original address survived into governed output")
	}
	if !bytes.Contains(res.Content, []byte("Email ")) {
		t.Errorf("surrounding text was corrupted: %q", res.Content)
	}

	vr, err := receipt.Verify(res.Receipt, keys, receipt.VerifyOptions{})
	if err != nil {
		t.Fatalf("receipt does not verify: %v", err)
	}
	if !vr.FullStrength {
		t.Error("expected full strength with a healthy detector")
	}

	// The receipt must describe what was released, not what came in.
	if res.Receipt.Content.OutputDigest != receipt.DigestContent(res.Content) {
		t.Error("output digest does not match the released content")
	}
	if res.Receipt.Content.InputDigest == res.Receipt.Content.OutputDigest {
		t.Error("input and output digests match despite transformation")
	}
}

// TestGovernBlocksSecrets proves credentials are refused and nothing is
// released.
func TestGovernBlocksSecrets(t *testing.T) {
	e, keys := testEngine(t)
	awsKey := "AK" + "IA" + "5J7QWMNBZX2LKPRD"

	res, err := e.Govern(req("r1", "deploy with "+awsKey+" now", testScope(t)))
	if err != nil {
		t.Fatalf("govern: %v", err)
	}

	if res.Decision != receipt.DecisionBlock {
		t.Fatalf("decision = %q, want block", res.Decision)
	}
	if res.Content != nil {
		t.Errorf("blocked action released content: %q", res.Content)
	}
	if res.Receipt.Content.OutputDigest != "" {
		t.Error("blocked receipt carries an output digest for content that was never released")
	}
	if _, err := receipt.Verify(res.Receipt, keys, receipt.VerifyOptions{}); err != nil {
		t.Fatalf("blocked receipt does not verify: %v", err)
	}
}

// TestGovernAllowsCleanContent proves a receipt is issued even when nothing
// is found. Issuing selectively would leave holes in the chain, and a hole
// is indistinguishable from a deleted record.
func TestGovernAllowsCleanContent(t *testing.T) {
	e, keys := testEngine(t)

	res, err := e.Govern(req("r1", "The quarterly governance report is attached.", testScope(t)))
	if err != nil {
		t.Fatalf("govern: %v", err)
	}
	if res.Decision != receipt.DecisionAllow {
		t.Errorf("decision = %q, want allow", res.Decision)
	}
	if len(res.Findings) != 0 {
		t.Errorf("findings on clean content: %v", res.Findings)
	}
	if res.Receipt == nil {
		t.Fatal("no receipt issued for a clean action")
	}
	if res.Receipt.Content.InputDigest != res.Receipt.Content.OutputDigest {
		t.Error("digests differ despite content passing through unchanged")
	}
	if _, err := receipt.Verify(res.Receipt, keys, receipt.VerifyOptions{}); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestDegradedDetectorProducesHonestReceipt is the invariant the whole
// design exists to protect: when a component is unavailable, the receipt
// must say so rather than reading like a healthy one.
func TestDegradedDetectorProducesHonestReceipt(t *testing.T) {
	e, keys := testEngine(t,
		Component{Name: "deterministic", Health: func() receipt.Health { return receipt.HealthHealthy }},
		Component{Name: "ml-sidecar", Health: func() receipt.Health { return receipt.HealthUnavailable }},
	)

	res, err := e.Govern(req("r1", "Email priya@acme.com please", testScope(t)))
	if err != nil {
		t.Fatalf("govern: %v", err)
	}

	if res.Receipt.Governance.Mode != receipt.ModeDegraded {
		t.Errorf("mode = %q, want degraded", res.Receipt.Governance.Mode)
	}

	vr, err := receipt.Verify(res.Receipt, keys, receipt.VerifyOptions{})
	if err != nil {
		t.Fatalf("a degraded receipt must still verify: %v", err)
	}
	if vr.FullStrength {
		t.Error("a degraded receipt reported full strength")
	}
	if len(vr.Warnings) == 0 {
		t.Fatal("no warning describing the degradation")
	}
	if !strings.Contains(strings.Join(vr.Warnings, " "), "ml-sidecar") {
		t.Errorf("warnings do not name the failed component: %v", vr.Warnings)
	}

	// Governance still happened, so the tokenisation must still be applied.
	if bytes.Contains(res.Content, []byte("priya@acme.com")) {
		t.Error("degraded mode skipped the deterministic tier that was healthy")
	}
}

// TestTotalOutageIsReportedAsBypassed proves the engine admits when nothing
// examined the content, rather than issuing a receipt that looks governed.
func TestTotalOutageIsReportedAsBypassed(t *testing.T) {
	e, keys := testEngine(t,
		Component{Name: "deterministic", Health: func() receipt.Health { return receipt.HealthUnavailable }},
	)

	res, err := e.Govern(req("r1", "Email priya@acme.com please", testScope(t)))
	if err != nil {
		t.Fatalf("govern: %v", err)
	}

	if res.Receipt.Governance.Mode != receipt.ModeBypassed {
		t.Fatalf("mode = %q, want bypassed", res.Receipt.Governance.Mode)
	}
	if len(res.Receipt.Governance.Findings) != 0 {
		t.Error("a bypassed receipt reported findings it could not have made")
	}
	if res.Receipt.Governance.Decision != receipt.DecisionAllow {
		t.Error("a bypassed receipt claimed enforcement that did not happen")
	}

	vr, err := receipt.Verify(res.Receipt, keys, receipt.VerifyOptions{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if vr.FullStrength {
		t.Error("a bypassed receipt reported full strength")
	}
	if !strings.Contains(strings.Join(vr.Warnings, " "), "bypassed") {
		t.Errorf("warnings do not disclose the bypass: %v", vr.Warnings)
	}
}

// TestReceiptsChain proves consecutive actions form a verifiable chain, so
// deleting one is detectable.
func TestReceiptsChain(t *testing.T) {
	e, keys := testEngine(t)
	scope := testScope(t)

	var chain []*receipt.Receipt
	for _, id := range []string{"r1", "r2", "r3", "r4"} {
		res, err := e.Govern(req(id, "message from priya@acme.com", scope))
		if err != nil {
			t.Fatalf("govern %s: %v", id, err)
		}
		chain = append(chain, res.Receipt)
	}

	if _, err := receipt.VerifyChain(chain, keys, receipt.VerifyOptions{}); err != nil {
		t.Fatalf("chain does not verify: %v", err)
	}

	withHole := append(append([]*receipt.Receipt{}, chain[:1]...), chain[2:]...)
	if _, err := receipt.VerifyChain(withHole, keys, receipt.VerifyOptions{}); err == nil {
		t.Error("a deleted receipt went undetected")
	}
}

// TestTokenizeRequiresScope proves the engine refuses rather than silently
// producing an irreversible transformation.
func TestTokenizeRequiresScope(t *testing.T) {
	e, _ := testEngine(t)
	if _, err := e.Govern(req("r1", "email priya@acme.com", nil)); err == nil {
		t.Error("tokenisation proceeded without a scope")
	}
}

// TestOnlyTokenizeClassesAreSubstituted proves a finding the policy merely
// logs is not silently rewritten because another class triggered
// tokenisation.
func TestOnlyTokenizeClassesAreSubstituted(t *testing.T) {
	e, _ := testEngine(t)
	scope := testScope(t)

	// The IP is low confidence, so the default policy only logs it; the
	// email is tokenised.
	res, err := e.Govern(req("r1", "user priya@acme.com from 192.168.1.50", scope))
	if err != nil {
		t.Fatalf("govern: %v", err)
	}

	if !bytes.Contains(res.Content, []byte("192.168.1.50")) {
		t.Errorf("a log-only finding was rewritten: %q", res.Content)
	}
	if bytes.Contains(res.Content, []byte("priya@acme.com")) {
		t.Errorf("a tokenise finding was not rewritten: %q", res.Content)
	}
}

func TestChainResume(t *testing.T) {
	e, keys := testEngine(t)
	scope := testScope(t)

	var chain []*receipt.Receipt
	for _, id := range []string{"r1", "r2"} {
		res, err := e.Govern(req(id, "hello", scope))
		if err != nil {
			t.Fatalf("govern: %v", err)
		}
		chain = append(chain, res.Receipt)
	}

	seq, head, ok := e.ChainHead("ws_test")
	if !ok {
		t.Fatal("chain head unknown")
	}

	// Restart: a fresh engine with the same signer resumes the chain.
	e2, err := New(Config{Signer: mustSigner(t, e)})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	if err := e2.ResumeChain("ws_test", seq, head); err != nil {
		t.Fatalf("resume: %v", err)
	}

	res, err := e2.Govern(req("r3", "after restart", scope))
	if err != nil {
		t.Fatalf("govern after restart: %v", err)
	}
	chain = append(chain, res.Receipt)

	if _, err := receipt.VerifyChain(chain, keys, receipt.VerifyOptions{}); err != nil {
		t.Fatalf("chain must survive a restart: %v", err)
	}
}

func mustSigner(t *testing.T, e *Engine) receipt.Signer {
	t.Helper()
	return e.signer
}

func TestPolicyValidation(t *testing.T) {
	tests := []struct {
		name   string
		policy Policy
	}{
		{"no id", Policy{Version: "1", Default: receipt.DecisionAllow}},
		{"no version", Policy{ID: "p", Default: receipt.DecisionAllow}},
		{"bad default", Policy{ID: "p", Version: "1", Default: "nonsense"}},
		{"rule matches nothing", Policy{ID: "p", Version: "1", Default: receipt.DecisionAllow,
			Rules: []PolicyRule{{Decision: receipt.DecisionBlock}}}},
		{"rule sets both class and family", Policy{ID: "p", Version: "1", Default: receipt.DecisionAllow,
			Rules: []PolicyRule{{Class: "pii.email", Family: "pii", Decision: receipt.DecisionBlock}}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.policy.Validate(); err == nil {
				t.Error("invalid policy accepted")
			}
		})
	}
	if err := DefaultPolicy().Validate(); err != nil {
		t.Errorf("the shipped default policy is invalid: %v", err)
	}
}

func TestPolicyConfidenceThreshold(t *testing.T) {
	p := DefaultPolicy()

	// A high-confidence secret blocks; a low-confidence one is only logged.
	if got := p.Decide(detect.ClassAWSAccessKey, detect.ConfidenceExact); got != receipt.DecisionBlock {
		t.Errorf("exact secret decision = %q, want block", got)
	}
	if got := p.Decide(detect.ClassAWSAccessKey, detect.ConfidenceLow); got != receipt.DecisionLogOnly {
		t.Errorf("low-confidence secret decision = %q, want log_only", got)
	}
	// A low-confidence IP is never enforced on.
	if got := p.Decide(detect.ClassIPv4, detect.ConfidenceLow); got != receipt.DecisionLogOnly {
		t.Errorf("low-confidence IP decision = %q, want log_only", got)
	}
}

func TestFindingsAreSorted(t *testing.T) {
	e, _ := testEngine(t)
	scope := testScope(t)

	res, err := e.Govern(req("r1", "priya@acme.com 192.168.1.1 +442071838750 4111111111111111", scope))
	if err != nil {
		t.Fatalf("govern: %v", err)
	}
	if len(res.Findings) < 3 {
		t.Fatalf("expected several classes, got %d", len(res.Findings))
	}
	for i := 1; i < len(res.Findings); i++ {
		if res.Findings[i].Class < res.Findings[i-1].Class {
			t.Error("findings are not sorted; receipts would not be byte-reproducible")
		}
	}
}

func TestConcurrentGovern(t *testing.T) {
	e, keys := testEngine(t)
	scope := testScope(t)

	const n = 40
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			_, err := e.Govern(Request{
				ChainID:   "ws_concurrent",
				ReceiptID: "r" + string(rune('a'+i%26)) + string(rune('0'+i/26)),
				Content:   []byte("message priya@acme.com"),
				Action: receipt.Action{
					Surface: receipt.SurfacePrimitive, Direction: receipt.DirectionRequest,
					Method: "POST /v1/govern",
				},
				Actor: receipt.Actor{
					Type: receipt.ActorAgent, ID: "a", Source: receipt.IdentityLyntwayKey,
				},
				Scope: scope,
			})
			errs <- err
		}(i)
	}
	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent govern failed: %v", err)
		}
	}

	seq, _, ok := e.ChainHead("ws_concurrent")
	if !ok || seq != n {
		t.Errorf("chain advanced to %d, want %d", seq, n)
	}
	_ = keys
}

func BenchmarkGovern(b *testing.B) {
	signer, _ := receipt.GenerateEd25519Signer("bench")
	e, _ := New(Config{Signer: signer})
	key := make([]byte, tokenize.KeySize)
	rand.Read(key)
	scope, _ := tokenize.NewScope(key, nil)
	content := []byte("Customer priya@acme.com called about invoice 4111111111111111.")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Govern(Request{
			ChainID: "bench", ReceiptID: "r", Content: content,
			Action: receipt.Action{Surface: receipt.SurfacePrimitive, Direction: receipt.DirectionRequest, Method: "POST"},
			Actor:  receipt.Actor{Type: receipt.ActorAgent, ID: "a", Source: receipt.IdentityLyntwayKey},
			Scope:  scope,
		})
	}
}

// TestHealthAggregation pins the three-way distinction directly, rather
// than relying on it being exercised incidentally. The middle case is the
// one that was wrong: one component down is partial capability, not a total
// bypass.
func TestHealthAggregation(t *testing.T) {
	up := func() receipt.Health { return receipt.HealthHealthy }
	slow := func() receipt.Health { return receipt.HealthDegraded }
	down := func() receipt.Health { return receipt.HealthUnavailable }

	tests := []struct {
		name     string
		probes   []func() receipt.Health
		wantMode receipt.Mode
	}{
		{"all healthy", []func() receipt.Health{up, up}, receipt.ModeFull},
		{"one down of two", []func() receipt.Health{up, down}, receipt.ModeDegraded},
		{"one degraded of two", []func() receipt.Health{up, slow}, receipt.ModeDegraded},
		{"all down", []func() receipt.Health{down, down}, receipt.ModeBypassed},
		{"single component down", []func() receipt.Health{down}, receipt.ModeBypassed},
		{"single component up", []func() receipt.Health{up}, receipt.ModeFull},
		{"mixed degraded and down", []func() receipt.Health{slow, down}, receipt.ModeDegraded},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			comps := make([]Component, len(tc.probes))
			for i, p := range tc.probes {
				comps[i] = Component{Name: "c" + string(rune('0'+i)), Health: p}
			}
			e, keys := testEngine(t, comps...)

			res, err := e.Govern(req("r1", "priya@acme.com", testScope(t)))
			if err != nil {
				t.Fatalf("govern: %v", err)
			}
			if res.Receipt.Governance.Mode != tc.wantMode {
				t.Errorf("mode = %q, want %q", res.Receipt.Governance.Mode, tc.wantMode)
			}
			// Whatever the mode, the receipt must verify and must list
			// every component so a reader can judge it independently.
			if _, err := receipt.Verify(res.Receipt, keys, receipt.VerifyOptions{}); err != nil {
				t.Fatalf("verify: %v", err)
			}
			if len(res.Receipt.Governance.Detector.Components) != len(tc.probes) {
				t.Errorf("receipt lists %d components, want %d",
					len(res.Receipt.Governance.Detector.Components), len(tc.probes))
			}
		})
	}
}

// The engine must carry evidence into the receipt.
//
// This is a test because the failure is quiet: a dropped evidence block
// leaves the receipt with none, which reads as "asserted" — correct by
// accident on the path where the caller really did assert, and wrong
// everywhere else. The default masked the bug on one path and exposed it
// on another, which is the worst way to find out.
func TestEngineCarriesEvidenceIntoTheReceipt(t *testing.T) {
	signer, err := receipt.GenerateEd25519Signer("k1")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	engine, err := New(Config{Signer: signer})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}

	for _, tc := range []struct {
		name     string
		evidence *receipt.Evidence
		want     receipt.Provenance
	}{
		{"observed", &receipt.Evidence{Provenance: receipt.ProvenanceObserved, Vantage: "gw/anthropic"}, receipt.ProvenanceObserved},
		{"attested", &receipt.Evidence{Provenance: receipt.ProvenanceAttested, Vantage: "litellm"}, receipt.ProvenanceAttested},
		{"asserted", &receipt.Evidence{Provenance: receipt.ProvenanceAsserted}, receipt.ProvenanceAsserted},
		{"absent reads as the weakest", nil, receipt.ProvenanceAsserted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := engine.Govern(Request{
				ChainID:   "ws_" + tc.name,
				ReceiptID: "rcpt_" + tc.name,
				Content:   []byte("nothing sensitive"),
				Action: receipt.Action{
					Surface: receipt.SurfacePrimitive, Direction: receipt.DirectionRequest,
					Method: "POST /x",
				},
				Actor:    receipt.Actor{Type: receipt.ActorAgent, ID: "a", Source: receipt.IdentityNone},
				Evidence: tc.evidence,
			})
			if err != nil {
				t.Fatalf("govern: %v", err)
			}
			if got := res.Receipt.EffectiveProvenance(); got != tc.want {
				t.Errorf("provenance = %q, want %q", got, tc.want)
			}
			if tc.evidence != nil && tc.evidence.Vantage != "" {
				if res.Receipt.Evidence == nil || res.Receipt.Evidence.Vantage != tc.evidence.Vantage {
					t.Errorf("vantage was not carried into the receipt")
				}
			}
		})
	}
}
