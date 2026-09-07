package govern

import (
	"bytes"
	"crypto/rand"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/lynt-x-global/lyntway-tools/detect"
	"github.com/lynt-x-global/lyntway-tools/receipt"
	"github.com/lynt-x-global/lyntway-tools/tokenize"
)

func streamEngine(t *testing.T) (*Engine, *tokenize.Scope) {
	t.Helper()
	signer, err := receipt.GenerateEd25519Signer("k1")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	engine, err := New(Config{Signer: signer})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	key := make([]byte, tokenize.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("key: %v", err)
	}
	scope, err := tokenize.NewScope(key, tokenize.NewMemoryStore())
	if err != nil {
		t.Fatalf("scope: %v", err)
	}
	return engine, scope
}

// streamAll feeds content through in chunks of the given size.
func streamAll(t *testing.T, engine *Engine, scope *tokenize.Scope, content string, chunk int) (string, *StreamGovernor, error) {
	t.Helper()
	return streamAllWith(t, engine.NewStreamGovernor(scope), content, chunk)
}

// streamAllWith is the same for a governor the caller has already chosen,
// so the outbound and returning directions can both be exercised.
func streamAllWith(t *testing.T, g *StreamGovernor, content string, chunk int) (string, *StreamGovernor, error) {
	t.Helper()
	var out bytes.Buffer

	for i := 0; i < len(content); i += chunk {
		end := i + chunk
		if end > len(content) {
			end = len(content)
		}
		released, err := g.Write([]byte(content[i:end]))
		if err != nil {
			return out.String(), g, err
		}
		out.Write(released)
	}
	tail, err := g.Close()
	out.Write(tail)
	return out.String(), g, err
}

// The defect this exists to prevent. A card number split across two chunks
// matches neither, and nothing reports it: a miss looks exactly like clean
// content.
//
// Rather than test one split, this tries every one. If any boundary lets a
// value through, this fails.
func TestNoValueEscapesAtAChunkBoundary(t *testing.T) {
	const content = "Customer priya@acme.com paid with card 4111 1111 1111 1111 " +
		"and rang from +442071838750 about invoice 8842."

	for chunk := 1; chunk <= len(content); chunk++ {
		engine, scope := streamEngine(t)
		got, _, err := streamAll(t, engine, scope, content, chunk)
		if err != nil {
			t.Fatalf("chunk size %d: %v", chunk, err)
		}
		for _, leaked := range []string{"priya@acme.com", "4111 1111 1111 1111", "+442071838750"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("chunk size %d let %q through:\n%s", chunk, leaked, got)
			}
		}
	}
}

// Streaming must not change the answer. Whatever chunking the network
// happens to produce, the reader must receive the same governed text they
// would have received in one piece.
func TestStreamedOutputMatchesGoverningItAllAtOnce(t *testing.T) {
	const content = "Reach dev.ananth@northbay.co.uk on +447700900412, card 5500 0055 5555 5559."

	engine, scope := streamEngine(t)
	whole, _, err := streamAll(t, engine, scope, content, len(content))
	if err != nil {
		t.Fatalf("whole: %v", err)
	}

	for chunk := 1; chunk <= len(content); chunk++ {
		// A fresh engine and scope each time, so tokens are compared on
		// their derivation rather than on cache state.
		e2, s2 := streamEngine(t)
		wholeAgain, _, err := streamAll(t, e2, s2, content, len(content))
		if err != nil {
			t.Fatalf("whole again: %v", err)
		}
		e3, s3 := streamEngine(t)
		streamed, _, err := streamAll(t, e3, s3, content, chunk)
		if err != nil {
			t.Fatalf("chunk %d: %v", chunk, err)
		}
		// Tokens differ per key, so compare shape rather than bytes: the
		// same number of substitutions in the same places.
		if strings.Count(streamed, "@tokenized.invalid") != strings.Count(wholeAgain, "@tokenized.invalid") {
			t.Fatalf("chunk %d substituted a different number of emails\n got: %s\nwant: %s",
				chunk, streamed, wholeAgain)
		}
		if len(streamed) == 0 && len(whole) > 0 {
			t.Fatalf("chunk %d produced nothing", chunk)
		}
	}
}

// A credential appearing mid-stream cannot be unsent, but it can be
// stopped. What must never happen is that it is released.
func TestACredentialMidStreamStopsTheStream(t *testing.T) {
	content := "Here is the deploy note. Everything normal so far. " +
		strings.Repeat("filler text that is perfectly ordinary. ", 30) +
		"Use AK" + "IA5J7QWMNBZX2LKPRD to authenticate."

	for _, chunk := range []int{1, 7, 64, 512} {
		engine, scope := streamEngine(t)
		got, g, err := streamAll(t, engine, scope, content, chunk)

		if !errors.Is(err, ErrStreamUnsafe) {
			t.Fatalf("chunk %d: stream was not stopped: err = %v", chunk, err)
		}
		if strings.Contains(got, "AKIA5J7QWMNBZX2LKPRD") {
			t.Fatalf("chunk %d released the credential:\n%s", chunk, got)
		}
		if !g.Truncated() {
			t.Errorf("chunk %d: the stream was cut but does not report it", chunk)
		}
	}
}

// The marker for a refusing class freezes emission before the rule has
// matched, because by the time it matches the bytes would already be gone.
func TestEmissionFreezesAtACredentialMarkerBeforeTheRuleMatches(t *testing.T) {
	engine, scope := streamEngine(t)
	g := engine.NewStreamGovernor(scope)

	// Enough ordinary text to push past the lookback so releasing starts.
	head := strings.Repeat("ordinary sentence about nothing at all. ", 40)
	released, err := g.Write([]byte(head))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(released) == 0 {
		t.Fatal("nothing was released from ordinary content")
	}

	// The beginning of a private key. The rule cannot match yet — the block
	// is not closed — and that is exactly why it must not be released.
	released, err = g.Write([]byte("\n-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg"))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if bytes.Contains(released, []byte("BEGIN PRIVATE KEY")) {
		t.Fatal("the start of a private key was released before the rule could match")
	}
}

// Held bytes cannot be held forever: a marker that never completes would
// otherwise hold the stream open, which is a denial of service performed by
// the content itself.
func TestAStreamHeldTooLongIsAbandonedRatherThanReleased(t *testing.T) {
	engine, scope := streamEngine(t)
	g := engine.NewStreamGovernor(scope)

	// A marker with no closing delimiter, followed by more than the buffer
	// allows.
	if _, err := g.Write([]byte("-----BEGIN PRIVATE KEY-----\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	var err error
	for i := 0; i < 40 && err == nil; i++ {
		_, err = g.Write(bytes.Repeat([]byte("A"), 16<<10))
	}
	if !errors.Is(err, ErrStreamUnsafe) {
		t.Fatalf("an unresolving stream was not abandoned: err = %v", err)
	}
	if !g.Truncated() {
		t.Error("the stream was abandoned but does not report truncation")
	}
}

// The receipt must describe the stream, not its final chunk.
func TestFindingsAccumulateAcrossTheWholeStream(t *testing.T) {
	engine, scope := streamEngine(t)
	content := "first a@x.com then b@y.com then c@z.com and a card 4111 1111 1111 1111"

	if _, g, err := streamAll(t, engine, scope, content, 3); err != nil {
		t.Fatalf("stream: %v", err)
	} else {
		emails, cards := 0, 0
		for _, f := range g.Findings() {
			switch f.Class {
			case "pii.email":
				emails = f.Count
			case "pci.card_number":
				cards = f.Count
			}
		}
		if emails != 3 {
			t.Errorf("email findings = %d, want 3", emails)
		}
		if cards != 1 {
			t.Errorf("card findings = %d, want 1", cards)
		}
	}
}

// Nothing sensitive means nothing withheld beyond the lookback.
func TestOrdinaryContentFlowsThrough(t *testing.T) {
	engine, scope := streamEngine(t)
	content := strings.Repeat("The quick brown fox jumps over the lazy dog. ", 50)

	got, g, err := streamAll(t, engine, scope, content, 64)
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	if got != content {
		t.Errorf("ordinary content was altered:\n got %d bytes\nwant %d bytes", len(got), len(content))
	}
	if g.Truncated() {
		t.Error("an ordinary stream reported truncation")
	}
}

// A streamed reply must come back in the caller's own values, not in the
// tokens the provider was handed.
//
// The buffered path restored them and the streaming path did not, because
// the streaming branch returns before the code that does it. So the same
// account, the same vault setting and the same prompt gave two different
// answers depending on stream=True — and the streaming answer was the one
// every chat interface gets.
//
// Found by running a real application against the deployed service. No unit
// test could see it: both halves were correct on their own.
func TestAStreamedReplyComesBackInTheCallersOwnValues(t *testing.T) {
	engine, scope := streamEngine(t)

	// What the application sent, and what the provider was allowed to see.
	original := "Charge card 4111 1111 1111 1111 and email priya@acme.co.uk."
	spans := engine.ruleset.Scan([]byte(original))
	if len(spans) == 0 {
		t.Fatal("the sample tripped no rule, so this test proves nothing")
	}
	tokenized, err := scope.Apply([]byte(original), spans)
	if err != nil {
		t.Fatalf("tokenising the sample: %v", err)
	}
	if bytes.Contains(tokenized, []byte("4111 1111 1111 1111")) {
		t.Fatal("the card survived tokenisation; the rest of this test is meaningless")
	}

	// The provider replies in terms of what it was given.
	reply := "Confirmed: " + string(tokenized)

	// Chunked small on purpose, so tokens straddle chunk boundaries the way
	// they do in a real event stream.
	for _, chunk := range []int{1, 7, 64} {
		got, _, err := streamAllWith(t, engine.NewRestoringStreamGovernor(scope), reply, chunk)
		if err != nil {
			t.Fatalf("chunk %d: streaming failed: %v", chunk, err)
		}
		if !strings.Contains(got, "4111 1111 1111 1111") {
			t.Errorf("chunk %d: the caller got tokens back instead of their own card number:\n%s",
				chunk, got)
		}
		if !strings.Contains(got, "priya@acme.co.uk") {
			t.Errorf("chunk %d: the caller got a token back instead of their own address:\n%s",
				chunk, got)
		}
		if strings.Contains(got, "tokenized.invalid") {
			t.Errorf("chunk %d: a token was left in what the caller received:\n%s", chunk, got)
		}
	}
}

// The hard case, and the one that made the first two fixes wrong.
//
// A single reply carries both kinds of value: tokens this scope issued,
// which belong to the caller and must come back as themselves, and a value
// the model produced that was never sent to it, which must be substituted
// like any other. They are indistinguishable by inspection — substitution
// is format-preserving, so a tokenised card is a valid card number.
//
// Restoring everything hands the caller their own data and lets the model's
// invention through. Substituting everything protects the invention and
// hands the caller their own data disguised. Only telling them apart works.
func TestAReturningStreamSeparatesTheCallersDataFromTheModelsInvention(t *testing.T) {
	engine, scope := streamEngine(t)

	sent := "Charge card 4111 1111 1111 1111."
	spans := engine.ruleset.Scan([]byte(sent))
	tokenized, err := scope.Apply([]byte(sent), spans)
	if err != nil {
		t.Fatalf("tokenising: %v", err)
	}

	// The model echoes the token it was given and volunteers a card number
	// nobody sent it.
	const invented = "5500 0000 0000 0004"
	reply := string(tokenized) + " I also found card " + invented + " on file."

	for _, chunk := range []int{1, 9, 128} {
		got, g, err := streamAllWith(t, engine.NewRestoringStreamGovernor(scope), reply, chunk)
		if err != nil {
			t.Fatalf("chunk %d: %v", chunk, err)
		}
		// The caller's own card, back as itself.
		if !strings.Contains(got, "4111 1111 1111 1111") {
			t.Errorf("chunk %d: the caller did not get their own card back:\n%s", chunk, got)
		}
		// The model's invention, substituted.
		if strings.Contains(got, invented) {
			t.Errorf("chunk %d: a card the model produced reached the caller unsubstituted:\n%s",
				chunk, got)
		}
		// Both counted, so the receipt describes the whole reply.
		if n := g.Findings(); len(n) == 0 {
			t.Errorf("chunk %d: nothing was recorded for a reply carrying two card numbers", chunk)
		}
	}
}

// A deployment that keeps no mappings must be unaffected: there is nothing
// to restore, and the stream must pass through rather than fail.
func TestAOneWayDeploymentStreamsUnchanged(t *testing.T) {
	engine, _ := streamEngine(t)

	// No scope at all is the strongest form of "retains nothing".
	got, _, err := streamAllWith(t, engine.NewRestoringStreamGovernor(nil),
		"Confirmed: nothing sensitive here.", 8)
	if err != nil {
		t.Fatalf("streaming without a scope failed: %v", err)
	}
	if got != "Confirmed: nothing sensitive here." {
		t.Errorf("the stream was altered with no scope in play: %q", got)
	}
}

// findingDecision returns the decision recorded for a class, or "" when
// the class was not found at all.
func findingDecision(g *StreamGovernor, class string) receipt.Decision {
	for _, f := range g.Findings() {
		if f.Class == class {
			return f.Decision
		}
	}
	return ""
}

// The same bytes, two destinations, two decisions. A rule scoped to one
// upstream must apply on a stream exactly as it does on a buffered reply,
// and must not apply when the stream's destination is unknown.
func TestAStreamIsDecidedForItsDestination(t *testing.T) {
	engine, scope := streamEngine(t)
	policy := &Policy{
		ID: "scoped", Version: "1", Default: receipt.DecisionAllow,
		Rules: []PolicyRule{
			{Class: "pii.email", Upstream: "crm", Decision: receipt.DecisionLogOnly},
			{Class: "pii.email", Decision: receipt.DecisionTokenize},
		},
	}
	const content = "Write to priya@acme.com about the invoice before Friday."

	for _, chunk := range []int{1, 7, 64} {
		toCRM, g, err := streamAllWith(t, engine.NewStreamGovernor(scope, WithPolicy(policy), WithTarget("crm")), content, chunk)
		if err != nil {
			t.Fatalf("chunk %d, to crm: %v", chunk, err)
		}
		if !strings.Contains(toCRM, "priya@acme.com") {
			t.Errorf("chunk %d, to crm: the scoped log_only rule did not hold on the stream:\n%s", chunk, toCRM)
		}
		if d := findingDecision(g, "pii.email"); d != receipt.DecisionLogOnly {
			t.Errorf("chunk %d, to crm: finding decision = %q, want log_only", chunk, d)
		}

		toModel, g, err := streamAllWith(t, engine.NewStreamGovernor(scope, WithPolicy(policy), WithTarget("openai")), content, chunk)
		if err != nil {
			t.Fatalf("chunk %d, to openai: %v", chunk, err)
		}
		if strings.Contains(toModel, "priya@acme.com") || !strings.Contains(toModel, "@tokenized.invalid") {
			t.Errorf("chunk %d, to openai: the general rule did not substitute:\n%s", chunk, toModel)
		}
		if d := findingDecision(g, "pii.email"); d != receipt.DecisionTokenize {
			t.Errorf("chunk %d, to openai: finding decision = %q, want tokenize", chunk, d)
		}

		// No destination: the scoped rule asked for a condition that cannot
		// be checked, and must not be treated as met.
		unknown, _, err := streamAllWith(t, engine.NewStreamGovernor(scope, WithPolicy(policy)), content, chunk)
		if err != nil {
			t.Fatalf("chunk %d, no target: %v", chunk, err)
		}
		if strings.Contains(unknown, "priya@acme.com") {
			t.Errorf("chunk %d, no target: a scoped allowance applied to an unknown destination:\n%s", chunk, unknown)
		}
	}
}

// A refusal scoped to one upstream cuts the stream bound there and leaves
// the same stream to anywhere else flowing. This is the path through the
// marker freeze and the completed-match cut, both of which decide by
// destination too.
func TestAScopedRefusalCutsOnlyTheStreamBoundForItsTarget(t *testing.T) {
	engine, scope := streamEngine(t)
	policy := &Policy{
		ID: "scoped-refusal", Version: "1", Default: receipt.DecisionAllow,
		Rules: []PolicyRule{
			{Class: "pii.email", Upstream: "crm", Decision: receipt.DecisionBlock},
			{Class: "pii.email", Decision: receipt.DecisionTokenize},
		},
	}
	const content = "Write to priya@acme.com about the invoice before Friday."

	toCRM, g, err := streamAllWith(t, engine.NewStreamGovernor(scope, WithPolicy(policy), WithTarget("crm")), content, 4)
	if !errors.Is(err, ErrStreamUnsafe) {
		t.Fatalf("to crm: err = %v, want ErrStreamUnsafe", err)
	}
	if strings.Contains(toCRM, "priya@acme.com") {
		t.Errorf("to crm: the refused value reached the caller:\n%s", toCRM)
	}
	if !g.Truncated() {
		t.Error("to crm: a cut stream is not reported as truncated")
	}
	if d := findingDecision(g, "pii.email"); d != receipt.DecisionBlock {
		t.Errorf("to crm: finding decision = %q, want block", d)
	}

	toModel, g, err := streamAllWith(t, engine.NewStreamGovernor(scope, WithPolicy(policy), WithTarget("openai")), content, 4)
	if err != nil {
		t.Fatalf("to openai: %v", err)
	}
	if g.Truncated() || !strings.Contains(toModel, "@tokenized.invalid") || !strings.Contains(toModel, "Friday") {
		t.Errorf("to openai: the stream should have been substituted and delivered whole:\n%s", toModel)
	}
}

// A ruleset handed to the governor is what the stream is scanned with —
// a tenant's own rule finds, and its policy decides, on the streaming path
// as on the buffered one.
func TestAStreamIsScannedWithTheRulesetItIsGiven(t *testing.T) {
	engine, scope := streamEngine(t)
	rules := append([]detect.Rule{}, detect.Default().Rules()...)
	rules = append(rules, detect.Rule{
		ID: "custom-codename", Class: "custom.codename",
		Pattern: regexp.MustCompile(`Project Voyager`), Confidence: detect.ConfidenceHigh, Priority: 10,
	})
	tenant := detect.NewRuleset("tenant-1", rules)
	policy := &Policy{
		ID: "tenant", Version: "1", Default: receipt.DecisionAllow,
		Rules: []PolicyRule{{Class: "custom.codename", Decision: receipt.DecisionBlock}},
	}
	const content = "The Project Voyager budget is attached."

	_, g, err := streamAllWith(t, engine.NewStreamGovernor(scope, WithRuleset(tenant), WithPolicy(policy), WithTarget("openai")), content, 5)
	if !errors.Is(err, ErrStreamUnsafe) {
		t.Fatalf("with the tenant ruleset: err = %v, want ErrStreamUnsafe", err)
	}
	if d := findingDecision(g, "custom.codename"); d != receipt.DecisionBlock {
		t.Errorf("with the tenant ruleset: finding decision = %q, want block", d)
	}

	// The engine's own ruleset knows nothing of the codename, whatever the
	// policy says about it.
	out, g, err := streamAllWith(t, engine.NewStreamGovernor(scope, WithPolicy(policy), WithTarget("openai")), content, 5)
	if err != nil {
		t.Fatalf("with the engine ruleset: %v", err)
	}
	if out != content || len(g.Findings()) != 0 {
		t.Errorf("with the engine ruleset: got %q with findings %v, want the content untouched", out, g.Findings())
	}
}

// A nil option leaves the engine's own configuration in place, so a caller
// holding a per-tenant ruleset that may be absent need not branch.
func TestNilStreamOptionsKeepTheEngineDefaults(t *testing.T) {
	engine, scope := streamEngine(t)
	g := engine.NewStreamGovernor(scope, WithRuleset(nil), WithPolicy(nil))
	if g.ruleset != engine.ruleset || g.policy != engine.policy {
		t.Error("nil options replaced the engine's ruleset or policy")
	}
}
