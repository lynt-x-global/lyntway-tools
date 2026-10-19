package main

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lynt-x-global/lyntway-tools/govern"
	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// A SELECT with a card and an email in it: what the audit ran through psql.
const auditQuery = "SELECT * FROM customers WHERE card = '4111111111111111' AND email = 'alice@example.com'"

// The row it returned, as pgDataRowText hands it to the engine.
var auditRow = []byte("1\n4111111111111111\nalice@example.com")

// The audit's observation: the wire carried the values untouched in both
// directions while the receipts said "tokenize". The gateway forwards
// every protocol message verbatim, so the strongest thing a receipt may
// claim is that findings were recorded.
func TestReceiptNeverClaimsASubstitutionThatDidNotHappen(t *testing.T) {
	g := testGovernor(t)

	for _, tc := range []struct {
		name string
		run  func() (*receiptResult, error)
	}{
		{"query", func() (*receiptResult, error) {
			res, err := g.governQuery("neon", auditQuery, "SELECT")
			return asResult(res), err
		}},
		{"row", func() (*receiptResult, error) {
			res, err := g.governResponse("neon", auditRow)
			return asResult(res), err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := tc.run()
			if err != nil {
				t.Fatal(err)
			}
			if !hasFinding(res.findings, "pci.card_number") {
				t.Fatalf("the card was not found; findings = %v", res.findings)
			}
			if !hasFinding(res.findings, "pii.email") {
				t.Fatalf("the email was not found; findings = %v", res.findings)
			}
			for _, d := range []receipt.Decision{res.decision, res.receiptDecision} {
				if d != receipt.DecisionLogOnly && d != receipt.DecisionAllow {
					t.Errorf("decision %q claims a transformation the gateway never performs", d)
				}
			}
			if res.inputDigest != res.outputDigest {
				t.Errorf("digests differ (%s / %s) but the bytes were forwarded unchanged", res.inputDigest, res.outputDigest)
			}
		})
	}
}

// The package documentation promises the queries, the results, and any
// values found in them stay on this machine. Whatever reaches the account
// must therefore be classes and counts and nothing else.
func TestReportCarriesNoContent(t *testing.T) {
	received := make(chan []byte, 8)
	paths := make(chan string, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received <- body
		paths <- r.URL.Path
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"receipt":{}}`))
	}))
	defer srv.Close()

	g := testGovernorReporting(t, srv.URL, "sk-test")

	if _, err := g.governQuery("neon", auditQuery, "SELECT"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.governResponse("neon", auditRow); err != nil {
		t.Fatal(err)
	}

	// The query and the row each become one report. Both must be free of
	// content; both must carry what the account can use.
	for i := 0; i < 2; i++ {
		var body []byte
		select {
		case body = <-received:
		case <-time.After(5 * time.Second):
			t.Fatalf("report %d never arrived", i)
		}
		path := <-paths

		// The reference is an opaque identifier this service generates, so
		// it cannot carry customer content by construction — and being
		// random hex it occasionally spells one of the strings below. A
		// digest reading rcpt_f6e660b286e41119205672c7 contains "4111" and
		// failed this test for a card number nobody sent. Blanked before
		// the scan rather than narrowing the scan, so every field that
		// could carry content is still checked.
		text := withoutReference(t, body)
		// The statement verb travels as action.method; it is a category,
		// not content. Everything after it is.
		for _, leak := range []string{"4111", "alice", "example.com", "customers", "WHERE"} {
			if strings.Contains(text, leak) {
				t.Errorf("report to %s carries content %q: %s", path, leak, text)
			}
		}
		for _, field := range []string{"request_body", "response_body"} {
			if strings.Contains(text, field) {
				t.Errorf("report to %s carries a %s field: %s", path, field, text)
			}
		}

		var payload struct {
			ChainID  string `json:"chain_id"`
			Tool     string `json:"tool"`
			Decision string `json:"decision"`
			Findings []struct {
				Class string `json:"class"`
				Count int    `json:"count"`
			} `json:"findings"`
			Action struct {
				Surface     string `json:"surface"`
				Direction   string `json:"direction"`
				Destination string `json:"destination"`
			} `json:"action"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("report is not JSON: %v", err)
		}
		if payload.Tool != "lyntway-dbgateway" || payload.ChainID != "db/neon" || payload.Action.Surface != "database" || payload.Action.Destination != "neon" {
			t.Errorf("report misnames its source: %s", text)
		}
		classes := map[string]int{}
		for _, f := range payload.Findings {
			classes[f.Class] += f.Count
		}
		if classes["pci.card_number"] != 1 || classes["pii.email"] != 1 {
			t.Errorf("report does not carry the classes and counts the account needs: %s", text)
		}
	}
}

// receiptResult is the part of a governed result the tests compare.
type receiptResult struct {
	decision        receipt.Decision
	receiptDecision receipt.Decision
	findings        []receipt.Finding
	inputDigest     string
	outputDigest    string
}

func asResult(res *govern.Result) *receiptResult {
	if res == nil {
		return nil
	}
	return &receiptResult{
		decision:        res.Decision,
		receiptDecision: res.Receipt.Governance.Decision,
		findings:        res.Findings,
		inputDigest:     res.Receipt.Content.InputDigest,
		outputDigest:    res.Receipt.Content.OutputDigest,
	}
}

func testGovernor(t *testing.T) *governor {
	t.Helper()
	return testGovernorWith(t, governorConfig{})
}

func testGovernorReporting(t *testing.T, origin, key string) *governor {
	t.Helper()
	return testGovernorWith(t, governorConfig{origin: origin, key: key})
}

// testGovernorWith fills in whatever paths cfg leaves empty with a fresh
// temporary directory.
func testGovernorWith(t *testing.T, cfg governorConfig) *governor {
	t.Helper()
	if cfg.receipts == "" {
		cfg.receipts = receiptsPath(t)
	}
	if cfg.keyPath == "" {
		cfg.keyPath = filepath.Join(filepath.Dir(cfg.receipts), "signing.key")
	}
	g, err := newGovernor(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.close)
	return g
}

// blockCards is a policy that refuses anything carrying a card number.
func blockCards() *govern.Policy {
	return &govern.Policy{
		ID:      "test.block-cards",
		Version: "1",
		Rules: []govern.PolicyRule{
			{Family: "pci", Decision: receipt.DecisionBlock},
		},
		Default: receipt.DecisionAllow,
	}
}

// Two runs of the process against the same files must produce one chain a
// verifier can walk end to end, under a key the verifier is handed beside
// the receipts. The audit found the opposite: a fresh key per run, never
// published; seq restarting at 0; an issuer name pointing at lyntway.com,
// which had never seen the key.
func TestChainContinuesAcrossRestartsAndVerifiesOffline(t *testing.T) {
	dir := t.TempDir()
	cfg := governorConfig{
		receipts: filepath.Join(dir, "receipts.jsonl"),
		keyPath:  filepath.Join(dir, "keys", "signing.key"),
	}

	for run := 0; run < 2; run++ {
		g, err := newGovernor(cfg)
		if err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
		for i := 0; i < 2; i++ {
			if _, err := g.governQuery("neon", "SELECT 1", "SELECT"); err != nil {
				t.Fatal(err)
			}
		}
		g.close()
	}

	rs := readReceipts(t, cfg.receipts)
	if len(rs) != 4 {
		t.Fatalf("got %d receipts, want 4", len(rs))
	}
	seen := map[string]bool{}
	for i, r := range rs {
		if r.Chain.ID != "db/neon" {
			t.Errorf("receipt %d is on chain %q", i, r.Chain.ID)
		}
		if r.Chain.Seq != uint64(i) {
			t.Errorf("receipt %d carries seq %d: the second run did not continue the chain", i, r.Chain.Seq)
		}
		if seen[r.ID] {
			t.Errorf("receipt identifier %q was issued twice", r.ID)
		}
		seen[r.ID] = true
		if r.Issuer.KeyID != rs[0].Issuer.KeyID {
			t.Errorf("receipt %d is signed by %q, receipt 0 by %q: the key did not survive the restart", i, r.Issuer.KeyID, rs[0].Issuer.KeyID)
		}
		if !strings.HasPrefix(r.Issuer.KeyID, "local-") {
			t.Errorf("key id %q does not say it is a local key", r.Issuer.KeyID)
		}
		if strings.Contains(r.Issuer.Name, "lyntway.com") {
			t.Errorf("issuer %q names lyntway.com, whose directory does not hold this key", r.Issuer.Name)
		}
		if r.Issuer.Name != localIssuer {
			t.Errorf("issuer = %q, want %q", r.Issuer.Name, localIssuer)
		}
	}

	info, err := os.Stat(cfg.keyPath)
	if err != nil {
		t.Fatalf("the signing seed was not kept: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("signing seed has mode %o, want 600", perm)
	}

	// The key file is in the shape lyntway-verify -keys reads.
	keysPath := keysPathFor(cfg.receipts)
	raw, err := os.ReadFile(keysPath)
	if err != nil {
		t.Fatalf("the public key was not published: %v", err)
	}
	var keys publishedKeys
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatalf("key file is not JSON: %v", err)
	}
	keyID := rs[0].Issuer.KeyID
	if keys.Keys[keyID] == "" {
		t.Fatalf("key file holds %v, not the key %q that signed the receipts", keys.Keys, keyID)
	}
	if keys.Algorithms[keyID] != "ed25519" {
		t.Errorf("algorithm for %q = %q, want ed25519", keyID, keys.Algorithms[keyID])
	}

	// The real verifier, with the real files. -chain takes an array, so
	// the JSONL is wrapped; nothing in it is altered.
	verifier := buildVerifier(t)
	chainPath := filepath.Join(dir, "chain.json")
	array, err := json.Marshal(rs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(chainPath, array, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(verifier, "-keys", keysPath, "-chain", chainPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("lyntway-verify refused the chain: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "receipts       4") {
		t.Errorf("verifier did not walk all four receipts:\n%s", out)
	}
	t.Logf("lyntway-verify:\n%s", out)
}

// buildVerifier compiles cmd/lyntway-verify, because the seam that matters
// is between this binary's files and that one's flags.
func buildVerifier(t *testing.T) string {
	t.Helper()
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go tool on PATH to build lyntway-verify with")
	}
	bin := filepath.Join(t.TempDir(), "lyntway-verify")
	build := exec.Command(goTool, "build", "-o", bin, "../lyntway-verify")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building lyntway-verify: %v\n%s", err, out)
	}
	return bin
}

func hasFinding(fs []receipt.Finding, class string) bool {
	for _, f := range fs {
		if f.Class == class && f.Count > 0 {
			return true
		}
	}
	return false
}

// readReceipts parses a JSONL receipt file.
func readReceipts(t *testing.T, path string) []*receipt.Receipt {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening receipts: %v", err)
	}
	defer f.Close()
	var out []*receipt.Receipt
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var r receipt.Receipt
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("receipt line is not JSON: %v", err)
		}
		out = append(out, &r)
	}
	return out
}

func receiptsPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "receipts.jsonl")
}

// withoutReference returns the report as text with the reference field
// emptied, so a random identifier cannot be mistaken for leaked content.
func withoutReference(t *testing.T, body []byte) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("report is not JSON: %v", err)
	}
	delete(m, "reference")
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("re-encoding the report: %v", err)
	}
	return string(out)
}
