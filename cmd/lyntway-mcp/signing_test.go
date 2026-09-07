package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// A receipt signed by a key that exists only for the life of one process,
// and is written nowhere, is a receipt nobody can ever verify. The key must
// outlive the process, its public half must be published where the
// verifier can be pointed at it, and the chain must continue across
// restarts rather than starting again at zero.
func TestReceiptsVerifyAcrossRestarts(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(t.TempDir(), "receipts.jsonl")

	message := `{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"hello"}]}}`
	for run := 0; run < 2; run++ {
		g, err := newGovernor(path, "test-server")
		if err != nil {
			t.Fatalf("run %d: governor: %v", run, err)
		}
		for i := 0; i < 2; i++ {
			if _, err := g.govern([]byte(message), directionToAgent); err != nil {
				t.Fatalf("run %d: govern: %v", run, err)
			}
		}
		g.close()
	}

	rows := receiptsIn(t, path)
	if len(rows) != 4 {
		t.Fatalf("wrote %d receipts, want 4", len(rows))
	}
	ids := map[string]bool{}
	for i, r := range rows {
		chain, _ := r["chain"].(map[string]any)
		if seq, _ := chain["seq"].(float64); int(seq) != i {
			t.Errorf("receipt %d has seq %v; the chain did not resume across the restart", i, chain["seq"])
		}
		id, _ := r["id"].(string)
		if ids[id] {
			t.Errorf("receipt id %q was issued twice", id)
		}
		ids[id] = true
		if strings.HasPrefix(id, "rcpt_mcp_") {
			t.Errorf("receipt id %q is a per-process counter", id)
		}
		issuer, _ := r["issuer"].(map[string]any)
		if name, _ := issuer["name"].(string); name == "Lyntway (lyntway.com)" {
			t.Errorf("receipt %d claims lyntway.com issued it; a local key did", i)
		}
	}

	// The private half stays on this machine and nobody else may read it.
	info, err := os.Stat(filepath.Join(home, ".lyntway", "mcp-signing.key"))
	if err != nil {
		t.Fatalf("the signing key was not kept: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("signing key mode = %o, want 600", perm)
	}

	// The public half is published in exactly the shape lyntway-verify
	// -keys reads, so the file can be handed over as it is.
	keysPath := strings.TrimSuffix(path, filepath.Ext(path)) + "-keys.json"
	raw, err := os.ReadFile(keysPath)
	if err != nil {
		t.Fatalf("no public key was published beside the receipts: %v", err)
	}
	var kf struct {
		Keys       map[string]string `json:"keys"`
		Algorithms map[string]string `json:"algorithms"`
	}
	if err := json.Unmarshal(raw, &kf); err != nil {
		t.Fatalf("the keys file is not valid JSON: %v", err)
	}
	keys := map[string][]byte{}
	for id, encoded := range kf.Keys {
		if kf.Algorithms[id] != "ed25519" {
			t.Errorf("key %q published with algorithm %q, want ed25519", id, kf.Algorithms[id])
		}
		pub, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatalf("key %q is not base64: %v", id, err)
		}
		keys[id] = pub
	}
	resolver, err := receipt.NewEd25519Resolver(keys)
	if err != nil {
		t.Fatalf("resolver: %v", err)
	}

	var chain []*receipt.Receipt
	for _, line := range strings.Split(strings.TrimSpace(mustRead(t, path)), "\n") {
		var r receipt.Receipt
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("parsing receipt: %v", err)
		}
		chain = append(chain, &r)
	}
	res, err := receipt.VerifyChain(chain, resolver, receipt.VerifyOptions{})
	if err != nil {
		t.Fatalf("the chain does not verify with the published key: %v", err)
	}
	if res.Length != 4 {
		t.Errorf("verified %d receipts, want 4", res.Length)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
