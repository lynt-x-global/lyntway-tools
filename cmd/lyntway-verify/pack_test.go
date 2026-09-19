package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// testdata/pack holds a compliance pack and the key set it was signed
// with, both taken unaltered from an evidence bundle a running server made.
// The bundle's README tells an auditor to run exactly
//
//	lyntway-verify -keys keys.json pack.json
//
// and this tool used to answer NOT VERIFIED for that, because it read the
// pack as a malformed receipt. An auditor following our own instructions
// would have concluded our evidence was invalid.

func packResolver(t *testing.T) receipt.KeyResolver {
	t.Helper()
	keys := keyFlag{}
	if _, err := loadKeyFile(filepath.Join("testdata", "pack", "keys.json"), keys); err != nil {
		t.Fatalf("loading the bundle's keys: %v", err)
	}
	resolver, err := buildResolver(keys)
	if err != nil {
		t.Fatalf("building a resolver: %v", err)
	}
	return resolver
}

func TestTheBundleInstructionsVerifyAPack(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "pack", "pack.json"))
	if err != nil {
		t.Fatal(err)
	}
	if code := verifyOne(data, packResolver(t), receipt.VerifyOptions{}, true, nil, ""); code != 0 {
		t.Fatalf("an intact pack did not verify: exit %d", code)
	}
}

func TestAnEditedPackIsCaught(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "pack", "pack.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pack map[string]any
	if err := json.Unmarshal(data, &pack); err != nil {
		t.Fatal(err)
	}
	// One number in the attested counts, the edit somebody would make to
	// flatter a month. The attestation's signature is untouched, so a tool
	// that checked only the signature would still say VERIFIED.
	summary := pack["attested"].(map[string]any)["summary"].(map[string]any)
	summary["actions"] = summary["actions"].(float64) + 1
	edited, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	if code := verifyOne(edited, packResolver(t), receipt.VerifyOptions{}, true, nil, ""); code == 0 {
		t.Fatal("a pack whose counts were changed after signing verified")
	}
}
