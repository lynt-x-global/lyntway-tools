package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// A saved key file that lists a key as revoked must make the CLI refuse
// what that key signed, and a malformed list must stop it outright.
func TestTheCLIHonoursRevokedKeys(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	signer, err := receipt.GenerateEd25519Signer("key-rev-1")
	if err != nil {
		t.Fatal(err)
	}
	r, _ := signedReceipt(t, nil)
	// Re-signed with a key whose public half this test knows.
	r.Issuer.KeyID = signer.KeyID()
	if err := receipt.Sign(r, signer); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rpath := filepath.Join(dir, "r.json")
	body, _ := json.Marshal(r)
	if err := os.WriteFile(rpath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	pub, _ := receipt.RawPublicKey(signer)

	runWith := func(revoked any) int {
		kf := map[string]any{
			"keys":       map[string]string{signer.KeyID(): base64.StdEncoding.EncodeToString(pub)},
			"algorithms": map[string]string{signer.KeyID(): "ed25519"},
		}
		if revoked != nil {
			kf["revoked"] = revoked
		}
		kpath := filepath.Join(dir, "keys.json")
		raw, _ := json.Marshal(kf)
		if err := os.WriteFile(kpath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		orig := os.Args
		defer func() { os.Args = orig }()
		os.Args = []string{"lyntway-verify", "-json", "-keys", kpath, rpath}
		var code int
		captureStdout(t, func() { code = run() })
		return code
	}

	if code := runWith(nil); code != 0 {
		t.Fatalf("an unrevoked key: exit %d, want 0", code)
	}
	if code := runWith([]map[string]any{{"key_id": signer.KeyID(), "revoked_at": "2026-09-01T00:00:00Z", "compromised": true}}); code == 0 {
		t.Error("a compromised key's receipt verified")
	}
	if code := runWith([]map[string]any{{"key_id": signer.KeyID(), "revoked_at": "2026-12-01T00:00:00Z"}}); code != 0 {
		t.Errorf("a receipt from before retirement: exit %d, want 0", code)
	}
	if code := runWith([]map[string]any{{"key_id": signer.KeyID(), "revoked_at": "soon"}}); code != 2 {
		t.Errorf("a malformed revocation: exit %d, want 2", code)
	}
}
